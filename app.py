from flask import Flask, request, render_template, redirect, url_for, flash
from flask_login import LoginManager, login_user, login_required, logout_user, current_user, UserMixin
from flask_mail import Mail, Message
from itsdangerous import URLSafeTimedSerializer, SignatureExpired
import sqlite3
import secrets
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from datetime import date
from dotenv import load_dotenv
import os
import re

load_dotenv()


app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY')


ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}

app.config['PROFILE_PIC_FOLDER'] = 'static/profile_pictures'
app.config['UPLOAD_FOLDER'] = os.path.join(os.getcwd(), 'static/uploads')
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = os.getenv('MAIL_USERNAME')
app.config['MAIL_DEFAULT_SENDER'] = ('Splooge', os.getenv('MAIL_USERNAME'))
app.config['MAIL_PASSWORD'] = os.getenv('MAIL_PASSWORD')
app.config['MAX_CONTENT_LENGTH'] = 2 * 1024 * 1024  # 1MB limit


mail = Mail(app)
s = URLSafeTimedSerializer(app.secret_key)

DB_FILE = 'users.db'

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'




class User(UserMixin):
    def __init__(self, id, email, password, username, bio, profile_pic_filename, notifications_enabled):
        self.id = id
        self.email = email
        self.password = password
        self.username = username
        self.bio = bio
        self.profile_pic_filename = profile_pic_filename
        self.notifications_enabled = notifications_enabled
        
        
        

from flask import flash

#function for validating username characters
def is_valid_username(username):
    return re.match(r'^[a-zA-Z0-9_-]+$', username) is not None


def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


#initialize DB
def db_setup():
     with sqlite3.connect(DB_FILE) as conn:
        cur = conn.cursor()
        cur.execute('''CREATE TABLE IF NOT EXISTS whitelist (email TEXT PRIMARY KEY)''')
        cur.execute('''CREATE TABLE IF NOT EXISTS pending_codes (
                        email TEXT PRIMARY KEY,
                        code TEXT,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)''')
        cur.execute('''CREATE TABLE IF NOT EXISTS users (
                        id INTEGER,
                        email TEXT,
                        password_hash TEXT,
                        username TEXT,
                        bio TEXT,
                        profile_pic_filename TEXT,
                        notifications_enabled INTEGER DEFAULT 1
                    )''')



def get_user_by_id(user_id):
    conn = sqlite3.connect('users.db')
    cur = conn.cursor()
    cur.execute("SELECT id, email, password_hash, username, bio, profile_pic_filename, notifications_enabled FROM users WHERE id = ?", (user_id,))
    row = cur.fetchone()
    conn.close()
    return User(*row) if row else None

def get_username_by_id(user_id):
    with sqlite3.connect(DB_FILE) as conn:
        cur = conn.cursor()
        cur.execute("SELECT username FROM users WHERE id = ?", (user_id,))
        row = cur.fetchone()
        return row[0] if row else None

def get_user_by_username(username):
    conn = sqlite3.connect('users.db')
    cur = conn.cursor()
    cur.execute("SELECT id, email, password_hash, username, bio, profile_pic_filename, notifications_enabled FROM users WHERE username = ?", (username,))
    row = cur.fetchone()
    conn.close()
    return User(*row) if row else None


@login_manager.user_loader
def load_user(user_id):
    return get_user_by_id(user_id)

#landing page
@app.route('/')
def index():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    else:
        return redirect(url_for('login'))

@app.route('/home')
@login_required
def home():
    return render_template('home.html')

# TODO 
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        user = get_user_by_username(username)
        password = request.form['password']
        if user and check_password_hash(user.password, password):
            login_user(user)
            return redirect(url_for('home'))
        flash("Invalid credentials", 'login')
    return render_template('login.html')

#DONE
@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))


#Updated
#check email is the route for verifying a persons email is on the whitelist and emailing them
@app.route('/check_email', methods=['GET', 'POST'])
def check_email():
    if request.method == 'POST':
        #get input email
        email = request.form['email'].strip().lower()
        #connect to DB and scan whitelist, making a new code if on whitelist and no user already exists with that email
        with sqlite3.connect(DB_FILE) as conn:
            cur = conn.cursor()
            cur.execute('SELECT 1 FROM whitelist WHERE email = ?', (email,))
            if not cur.fetchone():
                flash("You're not on the whitelist.", 'check_email')
                return redirect(url_for('check_email'))

            cur.execute('SELECT 1 FROM users WHERE email = ?', (email,))
            if cur.fetchone():
                flash("You already have an account.", 'check_email')
                return redirect(url_for('check_email'))

            code = secrets.token_urlsafe(8)
            cur.execute('REPLACE INTO pending_codes (email, code) VALUES (?, ?)', (email, code))
            conn.commit()

        #email token
        msg = Message('Your One-Time Registration Code for Splooge', recipients=[email])
        msg.body = f"Use this code to register: {code}"
        mail.send(msg)
        
        #redirect to register page
        flash('A registration code was sent to your email.', 'check_email')
        return render_template('register.html', email)
    else:
        return render_template('check_email.html')

#app route for registration (credentials) page
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        #get form info
        email = request.form['email'].strip().lower()
        code = request.form['code'].strip()
        username = request.form['username'].strip().lower()
        password = request.form['password']
        
        #connect to database
        with sqlite3.connect(DB_FILE) as conn:
            cur = conn.cursor()
            cur.execute('SELECT code FROM pending_codes WHERE email = ?', (email,))
            row = cur.fetchone()
             
            #check for expired code
            if not row or row[0] != code:
                flash('Invalid or expired code.', 'register')
                return redirect(url_for('register'))
            
            
            #check for username already in use
            cur.execute('SELECT 1 FROM users WHERE username = ?', (username,))
            if cur.fetchone():
                flash("This username is already in use", 'register')
                return redirect(url_for('register'))
            
            #check if username is valid
            
            if not is_valid_username(username):
                flash("Username can only contain letters, numbers, underscores, and hyphens.", "register")
                return redirect(url_for('register'))
            
            
            #check for email already in use or wrong email
            
            cur = conn.cursor()
            cur.execute('SELECT 1 FROM whitelist WHERE email = ?', (email,))
            if not cur.fetchone():
                flash("The email you entered is not on the whitelist.", 'register')
                return redirect(url_for('register'))
            
            cur = conn.cursor()
            cur.execute('SELECT 1 FROM users WHERE email = ?', (email,))
            if cur.fetchone():
                flash("This email is already in use", 'register')
                return redirect(url_for('register'))
            
            #password must be 8 characters
            if len(password) < 8:
                flash("Lengthen your password, fool. 8 characters MINIMUM.", 'register')
                return redirect(url_for('register'))
            
            
            #make and insert default bio
            today = date.today()
            bio = username + " has been splooging since " + today.strftime("%m %d %Y")
            
            #hash password and insert all into database
            password_hash = generate_password_hash(password)
            cur.execute('INSERT INTO users (email, password_hash, username, bio) VALUES (?, ?, ?, ?)',
                        (email, password_hash, username, bio))
            cur.execute('DELETE FROM pending_codes WHERE email = ?', (email,))
            conn.commit()
        #notify user of registration, redirect to login
        flash('Account created successfully! You can now log in.', 'register')
        return redirect(url_for('index'))

    return render_template('register.html')


#for uploading a post 
@app.route('/upload', methods=['GET', 'POST'])
@login_required
def upload():
    if request.method == 'POST':
        caption = request.form['caption']
        file = request.files.get('image')

        filename = None
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            upload_path = app.config['UPLOAD_FOLDER']
            os.makedirs(upload_path, exist_ok=True)  # ensure folder exists
            filepath = os.path.join(upload_path, filename)
            try:
                file.save(filepath)
                print("Saved file as:", filename)
            except Exception as e:
                flash("Error saving file.", "upload")
                return redirect(url_for('upload'))

        with sqlite3.connect(DB_FILE) as conn:
            cur = conn.cursor()
            cur.execute("""
                INSERT INTO posts (user_id, caption, image_filename)
                VALUES (?, ?, ?)
            """, (current_user.id, caption, filename))
            conn.commit()
            

        flash('Post created!', "upload")
        return redirect(url_for('home'))

    return render_template('upload.html')


#for viewing a users profile
@app.route('/profile/<username>', methods=['GET', 'POST'])
@login_required
def profile(username):
    with sqlite3.connect(DB_FILE) as conn:
        cur = conn.cursor()
        
        # Get user info
        cur.execute("SELECT id, bio, profile_pic_filename FROM users WHERE username = ?", (username,))
        user = cur.fetchone()
        
        if not user:
            abort(404)  # User doesn't exist

        user_id, bio, profile_pic = user

        # Get user's posts
        cur.execute("""
            SELECT caption, image_filename, timestamp
            FROM posts
            WHERE user_id = ?
            ORDER BY timestamp DESC
        """, (user_id,))
        
        posts = cur.fetchall()

    return render_template("profile.html", username=username, bio=bio, profile_pic=profile_pic, posts=posts)


#for viewing an individual post
@app.route('/view_post/<int:id>', methods=['GET', 'POST'])
@login_required
def view_post(id):
    with sqlite3.connect(DB_FILE) as conn:
        cur = conn.cursor()
        
        # Get post info from DB
        cur.execute("SELECT user_id, caption, image_filename, timestamp FROM posts WHERE id = ?", (id,))
        post = cur.fetchone()
        
        if not post:
            abort(404)  # Post doesn't exist

        user_id, caption, image_filename, timestamp = post
        
        username = get_username_by_id(user_id)
    return render_template("post.html", username=username, caption=caption, image_filename=image_filename, timestamp=timestamp)


#for viewing users own page 
@app.route('/myprofile')
@login_required
def myprofile():
    username = get_username_by_id(current_user.id)
    return redirect(url_for('profile', username=username))

#for settings changes

@app.route('/settings', methods=['GET', 'POST'])
@login_required
def settings():
    with sqlite3.connect(DB_FILE) as conn:
        cur = conn.cursor()

        if request.method == 'POST':
            changes_made = False
            
            cur.execute("SELECT profile_pic_filename FROM users WHERE id = ?", (current_user.id,))
            row = cur.fetchone()
            old_pic_filename = row[0]
            
            default_pic = 'default_profile_pictures/default.png'
            
            # Update profile picture
            file = request.files.get('profile-pic')
            profile_pic_filename = None
            remove_pic = 'remove_profile_pic' in request.form
            
            if file and not allowed_file(file.filename):
                flash('Filetype not supported. Use .png, .jpg, .jpeg, or .gif','settings')
            
            # If uploading a new valid image
            if file and allowed_file(file.filename):
                filename = secure_filename(file.filename)
                file_path = os.path.join(app.config['PROFILE_PIC_FOLDER'], filename)
                file.save(file_path)
                cur.execute("UPDATE users SET profile_pic_filename = ? WHERE id = ?", (filename, current_user.id))
                changes_made = True

            # If removing image AND it was not already default
            elif remove_pic and old_pic_filename != default_pic:
                try:
                    os.remove(os.path.join(app.config['PROFILE_PIC_FOLDER'], old_pic_filename))
                except FileNotFoundError:
                    pass
                cur.execute("UPDATE users SET profile_pic_filename = ? WHERE id = ?", (default_pic, current_user.id))
                changes_made = True

            # Update bio, username, email, notifications
            bio = request.form.get('bio', '').strip()
            username = request.form.get('username', '').strip()
            email = request.form.get('email', '').strip()
            notifications_enabled = 1 if request.form.get('notifications_enabled') else 0
            
            user = get_user_by_id(current_user.id)
            
            
            #check if newusername is valid
            
            if not is_valid_username(username):
                flash("Username can only contain letters, numbers, underscores, and hyphens.", "settings")
                return redirect(url_for('settings'))
            
            
            
            #if username in form is different from current user username, make sure another account is not using it
            if user.username != username:
                cur.execute('SELECT 1 FROM users WHERE username = ?', (username,))
                if cur.fetchone():
                    flash("This username is already in use", 'settings')
                    return redirect(url_for('settings'))
                changes_made = True
            
            #check for email already in use or wrong email
            
            cur.execute('SELECT 1 FROM whitelist WHERE email = ?', (email,))
            if not cur.fetchone():
                flash("The email you entered is not on the whitelist.", 'settings')
                return redirect(url_for('settings'))
            
            
            #if email in form is different from current user email, make sure another account is not using it
            if user.email != email:
                cur.execute('SELECT 1 FROM users WHERE email = ?', (email,))
                if cur.fetchone():
                    flash("This email is already in use", 'settings')
                    return redirect(url_for('settings'))
                changes_made = True
            
            
            # Check if bio changed
            if (user.bio or '') != bio:
                changes_made = True

            # Check if notification setting changed
            if user.notifications_enabled != notifications_enabled:
                changes_made = True

            # If changes were made, update the DB
            if changes_made:
                cur.execute("""
                    UPDATE users
                    SET bio = ?, username = ?, email = ?, notifications_enabled = ?
                    WHERE id = ?
                """, (bio, username, email, notifications_enabled, current_user.id))
                conn.commit()
                flash("Settings updated successfully.", category="settings")
            return redirect(url_for('settings'))

        # GET: fetch current user info
        cur.execute("SELECT username, email, bio, profile_pic_filename, notifications_enabled FROM users WHERE id = ?", (current_user.id,))
        user = cur.fetchone()
        if not user:
            flash("User not found.", category="settings")
            return redirect(url_for('home'))

        username, email, bio, profile_pic, notifications_enabled = user

    return render_template(
        'settings.html',
        username=username,
        email=email,
        bio=bio,
        profile_pic=profile_pic,
        notifications_enabled=bool(notifications_enabled)
    )
    
    
@app.route('/change_password', methods=['GET', 'POST'])
@login_required
def change_password():
    with sqlite3.connect(DB_FILE) as conn:
        cur = conn.cursor()
        #form 
        if request.method == 'POST':
            old_password = request.form['old_password']
            
            user = get_user_by_id(current_user.id)
            if not user or not check_password_hash(user.password, old_password):
                flash("Incorrect password", 'change_password')
                return redirect(url_for('change_password'))

            
            new_password = request.form['new_password']
            confirm_new_password = request.form['confirm_new_password']
            if new_password != confirm_new_password:
                flash("Passwords do not match.", "change_password")
                return redirect(url_for('change_password'))
            
            
            if len(new_password) < 8:
                flash("Lengthen your password, fool. 8 characters MINIMUM.", 'change_password')
                return redirect(url_for('change_password'))
            password_hash = generate_password_hash(new_password)
            cur.execute("UPDATE users SET password_hash = ? WHERE id = ?", (password_hash, current_user.id))
            conn.commit()
            flash("Password changed successfully.", "change_password")
            return redirect(url_for('change_password'))
    return render_template("change_password.html")
                

if __name__ == "__main__":
    db_setup()
    app.run(host='0.0.0.0', port=5000, debug=True)