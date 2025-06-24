from flask import Flask, request, render_template, redirect, url_for, flash
from flask_login import LoginManager, login_user, login_required, logout_user, current_user, UserMixin
from flask_mail import Mail, Message
from itsdangerous import URLSafeTimedSerializer, SignatureExpired
import sqlite3
import secrets
from werkzeug.security import generate_password_hash, check_password_hash


from dotenv import load_dotenv
import os

load_dotenv()


app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY')

# Flask-Mail configuration (use your SMTP server)
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = os.getenv('MAIL_USERNAME')
app.config['MAIL_DEFAULT_SENDER'] = ('Splooge', os.getenv('MAIL_USERNAME'))
app.config['MAIL_PASSWORD'] = os.getenv('MAIL_PASSWORD')

mail = Mail(app)
s = URLSafeTimedSerializer(app.secret_key)

DB_FILE = 'users.db'

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

class User(UserMixin):
    def __init__(self, id, email, password, username):
        self.id = id
        self.email = email
        self.password = password
        self.username = username
        

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
                        email TEXT PRIMARY KEY,
                        username TEXT,
                        password_hash TEXT)''')



def get_user_by_id(user_id):
    conn = sqlite3.connect('users.db')
    cur = conn.cursor()
    cur.execute("SELECT id, email, password_hash, username FROM users WHERE id = ?", (user_id,))
    row = cur.fetchone()
    conn.close()
    return User(*row) if row else None


def get_user_by_username(username):
    conn = sqlite3.connect('users.db')
    cur = conn.cursor()
    cur.execute("SELECT id, email, password_hash, username FROM users WHERE username = ?", (username,))
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
        return redirect(url_for('register'))
    else:
        return render_template('check_email.html')

#app route for registration (credentials) page
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        #get form info
        email = request.form['email'].strip().lower()
        code = request.form['code'].strip()
        username = request.form['username'].strip()
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
            
            #hash password and insert into database
            password_hash = generate_password_hash(password)
            cur.execute('INSERT INTO users (email, password_hash, username) VALUES (?, ?, ?)',
                        (email, password_hash, username))
            cur.execute('DELETE FROM pending_codes WHERE email = ?', (email,))
            conn.commit()
        #notify user of registration, redirect to login
        flash('Account created successfully! You can now log in.', 'register')
        return redirect(url_for('index'))

    return render_template('register.html')



if __name__ == "__main__":
    db_setup()
    app.run(host='0.0.0.0', port=5000, debug=True)