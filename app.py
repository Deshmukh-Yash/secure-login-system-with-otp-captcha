from flask import Flask, render_template, request, redirect, session
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_mail import Mail, Message
import random
import requests
import time

app = Flask(__name__)
app.secret_key = 'secretkey'
app.permanent_session_lifetime = 600

# DATABASE
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
db = SQLAlchemy(app)

# EMAIL CONFIG
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USERNAME'] = 'yashdeshmukh2424@gmail.com'
app.config['MAIL_PASSWORD'] = 'swduqvmkzfhrtyin'
app.config['MAIL_USE_TLS'] = True

mail = Mail(app)

# DATABASE MODEL
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100))
    password = db.Column(db.String(200))

# HOME
@app.route('/')
def home():
    return redirect('/login')

# REGISTER
@app.route('/register', methods=['GET', 'POST'])
def register():

    if request.method == 'POST':

        email = request.form['email'].strip().lower()
        password = generate_password_hash(request.form['password'])

        user = User(email=email, password=password)

        db.session.add(user)
        db.session.commit()

        return render_template('register_success.html')

    return render_template('register.html')

# CAPTCHA VERIFY
def verify_captcha(response):

    secret_key = "6LdiztIsAAAAAJfouuwuw8pu7QPGHM5GeXlj1s13"

    url = "https://www.google.com/recaptcha/api/siteverify"

    data = {
        'secret': secret_key,
        'response': response
    }

    r = requests.post(url, data=data)

    return r.json()['success']

# SEND EMAIL OTP
def send_otp(email, otp):

    msg = Message(
        'Your OTP Code',
        sender='yashdeshmukh2424@gmail.com',
        recipients=[email]
    )

    msg.body = f'Your OTP is {otp}'

    mail.send(msg)

# LOGIN
@app.route('/login', methods=['GET', 'POST'])
def login():

    # Initialize login attempts
    if 'login_attempts' not in session:
        session['login_attempts'] = 0

    if request.method == 'POST':

        # Block after 3 wrong attempts
        if session['login_attempts'] >= 3:

            return render_template(
                'error.html',
                message="Account Blocked 🚫 Too many wrong attempts"
            )

        captcha_response = request.form.get('g-recaptcha-response')

        # CAPTCHA CHECK
        if not verify_captcha(captcha_response):

            return render_template(
                'error.html',
                message="Captcha Failed ❌"
            )

        email = request.form['email'].strip().lower()
        password = request.form['password']

        user = User.query.filter_by(email=email).first()

        # USER NOT FOUND
        if not user:

            session['login_attempts'] += 1

            remaining = 3 - session['login_attempts']

            return render_template(
                'error.html',
                message=f"Invalid Email or Password ❌ Attempts left: {remaining}"
            )

        # WRONG PASSWORD
        if not check_password_hash(user.password, password):

            session['login_attempts'] += 1

            remaining = 3 - session['login_attempts']

            return render_template(
                'error.html',
                message=f"Invalid Email or Password ❌ Attempts left: {remaining}"
            )

        # SUCCESS LOGIN
        session['login_attempts'] = 0

        otp = random.randint(100000, 999999)

        session['otp'] = otp
        session['email'] = email
        session['otp_time'] = time.time()

        # SEND OTP EMAIL
        send_otp(email, otp)

        return redirect('/otp')

    return render_template('login.html')

# OTP VERIFY
@app.route('/otp', methods=['GET', 'POST'])
def otp():

    if request.method == 'POST':

        user_otp = request.form['otp']

        # OTP NOT GENERATED
        if session.get('otp') is None:
            return redirect('/login')

        # OTP EXPIRED
        if time.time() - session.get('otp_time', 0) > 120:

            session.pop('otp', None)
            session.pop('otp_time', None)

            return render_template(
                'error.html',
                message="OTP Expired ❌"
            )

        # CORRECT OTP
        if int(user_otp) == session.get('otp'):

            session.pop('otp', None)
            session.pop('otp_time', None)

            session['logged_in'] = True
            session.permanent = True

            # ADMIN REDIRECT
            if session.get('email') == "yashdeshmukh2424@gmail.com":

                return redirect('/admin')

            else:

                return redirect('/dashboard')

        # WRONG OTP
        else:

            return render_template(
                'error.html',
                message="Wrong OTP ❌"
            )

    return render_template('otp.html')

# USER DASHBOARD
@app.route('/dashboard')
def dashboard():

    if not session.get('logged_in'):
        return redirect('/login')

    return render_template(
        'dashboard.html',
        email=session.get('email')
    )

# ADMIN PANEL
@app.route('/admin')
def admin():

    if not session.get('logged_in'):
        return redirect('/login')

    if session.get('email') != "yashdeshmukh2424@gmail.com":

        return render_template(
            'error.html',
            message="Access Denied ❌"
        )

    users = User.query.all()

    return render_template(
        'admin.html',
        users=users
    )

# LOGOUT
@app.route('/logout')
def logout():

    session.clear()

    return redirect('/login')

# MAIN
if __name__ == "__main__":

    with app.app_context():
        db.create_all()

    app.run(debug=True)