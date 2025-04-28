from flask import Flask, render_template, request, redirect, url_for, session, flash
import random
import time
import sqlite3
from index import PasswordManager

app = Flask(__name__)
app.secret_key = '1234'  # Change this to something secure!

pm = PasswordManager()

INACTIVITY_TIMEOUT = 60  # 2 minutes

def is_key_loaded():
    return pm.key is not None

def log_action(message):
    with open("audit_log.txt", "a") as f:
        f.write(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] {message}\n")

def is_session_expired():
    last_active = session.get('last_active')
    if last_active and (time.time() - last_active > INACTIVITY_TIMEOUT):
        session.clear()
        return True
    return False

@app.route('/')
def index():
    return redirect(url_for('login'))

import getpass

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username'].strip()
        password = request.form['password'].strip()

        if not username.isalnum() or not password.isalnum():
            flash("Username and Password must be alphanumeric.", "danger")
            return redirect(url_for('register'))

        # Save original getpass
        original_getpass = getpass.getpass

        try:
            # Monkey-patch getpass.getpass to return password automatically
            getpass.getpass = lambda prompt='': password

            if pm.add_user(username):
                flash("Registration successful. Please log in.", "success")
                return redirect(url_for('login'))
            else:
                flash("Username already exists or password invalid.", "danger")

        finally:
            # Restore original getpass function
            getpass.getpass = original_getpass

    return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username'].strip()
        password = request.form['password'].strip()

        user_id = pm.log_in_user(username, password)
        if user_id:
            otp = str(random.randint(100000, 999999))
            session['otp'] = otp
            session['pending_user_id'] = user_id
            session['username'] = username
            session['last_active'] = time.time()
            flash(f"Your OTP code is: {otp}", "info")
            return redirect(url_for('otp'))
        else:
            #  Failed login attempt handling starts here
            session['failed_attempts'] = session.get('failed_attempts', 0) + 1

            if session['failed_attempts'] >= 5:
                session['lock_until'] = time.time() + 30  # 30 seconds lockout
                session.pop('failed_attempts', None)
                flash("Too many failed login attempts. Account temporarily locked for 30 seconds.", "danger")
            else:
                flash("Login failed. Wrong username or password.", "danger")
    else:
        # Check if currently locked
        if session.get('lock_until') and time.time() < session['lock_until']:
            flash("Account temporarily locked. Please wait.", "warning")
            return render_template('login.html')

    return render_template('login.html')

@app.route('/otp', methods=['GET', 'POST'])
def otp():
    if request.method == 'POST':
        entered_otp = request.form['otp']
        if entered_otp == session.get('otp'):
            session['user_id'] = session.pop('pending_user_id')
            session.pop('otp', None)
            session['last_active'] = time.time()
            return redirect(url_for('dashboard'))
        else:
            flash("Incorrect OTP.", "danger")
    return render_template('otp.html')

@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session or is_session_expired():
        flash("Session expired or not logged in.", "warning")
        return redirect(url_for('login'))
    session['last_active'] = time.time()
    return render_template('dashboard.html')

@app.route('/add-password', methods=['GET', 'POST'])
def add_password():
    if 'user_id' not in session or is_session_expired():
        flash("Session expired or not logged in.", "warning")
        return redirect(url_for('login'))

    if not is_key_loaded():
        flash("Encryption key not loaded!", "danger")
        return redirect(url_for('key_not_loaded'))

    if request.method == 'POST':
        site = request.form['site'].strip()
        password = request.form['password'].strip()
        pm.add_password(session['user_id'], site, password)
        flash("Password added successfully!", "success")
        session['last_active'] = time.time()
        return redirect(url_for('dashboard'))

    return render_template('add_password.html')

@app.route('/view-passwords')
def view_passwords():
    if 'user_id' not in session or is_session_expired():
        flash("Session expired or not logged in.", "warning")
        return redirect(url_for('login'))

    if not is_key_loaded():
        flash("Encryption key not loaded!", "danger")
        return redirect(url_for('key_not_loaded'))

    # ✅ Get user ID from session
    user_id = session['user_id']

    # ✅ Connect directly to passwords.db
    with sqlite3.connect('passwords.db') as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT site FROM passwords WHERE user_id = ?", (user_id,))
        sites = cursor.fetchall()

    passwords = []
    for site_row in sites:
        site = site_row[0]
        password = pm.get_password(user_id, site)
        passwords.append((site, password))

    session['last_active'] = time.time()

    return render_template('view_passwords.html', passwords=passwords)

@app.route('/logout')
def logout():
    username = session.get('username')
    session.clear()
    if username:
        log_action(f"User logged out: {username}")
    flash("Logged out successfully.", "info")
    return redirect(url_for('login'))

@app.route('/key-not-loaded', methods=['GET', 'POST'])
def key_not_loaded():
    if request.method == 'POST':
        try:
            pm.load_key()
            flash("Encryption key loaded successfully!", "success")
            return redirect(url_for('dashboard'))
        except Exception as e:
            flash(f"Failed to load encryption key: {str(e)}", "danger")
    return render_template('key_not_loaded.html')

if __name__ == "__main__":
    app.run(debug=True)
