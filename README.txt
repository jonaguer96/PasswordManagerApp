Password Manager - CS5340 Project
=================================

This is a secure password manager built for the CS5340 Information Security course. 
It allows users to create accounts, store encrypted passwords for various sites, 
and retrieve, update, or delete them securely.

Features
--------

- User registration with strong password validation
- Password strength checking using rockyou.txt dictionary
- Password hashing using PBKDF2-HMAC-SHA256 with customizable iterations
- Password encryption using Fernet (symmetric encryption)
- Local SQLite database to store credentials per user
- Command-line interface (CLI) for interaction
- Optional Flask-based web interface with OTP verification and session management

Requirements
------------

- Python 3.8 or newer
- Required libraries:
    - cryptography
    - flask
    - (optional) argon2-cffi if extended to Argon2

Install dependencies with:
    pip install cryptography flask

Note:
-----

- The `rockyou.txt` file must be present in the project directory.
  If you do not have it, you can find it online as part of common password datasets 
  (e.g., https://github.com/brannondorsey/naive-hashcat/releases/).

Usage (CLI)
-----------

1. Run the program:
    python3 index.py

2. Menu options:
    - Register or log in
    - Generate/load encryption key
    - Add, get, update, or delete site-specific passwords

Usage (Flask Web App)
---------------------

1. Make sure your `index.py` and the Flask script are in the same directory.

2. Create HTML templates (e.g., `login.html`, `dashboard.html`, etc.) in a `templates/` folder.

3. Run the Flask app:
    python3 app.py

4. Access the web UI at:
    http://127.0.0.1:5000/

Files
-----

- index.py          : Main application logic for CLI
- app.py            : Optional Flask web server
- rockyou.txt       : Dictionary file to block weak passwords
- key.key           : Encryption key file (generated once)
- passwords.db      : SQLite database storing user and password data
- templates/        : Folder with HTML files for Flask frontend

Security Notes
--------------

- Salt is generated randomly per user and stored encoded
- Passwords are never stored in plaintext
- Encrypted passwords are protected with Fernet encryption
- Login checks use HMAC to avoid timing attacks
- Web version includes OTP and inactivity-based session expiration

