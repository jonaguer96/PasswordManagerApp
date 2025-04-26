import sqlite3
import hashlib
import base64
import itertools
import string
import time

def fetch_user_credentials(db_path, username):
    with sqlite3.connect(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT password_salt, password_hash FROM users WHERE username = ?", (username,))
        row = cursor.fetchone()
        if row:
            salt = base64.b64decode(row[0])
            stored_hash = base64.b64decode(row[1])
            return salt, stored_hash
        else:
            print("User not found.")
            return None, None
        
def brute_force_password(salt, stored_hash):
    characters = string.ascii_lowercase  # 'abcdefghijklmnopqrstuvwxyz'
    total_attempts = 0
    start_time = time.time()

    for guess_tuple in itertools.product(characters, repeat=5):
        guess = ''.join(guess_tuple)
        guess_hash = hashlib.pbkdf2_hmac('sha256', guess.encode(), salt, 1000)
        total_attempts += 1
        if guess_hash == stored_hash:
            end_time = time.time()
            print(f"Password found: {guess}")
            print(f"Attempts: {total_attempts}")
            print(f"Time taken: {end_time - start_time:.2f} seconds")
            return guess

    print("Password not found.")
    return None

def main():
    db_path = 'passwords.db'  # your real database
    username = 'ProfessionalVictim3'     # your test user

    salt, stored_hash = fetch_user_credentials(db_path, username)
    if salt and stored_hash:
        brute_force_password(salt, stored_hash)

if __name__ == "__main__":
    main()
