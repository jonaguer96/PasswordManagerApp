import sqlite3
import hashlib
import hmac
import base64
import os
from cryptography.fernet import Fernet
import getpass

class PasswordManager:
    def __init__(self, db_path="passwords.db"):
        self.key = None
        self.db_path = db_path
        self._init_db()

    def _init_db(self):
        """Initialize SQLite database and create the users and passwords tables if they don't exist."""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()

            # Create users table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT UNIQUE NOT NULL,
                    password_salt TEXT NOT NULL,
                    password_hash TEXT NOT NULL
                )
            """)

            # Create passwords table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS passwords (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER NOT NULL,
                    site TEXT NOT NULL,
                    encrypted_password TEXT NOT NULL,
                    FOREIGN KEY (user_id) REFERENCES users(id),
                    UNIQUE(user_id, site)
                )
            """)

            conn.commit()

    def add_user(self, new_username):

        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()

            #Check if there is a username like that in the database. 
            cursor.execute("SELECT * FROM users WHERE username = ?", (new_username,))
            user = cursor.fetchone()
            #If db fetched a username, then it is already registered.
            if user is not None:
                print("Username is already taken.")
                print("Please try again.")
                return False
            #Otherwise, ask for username, password, and create a random salt to store with them.
            else:
                password = getpass.getpass("Enter a password: ")
                salt = os.urandom(16)
                hashed_password = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100000)
                salt_encoded = base64.b64encode(salt).decode()
                hash_encoded = base64.b64encode(hashed_password).decode()
                cursor.execute(
                    "INSERT INTO users (username, password_salt, password_hash) VALUES (?, ?, ?)",
                    (new_username, salt_encoded, hash_encoded)
                )
                conn.commit()
            print("User registered successfully.")
            return True

    def log_in_user(self, username, user_password):
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()

        #Check if there is a username like that in the database. 
        cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
        user = cursor.fetchone()   
        if user is not None: 
            salt_encoded = user[2]
            hash_encoded = user[3]
            #Decode salt stored in db (does not mean decrypt)
            salt = base64.b64decode(salt_encoded)
            #Decode hash stored in db (does not mean decrypt)
            stored_hash = base64.b64decode(hash_encoded)

            #Hash the entered password with the fetched salt; 
            #see if the hashed password with the same salt results in the same hash in db
            entered_hash = hashlib.pbkdf2_hmac('sha256', user_password.encode(), salt, 100000)
            if hmac.compare_digest(entered_hash, stored_hash):
                return user[0]  # Return the user_id (user[0])
            else:
                print("Incorrect password.")
                return None

        else: 
            print("User does not exist.")
            return False


        
    def generate_key(self, path="key.key"):
        """Generate and store an encryption key locally."""
        if os.path.exists(path):
            print("Error: Key file already exists.")
            return
        self.key = Fernet.generate_key()
        with open(path, 'wb') as file:
            file.write(self.key)
        print("Key generated and saved.")

    def load_key(self, path="key.key"):
        """Load the encryption key from a file."""
        if not os.path.exists(path):
            print("Error: Key file not found.")
            return
        with open(path, 'rb') as file:
            self.key = file.read()
        print("Key loaded successfully.")

    def add_password(self, user_id, site, password):
        """Encrypt and store a password in SQLite."""
        if not self.key:
            print("Error: No key loaded.")
            return

        encrypted_password = base64.b64encode(Fernet(self.key).encrypt(password.encode())).decode()

        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute(
                "INSERT OR REPLACE INTO passwords (user_id, site, encrypted_password) VALUES (?, ?, ?)",
                (user_id, site, encrypted_password)
            )
            conn.commit()
        print(f"Password for {site} stored securely.")

    def get_password(self, user_id, site):
        #TO DO: Input of user id to reference in the database with so the proper user accesses its password.
        """Retrieve and decrypt a password from SQLite."""
        if not self.key:
            print("Error: No key loaded.")
            return None

        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT encrypted_password FROM passwords WHERE site = ? AND user_id = ?", (site, user_id))
            result = cursor.fetchone()

        if result:
            decrypted_password = Fernet(self.key).decrypt(base64.b64decode(result[0])).decode()
            return decrypted_password
        else:
            print(f"Error: No password found for {site}.")
            return None

    def update_password(self, site, new_password):
        #TO DO: Input of user id to reference in the database with so the proper user accesses its password.
        """Update an existing password in SQLite."""
        if not self.key:
            print("Error: No key loaded.")
            return

        encrypted_password = base64.b64encode(Fernet(self.key).encrypt(new_password.encode())).decode()

        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("UPDATE passwords SET encrypted_password = ? WHERE site = ?", (encrypted_password, site))
            conn.commit()
        print(f"Password for {site} updated successfully.")

    def delete_password(self, site):
        #TO DO: Input of user id to reference in the database with so the proper user accesses its password.
        """Delete a password from SQLite."""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM passwords WHERE site = ?", (site,))
            conn.commit()
        print(f"Password for {site} deleted successfully.")

# --- Example Usage ---
def main():
    pm = PasswordManager()
    current_user_id = None
    
    while True:
        print("Welcome!")
        print("1. Log in")
        print("2. Register")
        print("3. Exit")

        choice = input("Enter choice: ")
        
        if choice == '1':
            while True:
                username = input("Username: ")
                user_password = getpass.getpass("Enter password: ")
                result = pm.log_in_user(username, user_password)
                if result:
                    current_user_id = result
                    print("Login successful!")
                    break
                else:
                    print("Login failed. Try again.")
            break

        elif choice == '2': 
            while True:
                new_username = input("Username: ")
                result = pm.add_user(new_username)
                if result is True:
                    print("Registration Successful!")
                    break  # Exit the loop if registration worked
            continue #Skip the rest of this loop and go to the next loop

        elif choice == '3':
            print("Exiting...")
            return

        else: 
            print("Invalid choice. Try again.")

    while True:
        print("\n*** Password Manager ***")
        print("1. Generate Key")
        print("2. Load Key")
        print("3. Add Password")
        print("4. Get Password")
        print("5. Update Password")
        print("6. Delete Password")
        print("7. Exit")

        choice = input("Enter choice: ")

        if choice == '1':
            pm.generate_key()
        elif choice == '2':
            pm.load_key()
        elif choice == '3':
            site = input("Enter site: ")
            password = getpass.getpass("Enter password: ")
            pm.add_password(current_user_id, site, password)
        elif choice == '4':
            site = input("Enter site: ")
            print(f"Password for {site}: {pm.get_password(current_user_id, site)}")
        elif choice == '5':
            site = input("Enter site: ")
            new_password = getpass.getpass("Enter new password: ")
            pm.update_password(current_user_id, site, new_password)
        elif choice == '6':
            site = input("Enter site to delete: ")
            pm.delete_password(site)
        elif choice == '7':
            print("Exiting...")
            break
        else:
            print("Invalid choice. Try again.")

if __name__ == '__main__':
    main()
