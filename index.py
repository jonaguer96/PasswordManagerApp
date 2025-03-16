import sqlite3
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
        """Initialize SQLite database and create the passwords table if it doesn't exist."""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS passwords (
                    site TEXT PRIMARY KEY,
                    encrypted_password TEXT NOT NULL
                )
            """)
            conn.commit()

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

    def add_password(self, site, password):
        """Encrypt and store a password in SQLite."""
        if not self.key:
            print("Error: No key loaded.")
            return

        encrypted_password = base64.b64encode(Fernet(self.key).encrypt(password.encode())).decode()

        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute(
                "INSERT OR REPLACE INTO passwords (site, encrypted_password) VALUES (?, ?)",
                (site, encrypted_password)
            )
            conn.commit()
        print(f"Password for {site} stored securely.")

    def get_password(self, site):
        """Retrieve and decrypt a password from SQLite."""
        if not self.key:
            print("Error: No key loaded.")
            return None

        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT encrypted_password FROM passwords WHERE site = ?", (site,))
            result = cursor.fetchone()

        if result:
            decrypted_password = Fernet(self.key).decrypt(base64.b64decode(result[0])).decode()
            return decrypted_password
        else:
            print(f"Error: No password found for {site}.")
            return None

    def update_password(self, site, new_password):
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
        """Delete a password from SQLite."""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM passwords WHERE site = ?", (site,))
            conn.commit()
        print(f"Password for {site} deleted successfully.")

# --- Example Usage ---
def main():
    pm = PasswordManager()

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
            pm.add_password(site, password)
        elif choice == '4':
            site = input("Enter site: ")
            print(f"Password for {site}: {pm.get_password(site)}")
        elif choice == '5':
            site = input("Enter site: ")
            new_password = getpass.getpass("Enter new password: ")
            pm.update_password(site, new_password)
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
