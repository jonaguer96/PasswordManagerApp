import base64
from cryptography.fernet import Fernet

# PasswordManager class
class PasswordManager:
    def __init__(self):
        self.key = None
        self.password_file = None
        self.password_dict = {}

    # Generate key
    def generate_key(self, path):
        self.key = Fernet.generate_key()
        with open(path, 'wb') as file:
            file.write(self.key)

    # Load key
    def load_key(self, path):
        with open(path, 'rb') as file:
            self.key = file.read()

    # Generate password file
    def generate_password_file(self, path, initial_passwords=None):
        self.password_file = path
        if initial_passwords:
            for site, password in initial_passwords.items():
                self.add_password(site, password)

    # Load password file
    def load_password_file(self, path):
        self.password_file = path
        with open(path, 'r') as file:
            for line in file:
                try:
                    site, encrypted = line.strip().split(':')
                    decrypted_password = Fernet(self.key).decrypt(base64.b64decode(encrypted)).decode()
                    self.password_dict[site] = decrypted_password
                except Exception as e:
                    print(f"Error loading '{line.strip()}': {e}")
                    continue  

    # Add password
    def add_password(self, site, password):
        if not self.key:
            print("Error: No key loaded.")
            return

        # Encrypt the password
        self.password_dict[site] = password
        if self.password_file:
            with open(self.password_file, 'a') as file:
                encrypted = Fernet(self.key).encrypt(password.encode())
                file.write(f"{site}:{base64.b64encode(encrypted).decode()}\n")

    # Get password
    def get_password(self, site):
        return self.password_dict.get(site, None)
    
# Main function
def main():
    password = {
        "google": "password123",
        "facebook": "password456",
        "twitter": "password789",
        "youtube": "password000",
        "something": "password0001"
    }

    pm = PasswordManager()

    # Display the menu
    print(""""Welcome to Password Manager
    1. Generate Key
    2. Load Key"
    3. Generate Password File
    4. Load Password File"
    5. Add Password"
    6. Get Password
    7. Exit""")

    done = False

    # Loop until the user is done
    while not done:
        choice = input("Enter choice: ")

        # Perform the desired action
        if choice == '1':
            path = input("Enter path to save key: ")
            pm.generate_key(path)
        elif choice == '2':
            path = input("Enter path to load key: ")
            pm.load_key(path)
        elif choice == '3':
            path = input("Enter path to save password file: ")
            pm.generate_password_file(path, password)
        elif choice == '4':
            path = input("Enter path to load password file: ")
            pm.load_password_file(path)
        elif choice == '5':
            site = input("Enter site: ")
            password = input("Enter password: ")
            pm.add_password(site, password)
        elif choice == '6':
            site = input("Enter site: ")
            print(f"Password for {site} is {pm.get_password(site)}")
        elif choice == '7':
            done = True
        else:
            print("Invalid choice")

# Run the main function
if __name__ == '__main__':
    main()
