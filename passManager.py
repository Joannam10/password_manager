import json
import os
import hashlib # For hashing master password
import pyperclip # For copying passwords to clipboard

# Assuming key_manager.py is in the same directory
from key_manager import get_fernet_cipher, generate_key

DATA_FILE = "passwords.json"
MASTER_PASSWORD_HASH_FILE = "master_hash.txt"

class PasswordManager:
    def __init__(self):
        self.fernet = get_fernet_cipher()
        if not self.fernet:
            print("Encryption key not found. Generating a new one.")
            generate_key()
            self.fernet = get_fernet_cipher()
            if not self.fernet:
                raise Exception("Failed to initialize encryption cipher.")

        self.passwords = self._load_passwords()
        self.master_password_hash = self._load_master_password_hash()

    def _load_passwords(self):
        """Loads encrypted passwords from the data file."""
        if os.path.exists(DATA_FILE):
            try:
                with open(DATA_FILE, "r") as f:
                    encrypted_data = json.load(f)
                decrypted_passwords = {}
                for service, encrypted_password_str in encrypted_data.items():
                    # Fernet.decrypt expects bytes, so we encode the base64 string to bytes
                    decrypted_password = self.fernet.decrypt(encrypted_password_str.encode()).decode()
                    decrypted_passwords[service] = decrypted_password
                return decrypted_passwords
            except Exception as e:
                print(f"Error loading passwords: {e}. Starting with empty data.")
                return {}
        return {}

    def _save_passwords(self):
        """Saves encrypted passwords to the data file."""
        encrypted_data_to_save = {}
        for service, password in self.passwords.items():
            # Encrypt the password (which is a string) to bytes
            encrypted_password_bytes = self.fernet.encrypt(password.encode())
            # Convert the encrypted bytes to a base64 string for JSON storage
            encrypted_data_to_save[service] = encrypted_password_bytes.decode()
        with open(DATA_FILE, "w") as f:
            json.dump(encrypted_data_to_save, f, indent=4)

    @staticmethod # Added staticmethod decorator
    def _hash_password(password): # self parameter removed
        """Hashes the password using SHA256."""
        return hashlib.sha256(password.encode()).hexdigest()

    @staticmethod # Added staticmethod decorator
    def _load_master_password_hash(): # self parameter removed
        """Loads the master password hash from file."""
        if os.path.exists(MASTER_PASSWORD_HASH_FILE):
            with open(MASTER_PASSWORD_HASH_FILE, "r") as f:
                return f.read().strip()
        return None

    @staticmethod # Added staticmethod decorator
    def _save_master_password_hash(master_hash): # self parameter removed
        """Saves the master password hash to file."""
        with open(MASTER_PASSWORD_HASH_FILE, "w") as f:
            f.write(master_hash)

    def set_master_password(self):
        """Sets or updates the master password."""
        while True:
            new_master = input("Enter a new master password: ")
            confirm_master = input("Confirm new master password: ")
            if new_master == confirm_master and new_master:
                self.master_password_hash = self._hash_password(new_master)
                self._save_master_password_hash(self.master_password_hash)
                print("Master password set successfully!")
                break
            else:
                print("Passwords do not match or are empty. Please try again.")

    def authenticate(self):
        """Authenticates the user with the master password."""
        print("DEBUG: Inside authenticate function.") # <-- הוסף שורה זו
        if not self.master_password_hash:
            print("DEBUG: Master password hash not found. Setting new one.") # <-- הוסף שורה זו
            print("No master password set. Please set one first.")
            self.set_master_password()
            return True # After setting, assume authenticated

        entered_master = input("Enter master password: ") # <--- וודא שזה input כאן!
        print(f"DEBUG: Entered master password (hashed): {self._hash_password(entered_master)}") # <-- הוסף שורה זו
        print(f"DEBUG: Stored master password hash: {self.master_password_hash}") # <-- הוסף שורה זו

        if self._hash_password(entered_master) == self.master_password_hash:
            print("Authentication successful!")
            return True
        else:
            print("Authentication failed.")
            print("DEBUG: Master password mismatch.") # <-- הוסף שורה זו
            return False

    def add_password(self):
        """Adds a new password entry."""
        if not self.authenticate(): return

        service = input("Enter service name (e.g., Google, Facebook): ").strip()
        password = input("Enter password: ").strip() # השתמשנו ב-input באופן זמני, וחשוב לוודא שיש .strip()

        print(f"DEBUG: Service entered: '{service}', Password entered (length): {len(password) if password else 0}") # <-- הוסף שורה זו

        if service and password:
            self.passwords[service] = password
            self._save_passwords()
            print(f"Password for '{service}' added successfully.")
        else:
            print("DEBUG: Service or password was empty.") # <-- הוסף שורה זו
            print("Service and password cannot be empty.")

    def view_passwords(self):
        """Displays all stored passwords."""
        if not self.authenticate(): return

        if not self.passwords:
            print("No passwords stored yet.")
            return

        print("\n--- Your Passwords ---")
        for service, password in self.passwords.items():
            print(f"Service: {service}, Password: {password}")
        print("----------------------\n")

    def get_password(self):
        """Retrieves and optionally copies a specific password."""
        if not self.authenticate(): return

        service = input("Enter service name to retrieve: ").strip()
        if service in self.passwords:
            password = self.passwords[service]
            print(f"Password for {service}: {password}")
            try:
                pyperclip.copy(password)
                print("Password copied to clipboard!")
            except pyperclip.PyperclipException as e:
                print(f"Could not copy to clipboard: {e}. Please copy manually.")
        else:
            print(f"Password for '{service}' not found.")

    def delete_password(self):
        """Deletes a password entry."""
        if not self.authenticate(): return

        service = input("Enter service name to delete: ").strip()
        if service in self.passwords:
            del self.passwords[service]
            self._save_passwords()
            print(f"Password for '{service}' deleted successfully.")
        else:
            print(f"Password for '{service}' not found.")

def main():
    manager = PasswordManager()

    while True:
        print("\n--- Password Manager Menu ---")
        print("1. Set/Update Master Password")
        print("2. Add New Password")
        print("3. View All Passwords")
        print("4. Get Specific Password (and copy to clipboard)")
        print("5. Delete Password")
        print("6. Exit")

        choice = input("Enter your choice: ")

        if choice == '1':
            manager.set_master_password()
        elif choice == '2':
            manager.add_password()
        elif choice == '3':
            manager.view_passwords()
        elif choice == '4':
            manager.get_password()
        elif choice == '5':
            manager.delete_password()
        elif choice == '6':
            print("Exiting Password Manager. Goodbye!")
            break
        else:
            print("Invalid choice. Please try again.")

if __name__ == "__main__":
    main()