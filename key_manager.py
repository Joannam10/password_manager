from cryptography.fernet import Fernet
import os

def generate_key():
    """Generates a new encryption key and saves it to a file."""
    key = Fernet.generate_key()
    with open("secret.key", "wb") as key_file:
        key_file.write(key)
    print("Encryption key generated and saved to 'secret.key'")

def load_key():
    """Loads the encryption key from the current directory."""
    try:
        return open("secret.key", "rb").read()
    except FileNotFoundError:
        print("Encryption key not found. Please run generate_key() first.")
        return None

def get_fernet_cipher():
    """Returns a Fernet cipher object using the loaded key."""
    key = load_key()
    if key:
        return Fernet(key)
    return None

if __name__ == "__main__":
    # This block will only run if key_manager.py is executed directly
    if not os.path.exists("secret.key"):
        generate_key()
    else:
        print("secret.key already exists. To generate a new one, delete the existing file.")