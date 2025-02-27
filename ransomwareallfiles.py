import os
import base64
import getpass
import pathlib
import secrets
import sys
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

DESKTOP_PATH = os.path.join(os.path.expanduser("~"), "Desktop")
TARGET_FOLDER = os.path.join(DESKTOP_PATH, "test-folder")
SALT_FILE = os.path.join(TARGET_FOLDER, ".salt.salt")
BAT_FILE = os.path.join(TARGET_FOLDER, "decrypt_all.bat")
README_FILE = os.path.join(TARGET_FOLDER, "README.txt")

WARNING_MESSAGE = (
    "\n⚠ THIS FILE IS ENCRYPTED ⚠\n"
    "You must enter the correct password to access the contents.\n"
    "If you enter the wrong password, decryption will fail.\n\n"
).encode()

ALERT_MESSAGE = (
    "\n🚨 FILE ENCRYPTED 🚨\n"
    "This file is encrypted and cannot be opened directly.\n"
    "To decrypt all files, run 'decrypt_all.bat' and enter the correct password.\n"
).encode()

def generate_salt(size=16):
    """Generates a salt for key derivation, ensuring it is never encrypted."""
    if not os.path.exists(SALT_FILE):
        salt = secrets.token_bytes(size)
        with open(SALT_FILE, "wb") as f:
            f.write(salt)
    else:
        with open(SALT_FILE, "rb") as f:
            salt = f.read()
    return salt

def derive_key(password, salt):
    """Derives a strong encryption key using Scrypt KDF."""
    kdf = Scrypt(salt=salt, length=32, n=2**14, r=8, p=1)
    return base64.urlsafe_b64encode(kdf.derive(password.encode()))

def get_key(password):
    """Retrieves or generates a salt and derives the encryption key."""
    salt = generate_salt()
    return derive_key(password, salt)

def create_decryption_bat():
    """Creates a batch file to simplify decryption for users."""
    bat_content = f"""@echo off
python "{os.path.abspath(__file__)}" decrypt
pause
"""
    with open(BAT_FILE, "w") as bat_file:
        bat_file.write(bat_content)

def create_warning_readme():
    """Creates a README file warning users about encrypted files."""
    if not os.path.exists(README_FILE):
        with open(README_FILE, "w", encoding="utf-8") as f:
            f.write(ALERT_MESSAGE.decode())

def encrypt_file(filepath, key):
    """Encrypts a file and replaces it with an encrypted version."""
    try:
        if filepath == SALT_FILE or filepath.endswith(".byte"):
            return  # Do not encrypt the salt file or already encrypted files
        
        fernet = Fernet(key)
        with open(filepath, "rb") as file:
            file_data = file.read()

        encrypted_data = fernet.encrypt(ALERT_MESSAGE + file_data)
        encrypted_filepath = f"{filepath}.byte"

        with open(encrypted_filepath, "wb") as file:
            file.write(encrypted_data)

        os.remove(filepath)
        print(f"[✔] Encrypted {os.path.basename(filepath)} → {os.path.basename(encrypted_filepath)}")
    except Exception as e:
        print(f"[!] Error encrypting {filepath}: {e}")

def decrypt_all_files(key):
    """Decrypts all encrypted files in the folder."""
    enc_files = list(pathlib.Path(TARGET_FOLDER).glob("*.byte"))
    if not enc_files:
        print("[⚠] No encrypted files found to decrypt.")
        return

    for file in enc_files:
        try:
            if file.name == ".salt.salt.byte":
                print(f"[⚠] Skipping {file.name}, salt should never be encrypted.")
                continue  # Skip salt file

            fernet = Fernet(key)
            with open(file, "rb") as encrypted_file:
                encrypted_data = encrypted_file.read()

            decrypted_data = fernet.decrypt(encrypted_data)

            if decrypted_data.startswith(ALERT_MESSAGE):
                decrypted_data = decrypted_data[len(ALERT_MESSAGE):]

            decrypted_filepath = file.with_suffix("")
            with open(decrypted_filepath, "wb") as decrypted_file:
                decrypted_file.write(decrypted_data)

            os.remove(file)
            print(f"[✔] Decrypted {file.name} → {decrypted_filepath.name}")
        except Exception:
            print(f"[❌] Failed to decrypt {file.name}. Incorrect password?")
            return

if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "decrypt":
        print("\n🚨 FILES ENCRYPTED 🚨\n")
        password = getpass.getpass("Enter decryption key: ")
        key = get_key(password)
        decrypt_all_files(key)
        input("\nPress Enter to exit...")
        sys.exit()

    if not os.path.exists(TARGET_FOLDER):
        print(f"[⚠] Folder '{TARGET_FOLDER}' does not exist.")
        exit()

    password = "1234"  # Change this to user input in production
    key = get_key(password)
    files_to_encrypt = [
        f for f in pathlib.Path(TARGET_FOLDER).iterdir()
        if f.is_file() and f.name != ".salt.salt" and not f.name.endswith(".byte")
    ]

    if files_to_encrypt:
        for file in files_to_encrypt:
            encrypt_file(str(file), key)
        print("\n[🔒] All files encrypted.")
        create_decryption_bat()
        create_warning_readme()
    else:
        print("\n[⚠] No files found to encrypt.")
