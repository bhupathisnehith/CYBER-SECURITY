from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.fernet import Fernet
import base64, os
import getpass

def derive_key(password: str, salt: bytes) -> bytes:
    """Derives a secure encryption key from a password using PBKDF2."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode()))

def encrypt_file(file_path: str, password: str):
    """Encrypts a file using AES-256 via Fernet."""
    salt = os.urandom(16)
    key = derive_key(password, salt)
    fernet = Fernet(key)

    with open(file_path, 'rb') as file:
        data = file.read()

    encrypted = fernet.encrypt(data)

    with open(file_path + '.enc', 'wb') as file:
        file.write(salt + encrypted)

    print(f"[+] File encrypted: {file_path}.enc")

def decrypt_file(file_path: str, password: str):
    """Decrypts a previously encrypted file."""
    with open(file_path, 'rb') as file:
        content = file.read()

    salt = content[:16]
    encrypted = content[16:]

    key = derive_key(password, salt)
    fernet = Fernet(key)

    try:
        decrypted = fernet.decrypt(encrypted)
        output_path = file_path.replace('.enc', '.dec')
        with open(output_path, 'wb') as file:
            file.write(decrypted)
        print(f"[+] File decrypted: {output_path}")
    except Exception as e:
        print("[!] Decryption failed:", e)

def main():
    print("==========================================")
    print("=== Advanced AES-256 Encryption Tool ===")
    print("==========================================\n")
    print("1. Encrypt File")
    print("2. Decrypt File")
    choice = input("Select option (1/2): ").strip()

    if choice not in ('1', '2'):
        print("[!] Invalid choice.")
        return

    file_path = input("Enter file path: ").strip()
    if not os.path.exists(file_path):
        print("[!] File not found.")
        return

    password = getpass.getpass("Enter encryption password: ")

    if choice == '1':
        encrypt_file(file_path, password)
    elif choice == '2':
        decrypt_file(file_path, password)

if __name__ == "__main__":
    main()

**OUTPUT**
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.fernet import Fernet
import base64, os
import getpass

def derive_key(password: str, salt: bytes) -> bytes:
    """Derives a secure encryption key from a password using PBKDF2."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode()))

def encrypt_file(file_path: str, password: str):
    """Encrypts a file using AES-256 via Fernet."""
    salt = os.urandom(16)
    key = derive_key(password, salt)
    fernet = Fernet(key)

    with open(file_path, 'rb') as file:
        data = file.read()

    encrypted = fernet.encrypt(data)

    with open(file_path + '.enc', 'wb') as file:
        file.write(salt + encrypted)

    print(f"[+] File encrypted: {file_path}.enc")

def decrypt_file(file_path: str, password: str):
    """Decrypts a previously encrypted file."""
    with open(file_path, 'rb') as file:
        content = file.read()

    salt = content[:16]
    encrypted = content[16:]

    key = derive_key(password, salt)
    fernet = Fernet(key)

    try:
        decrypted = fernet.decrypt(encrypted)
        output_path = file_path.replace('.enc', '.dec')
        with open(output_path, 'wb') as file:
            file.write(decrypted)
        print(f"[+] File decrypted: {output_path}")
    except Exception as e:
        print("[!] Decryption failed:", e)

def main():
    print("==========================================")
    print("=== Advanced AES-256 Encryption Tool ===")
    print("==========================================\n")
    print("1. Encrypt File")
    print("2. Decrypt File")
    choice = input("Select option (1/2): ").strip()

    if choice not in ('1', '2'):
        print("[!] Invalid choice.")
        return

    file_path = input("Enter file path: ").strip()
    if not os.path.exists(file_path):
        print("[!] File not found.")
        return

    password = getpass.getpass("Enter encryption password: ")

    if choice == '1':
        encrypt_file(file_path, password)
    elif choice == '2':
        decrypt_file(file_path, password)

if __name__ == "__main__":
    main()

**OUTPUT**
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.fernet import Fernet
import base64, os
import getpass

def derive_key(password: str, salt: bytes) -> bytes:
    """Derives a secure encryption key from a password using PBKDF2."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode()))

def encrypt_file(file_path: str, password: str):
    """Encrypts a file using AES-256 via Fernet."""
    salt = os.urandom(16)
    key = derive_key(password, salt)
    fernet = Fernet(key)

    with open(file_path, 'rb') as file:
        data = file.read()

    encrypted = fernet.encrypt(data)

    with open(file_path + '.enc', 'wb') as file:
        file.write(salt + encrypted)

    print(f"[+] File encrypted: {file_path}.enc")

def decrypt_file(file_path: str, password: str):
    """Decrypts a previously encrypted file."""
    with open(file_path, 'rb') as file:
        content = file.read()

    salt = content[:16]
    encrypted = content[16:]

    key = derive_key(password, salt)
    fernet = Fernet(key)

    try:
        decrypted = fernet.decrypt(encrypted)
        output_path = file_path.replace('.enc', '.dec')
        with open(output_path, 'wb') as file:
            file.write(decrypted)
        print(f"[+] File decrypted: {output_path}")
    except Exception as e:
        print("[!] Decryption failed:", e)

def main():
    print("==========================================")
    print("=== Advanced AES-256 Encryption Tool ===")
    print("==========================================\n")
    print("1. Encrypt File")
    print("2. Decrypt File")
    choice = input("Select option (1/2): ").strip()

    if choice not in ('1', '2'):
        print("[!] Invalid choice.")
        return

    file_path = input("Enter file path: ").strip()
    if not os.path.exists(file_path):
        print("[!] File not found.")
        return

    password = getpass.getpass("Enter encryption password: ")

    if choice == '1':
        encrypt_file(file_path, password)
    elif choice == '2':
        decrypt_file(file_path, password)

if __name__ == "__main__":
    main()

**OUTPUT**
==========================================
=== Advanced AES-256 Encryption Tool ===
==========================================

1. Encrypt File
2. Decrypt File
Select option (1/2): 1
Enter file path: /hello.txt.txt
Enter encryption password: ··········
[+] File encrypted: /hello.txt.txt.enc
------------------------------------------------------
Select option (1/2): 2
Enter file path: hello.txt.enc
Enter encryption password: ··········
[+] File decrypted: secret.txt.dec
