import bcrypt
from cryptography.fernet import Fernet

def generate_key(password):
    salt = bcrypt.gensalt()
    key = bcrypt.kdf(password.encode(), salt, 32, 100)
    return Fernet(key)

def encrypt_message(message, password):
    key = generate_key(password)
    encrypted_message = key.encrypt(message.encode())
    return encrypted_message

def decrypt_message(encrypted_message, password):
    key = generate_key(password)
    decrypted_message = key.decrypt(encrypted_message.encode()).decode()
    return decrypted_message
