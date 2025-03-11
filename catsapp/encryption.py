from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import base64
import os

def generate_aes_key():
    """Génère une clé AES aléatoire."""
    return os.urandom(32)  # 256 bits pour AES-256

def encrypt_message(message, key):
    """Chiffre un message avec une clé AES."""
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    encrypted_message = encryptor.update(message.encode('utf-8')) + encryptor.finalize()
    return base64.b64encode(iv + encrypted_message).decode('utf-8')

def decrypt_message(encrypted_message, key):
    """Déchiffre un message avec une clé AES."""
    encrypted_message_bytes = base64.b64decode(encrypted_message.encode('utf-8'))
    iv = encrypted_message_bytes[:16]
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_message = decryptor.update(encrypted_message_bytes[16:]) + decryptor.finalize()
    return decrypted_message.decode('utf-8')
