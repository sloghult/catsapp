from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import base64
import os
import logging

logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

def generate_rsa_keys():
    """Génère une paire de clés RSA."""
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()

    private_key_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

    public_key_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    return private_key_pem, public_key_pem

def generate_symmetric_key():
    """Génère une clé symétrique."""
    salt = os.urandom(16)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    key = kdf.derive(os.urandom(32))
    return key

def encrypt_message(message, key):
    """Chiffre un message avec une clé symétrique."""
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    encrypted_message = encryptor.update(message.encode('utf-8')) + encryptor.finalize()
    logger.debug(f"Message chiffré: {base64.b64encode(encrypted_message).decode('utf-8')}")
    return base64.b64encode(iv + encrypted_message).decode('utf-8')

def decrypt_message(encrypted_message, key):
    """Déchiffre un message avec une clé symétrique."""
    try:
        encrypted_message_bytes = base64.b64decode(encrypted_message.encode('utf-8'))
        iv = encrypted_message_bytes[:16]
        cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        decrypted_message = decryptor.update(encrypted_message_bytes[16:]) + decryptor.finalize()
        logger.debug(f"Message déchiffré: {decrypted_message.decode('utf-8')}")
        return decrypted_message.decode('utf-8')
    except Exception as e:
        logger.error(f"Erreur lors du déchiffrement du message: {str(e)}")
        raise

def encrypt_symmetric_key(symmetric_key, public_key_pem):
    """Chiffre une clé symétrique avec une clé publique RSA."""
    public_key = serialization.load_pem_public_key(public_key_pem, backend=default_backend())
    encrypted_key = public_key.encrypt(
        symmetric_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return base64.b64encode(encrypted_key).decode('utf-8')

def decrypt_symmetric_key(encrypted_key, private_key_pem):
    """Déchiffre une clé symétrique avec une clé privée RSA."""
    try:
        private_key = serialization.load_pem_private_key(private_key_pem, password=None, backend=default_backend())
        encrypted_key_bytes = base64.b64decode(encrypted_key.encode('utf-8'))
        decrypted_key = private_key.decrypt(
            encrypted_key_bytes,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return decrypted_key
    except Exception as e:
        logger.error(f"Erreur lors du déchiffrement de la clé symétrique: {str(e)}")
        raise
