from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend
import base64
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

def encrypt_message(message, public_key_pem):
    """Chiffre un message avec une clé publique RSA."""
    public_key = serialization.load_pem_public_key(public_key_pem, backend=default_backend())
    encrypted_message = public_key.encrypt(
        message.encode('utf-8'),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    logger.debug(f"Message chiffré: {base64.b64encode(encrypted_message).decode('utf-8')}")
    return base64.b64encode(encrypted_message).decode('utf-8')

def decrypt_message(encrypted_message, private_key_pem):
    """Déchiffre un message avec une clé privée RSA."""
    try:
        private_key = serialization.load_pem_private_key(private_key_pem, password=None, backend=default_backend())
        encrypted_message_bytes = base64.b64decode(encrypted_message.encode('utf-8'))
        decrypted_message = private_key.decrypt(
            encrypted_message_bytes,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        logger.debug(f"Message déchiffré: {decrypted_message.decode('utf-8')}")
        return decrypted_message.decode('utf-8')
    except Exception as e:
        logger.error(f"Erreur lors du déchiffrement du message: {str(e)}")
        raise
