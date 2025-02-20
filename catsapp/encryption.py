from base64 import b64encode, b64decode
import random
import string
'''
# CHIFFREMENT CÉSAR

def generate_random_key():
    """Génère une clé aléatoire de longueur 1 lettre pour le chiffrement César."""
    return random.choice(string.ascii_uppercase)

def encrypt(text):
    """
    Chiffre un texte en utilisant le chiffrement de César avec une clé aléatoire.
    
    Args:
        text (str): Le texte à chiffrer
    
    Returns:
        tuple: (texte_chiffré, clé)
    """
    if not text:
        return "", ""
        
    # Générer une clé aléatoire
    key = generate_random_key()
    
    encrypted = ""
    key = key.upper()
    key_shift = ord(key) - ord('A')
    
    for char in text:
        if char.isalpha():
            # Détermine si le caractère est en majuscule ou minuscule
            is_upper = char.isupper()
            char_idx = ord(char.upper()) - ord('A')
            
            # Applique le chiffrement de César
            encrypted_idx = (char_idx + key_shift) % 26
            
            # Convertit l'index en caractère en préservant la casse
            encrypted_char = chr(encrypted_idx + ord('A'))
            if not is_upper:
                encrypted_char = encrypted_char.lower()
            
            encrypted += encrypted_char
        else:
            encrypted += char
            
    return encrypted, key

def decrypt(text, key):
    """
    Déchiffre un texte chiffré avec le chiffrement de César.
    
    Args:
        text (str): Le texte à déchiffrer
        key (str): La clé de déchiffrement
    
    Returns:
        str: Le texte déchiffré
    """
    if not text or not key:
        return ""
        
    decrypted = ""
    key = key.upper()
    key_shift = ord(key) - ord('A')
    
    for char in text:
        if char.isalpha():
            # Détermine si le caractère est en majuscule ou minuscule
            is_upper = char.isupper()
            char_idx = ord(char.upper()) - ord('A')
            
            # Applique le déchiffrement de César
            decrypted_idx = (char_idx - key_shift) % 26
            
            # Convertit l'index en caractère en préservant la casse
            decrypted_char = chr(decrypted_idx + ord('A'))
            if not is_upper:
                decrypted_char = decrypted_char.lower()
            
            decrypted += decrypted_char
        else:
            decrypted += char
            
    return decrypted

def encrypt_key(key, contact_key):
    """
    Chiffre une clé avec une contact_key.
    
    Args:
        key (str): La clé à chiffrer
        contact_key (str): La clé de contact utilisée pour le chiffrement
    
    Returns:
        str: La clé chiffrée
    """
    encrypted_key = ''.join(chr((ord(k) + ord(c)) % 256) for k, c in zip(key, contact_key))
    return b64encode(encrypted_key.encode()).decode()

def decrypt_key(encrypted_key, contact_key):
    """
    Déchiffre une clé chiffrée avec une contact_key.
    
    Args:
        encrypted_key (str): La clé chiffrée
        contact_key (str): La clé de contact utilisée pour le déchiffrement
    
    Returns:
        str: La clé déchiffrée
    """
    encrypted_key = b64decode(encrypted_key).decode()
    decrypted_key = ''.join(chr((ord(k) - ord(c)) % 256) for k, c in zip(encrypted_key, contact_key))
    return decrypted_key
'''
def generate_random_key():
    """Génère une clé aléatoire de longueur entre 10 et 15 lettres."""
    key_length = random.randint(10, 15)
    return ''.join(random.choices(string.ascii_uppercase, k=key_length))

def encrypt(text):
    """
    Chiffre un texte en utilisant le chiffrement de Vigenère avec une clé aléatoire.
    
    Args:
        text (str): Le texte à chiffrer
    
    Returns:
        tuple: (texte_chiffré, clé)
    """
    if not text:
        return "", ""
        
    # Générer une clé aléatoire
    key = generate_random_key()
    
    encrypted = ""
    key = key.upper()
    key_length = len(key)
    key_as_int = [ord(i) - ord('A') for i in key]
    
    for i, char in enumerate(text):
        if char.isalpha():
            # Détermine si le caractère est en majuscule ou minuscule
            is_upper = char.isupper()
            char_idx = ord(char.upper()) - ord('A')
            # Utilise la clé de manière cyclique
            key_idx = key_as_int[i % key_length]
            
            # Applique le chiffrement de Vigenère
            encrypted_idx = (char_idx + key_idx) % 26
            
            # Convertit l'index en caractère en préservant la casse
            encrypted_char = chr(encrypted_idx + ord('A'))
            if not is_upper:
                encrypted_char = encrypted_char.lower()
            
            encrypted += encrypted_char
        else:
            encrypted += char
            
    return encrypted, key

def decrypt(text, key):
    """
    Déchiffre un texte chiffré avec le chiffrement de Vigenère.
    
    Args:
        text (str): Le texte à déchiffrer
        key (str): La clé de déchiffrement
    
    Returns:
        str: Le texte déchiffré
    """
    if not text or not key:
        return ""
        
    decrypted = ""
    key = key.upper()
    key_length = len(key)
    key_as_int = [ord(i) - ord('A') for i in key]
    
    for i, char in enumerate(text):
        if char.isalpha():
            # Détermine si le caractère est en majuscule ou minuscule
            is_upper = char.isupper()
            char_idx = ord(char.upper()) - ord('A')
            
            # Utilise la clé de manière cyclique
            key_idx = key_as_int[i % key_length]
            
            # Applique le déchiffrement de Vigenère
            decrypted_idx = (char_idx - key_idx) % 26
            
            # Convertit l'index en caractère en préservant la casse
            decrypted_char = chr(decrypted_idx + ord('A'))
            if not is_upper:
                decrypted_char = decrypted_char.lower()
            
            decrypted += decrypted_char
        else:
            decrypted += char
            
    return decrypted

def encrypt_key(key, contact_key):
    """
    Chiffre une clé avec une contact_key.
    
    Args:
        key (str): La clé à chiffrer
        contact_key (str): La clé de contact utilisée pour le chiffrement
    
    Returns:
        str: La clé chiffrée
    """
    encrypted_key = ''.join(chr((ord(k) + ord(c)) % 256) for k, c in zip(key, contact_key))
    return b64encode(encrypted_key.encode()).decode()

def decrypt_key(encrypted_key, contact_key):
    """
    Déchiffre une clé chiffrée avec une contact_key.
    
    Args:
        encrypted_key (str): La clé chiffrée
        contact_key (str): La clé de contact utilisée pour le déchiffrement
    
    Returns:
        str: La clé déchiffrée
    """
    encrypted_key = b64decode(encrypted_key).decode()
    decrypted_key = ''.join(chr((ord(k) - ord(c)) % 256) for k, c in zip(encrypted_key, contact_key))
    return decrypted_key
