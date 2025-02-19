# CHIFFREMENT CESAR


from base64 import b64encode, b64decode
import random
import string


def encrypt(text):
    """
    Chiffre un texte en utilisant une version améliorée du chiffrement de César avec une clé aléatoire.
    Retourne un tuple (texte_chiffré, clé)
    """
    if not isinstance(text, str):
        return "", "0"
    
    try:
        # Générer une clé aléatoire entre 1 et 100
        shift = random.randint(1, 100)
        
        # Convertir en bytes pour gérer tous les types de caractères
        text_bytes = text.encode('utf-8')
        encrypted_bytes = bytes([(b + shift) % 256 for b in text_bytes])
        # Encoder en base64 pour assurer une représentation sûre
        return b64encode(encrypted_bytes).decode('utf-8'), str(shift)
    except Exception as e:
        print(f"Erreur de chiffrement: {str(e)}")
        return "", "0"

def decrypt(text, shift):
    """Déchiffre un texte chiffré avec une clé donnée."""
    if not isinstance(text, str) or not isinstance(shift, (str, int)):
        return ""
    
    try:
        # Convertir shift en entier si c'est une chaîne
        shift = int(shift)
        # Décoder le base64 et déchiffrer
        encrypted_bytes = b64decode(text.encode('utf-8'))
        decrypted_bytes = bytes([(b - shift) % 256 for b in encrypted_bytes])
        return decrypted_bytes.decode('utf-8')
    except Exception as e:
        print(f"Erreur de déchiffrement: {str(e)}")
        return ""


#CHIFFREMENT  VIGENERE
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
'''