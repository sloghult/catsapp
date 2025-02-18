# CHIFFREMENT CESAR


def encrypt(text, shift=3):
    """Chiffre un texte en utilisant le chiffrement de César."""
    encrypted = ""
    for char in text:
        if char.isalpha():
            ascii_offset = ord('A') if char.isupper() else ord('a')
            encrypted += chr((ord(char) - ascii_offset + shift) % 26 + ascii_offset)
        else:
            encrypted += char
    return encrypted

def decrypt(text, shift=3):
    """Déchiffre un texte chiffré avec le chiffrement de César."""
    return encrypt(text, -shift)  # Le déchiffrement est un chiffrement avec un décalage négatif


#CHIFFREMENT  VIGENERE
'''
def encrypt(text, key="CATSAPP"):
    """
    Chiffre un texte en utilisant le chiffrement de Vigenère.
    
    Args:
        text (str): Le texte à chiffrer
        key (str): La clé de chiffrement (par défaut "CATSAPP")
    
    Returns:
        str: Le texte chiffré
    """
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
            # Conserve les caractères non-alphabétiques tels quels
            encrypted += char
            
    return encrypted

def decrypt(text, key="CATSAPP"):
    """
    Déchiffre un texte chiffré avec le chiffrement de Vigenère.
    
    Args:
        text (str): Le texte à déchiffrer
        key (str): La clé de chiffrement (par défaut "CATSAPP")
    
    Returns:
        str: Le texte déchiffré
    """
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
            # Conserve les caractères non-alphabétiques tels quels
            decrypted += char
            
    return decrypted
'''