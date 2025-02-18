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
