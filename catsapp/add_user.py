from database.db import DB_CONFIG, user_exists
import mysql.connector
from werkzeug.security import generate_password_hash

def add_user(username, password, nom, prenom):
    connection = mysql.connector.connect(**DB_CONFIG, database='catsapp')
    try:
        cursor = connection.cursor()

        # Vérifier si l'utilisateur existe déjà
        if user_exists(username):
            print("Ce nom d'utilisateur est déjà pris. Veuillez en choisir un autre.")
            return False

        # Générer le hash du mot de passe
        hashed_password = generate_password_hash(password)

        # Insérer le nouvel utilisateur
        sql = "INSERT INTO users (username, password, nom, prenom) VALUES (%s, %s, %s, %s)"
        cursor.execute(sql, (username, hashed_password, nom, prenom))
        connection.commit()
        print("Utilisateur ajouté avec succès.")
        return True
    except mysql.connector.Error as err:
        print(f"Erreur: {err}")
        return False
    finally:
        cursor.close()
        connection.close()

if __name__ == '__main__':
    add_user()
