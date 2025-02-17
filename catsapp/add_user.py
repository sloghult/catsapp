from database.db import DB_CONFIG
import mysql.connector
from werkzeug.security import generate_password_hash

def add_user():
    connection = mysql.connector.connect(**DB_CONFIG, database='catsapp')
    try:
        cursor = connection.cursor()
        
        # Générer le hash du mot de passe
        hashed_password = generate_password_hash('123')
        
        # Insérer le nouvel utilisateur
        sql = "INSERT INTO users (username, password, nom, prenom) VALUES (%s, %s, %s, %s)"
        values = ('pierre', hashed_password, 'Dupont', 'Pierre')
        
        cursor.execute(sql, values)
        connection.commit()
        print("Utilisateur Pierre ajouté avec succès!")
        
    except Exception as e:
        print(f"Erreur: {e}")
    finally:
        cursor.close()
        connection.close()

if __name__ == '__main__':
    add_user()
