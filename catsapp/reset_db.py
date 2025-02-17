from database.db import DB_CONFIG
import mysql.connector

def reset_db():
    connection = mysql.connector.connect(**DB_CONFIG)
    try:
        cursor = connection.cursor()
        cursor.execute("DROP DATABASE IF EXISTS catsapp")
        print("Base de données supprimée avec succès!")
    except Exception as e:
        print(f"Erreur: {e}")
    finally:
        cursor.close()
        connection.close()

if __name__ == '__main__':
    reset_db()
