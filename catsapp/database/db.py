import mysql.connector
from mysql.connector import Error
import os
import logging
from werkzeug.security import generate_password_hash
from encryption import generate_rsa_keys  # Importer la fonction de génération des clés RSA

# Configuration du logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

# Configuration de la base de données
DB_CONFIG = {
    'host': 'localhost',
    'user': 'root',
    'password': 'rootpassword',  # Mot de passe MySQL correct
    'raise_on_warnings': True
}

def init_db():
    connection = None
    try:
        # Établir la connexion sans spécifier de base de données
        connection = mysql.connector.connect(**DB_CONFIG)
        logger.debug("Connexion au serveur MySQL réussie")

        if connection.is_connected():
            cursor = connection.cursor()

            # Lire et exécuter le script SQL d'initialisation
            script_path = os.path.join(os.path.dirname(__file__), 'init.sql')
            with open(script_path, 'r', encoding='utf-8') as sql_file:
                sql_script = sql_file.read()

            # Exécuter chaque commande SQL séparément
            for command in sql_script.split(';'):
                if command.strip():
                    cursor.execute(command)

            # Ajouter les utilisateurs par défaut avec les clés RSA
            default_users = [
                ('anna', 'Dubois', 'Anna'),
                ('jean', 'Martin', 'Jean'),
                ('admin', 'Admin', 'Admin'),
                ('pierre', 'Dupont', 'Pierre')
            ]

            for username, nom, prenom in default_users:
                try:
                    hashed_password = generate_password_hash('123')
                    private_key_pem, public_key_pem = generate_rsa_keys()  # Générer les clés RSA

                    cursor.execute("""
                    INSERT INTO users (username, password, nom, prenom, public_key, private_key)
                    VALUES (%s, %s, %s, %s, %s, %s)
                    ON DUPLICATE KEY UPDATE
                    password = VALUES(password),
                    nom = VALUES(nom),
                    prenom = VALUES(prenom),
                    public_key = VALUES(public_key),
                    private_key = VALUES(private_key)
                    """, (username, hashed_password, nom, prenom, public_key_pem.decode('utf-8'), private_key_pem.decode('utf-8')))

                except Error as e:
                    logger.error(f"Erreur lors de l'ajout de l'utilisateur {username}: {e}")

            connection.commit()
            logger.debug("Base de données initialisée avec succès")

    except Error as e:
        logger.error(f"Erreur lors de l'initialisation de la base de données: {e}")
    finally:
        if connection and connection.is_connected():
            cursor.close()
            connection.close()
            logger.debug("Connexion à la base de données fermée")
