import mysql.connector
from mysql.connector import Error
import os
import logging

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
            
            # Créer la base de données si elle n'existe pas
            cursor.execute("CREATE DATABASE IF NOT EXISTS catsapp")
            logger.debug("Base de données catsapp créée ou déjà existante")
            
            # Utiliser la base de données
            cursor.execute("USE catsapp")
            logger.debug("Utilisation de la base de données catsapp")
            
            # Sauvegarder la structure actuelle de la table si elle existe
            cursor.execute("SHOW CREATE TABLE users")
            old_table_structure = cursor.fetchone()
            logger.debug("Structure actuelle de la table récupérée")
            
            # Renommer l'ancienne table si elle existe
            cursor.execute("DROP TABLE IF EXISTS users_old")
            cursor.execute("RENAME TABLE users TO users_old")
            logger.debug("Ancienne table renommée")
            
            # Créer la nouvelle table avec la nouvelle structure
            cursor.execute("""
            CREATE TABLE users (
                id INT AUTO_INCREMENT PRIMARY KEY,
                username VARCHAR(50) NOT NULL UNIQUE,
                password VARCHAR(255) NOT NULL,
                nom VARCHAR(100) NOT NULL,
                prenom VARCHAR(100) NOT NULL,
                role ENUM('user', 'admin') NOT NULL DEFAULT 'user',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
            """)
            logger.debug("Nouvelle table créée avec la structure mise à jour")
            
            # Copier les données de l'ancienne table vers la nouvelle
            try:
                cursor.execute("""
                INSERT INTO users (id, username, password, nom, prenom, created_at)
                SELECT id, username, password, nom, prenom, created_at
                FROM users_old
                """)
                logger.debug("Données migrées de l'ancienne table vers la nouvelle")
            except Error as e:
                logger.error(f"Erreur lors de la migration des données: {e}")
            
            # Supprimer l'ancienne table
            cursor.execute("DROP TABLE IF EXISTS users_old")
            logger.debug("Ancienne table supprimée")
            
            connection.commit()
            logger.debug("Base de données initialisée avec succès!")

    except Error as e:
        if "Table 'catsapp.users' doesn't exist" in str(e):
            # Si la table n'existe pas, créer la nouvelle structure
            cursor.execute("""
            CREATE TABLE users (
                id INT AUTO_INCREMENT PRIMARY KEY,
                username VARCHAR(50) NOT NULL UNIQUE,
                password VARCHAR(255) NOT NULL,
                nom VARCHAR(100) NOT NULL,
                prenom VARCHAR(100) NOT NULL,
                role ENUM('user', 'admin') NOT NULL DEFAULT 'user',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
            """)
            connection.commit()
            logger.debug("Nouvelle table créée avec succès!")
        else:
            logger.error(f"Erreur lors de l'initialisation de la base de données: {e}")
            if connection:
                connection.rollback()
    finally:
        if connection and connection.is_connected():
            cursor.close()
            connection.close()
            logger.debug("Connexion MySQL fermée")
