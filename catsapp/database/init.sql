-- Création de la base de données si elle n'existe pas
CREATE DATABASE IF NOT EXISTS catsapp;
USE catsapp;

-- Table des utilisateurs
CREATE TABLE IF NOT EXISTS users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(50) UNIQUE NOT NULL,
    password VARCHAR(255) NOT NULL,
    nom VARCHAR(50) NOT NULL,
    prenom VARCHAR(50) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Table des messages
CREATE TABLE IF NOT EXISTS messages (
    id INT AUTO_INCREMENT PRIMARY KEY,
    sender_id INT NOT NULL,
    receiver_id INT NOT NULL,
    content TEXT NOT NULL,
    is_read BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (sender_id) REFERENCES users(id),
    FOREIGN KEY (receiver_id) REFERENCES users(id)
);

-- Insertion des utilisateurs de test
-- Note: Les mots de passe sont hachés avec Werkzeug (équivalent à '123')
INSERT INTO users (username, password, nom, prenom) VALUES
('admin', 'pbkdf2:sha256:600000$8qPYhxKJxQi1Sirx$6e0a85d6f94aa66667e2f1c10e5e4d4a48a9d3c50c1b3e2352c4e9671b6b89e9', 'Admin', 'Admin')
ON DUPLICATE KEY UPDATE username=username;
