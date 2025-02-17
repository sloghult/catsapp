from app import app
from database.db import init_db

if __name__ == '__main__':
    # Initialisation de la base de données
    with app.app_context():
        init_db()
    
    # Configuration du serveur Flask
    app.config['SECRET_KEY'] = 'votre_cle_secrete_ici'  # À changer en production
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    
    # Lancement du serveur
    app.run(
        host='0.0.0.0',  # Permet l'accès depuis d'autres machines sur le réseau
        port=5000,       # Port par défaut
        debug=True       # Mode debug pour le développement (à désactiver en production)
    )
