import subprocess
import sys
import time
import os
import signal
import atexit

def start_servers():
    # Démarrer le serveur de chat
    chat_server = subprocess.Popen([sys.executable, 'server.py'])
    print("Serveur de chat démarré...")
    
    # Attendre un peu pour s'assurer que le serveur de chat est prêt
    time.sleep(2)
    
    # Démarrer l'application web
    web_app = subprocess.Popen([sys.executable, 'app.py'])
    print("Application web démarrée...")
    
    # Fonction pour arrêter proprement les serveurs
    def cleanup():
        print("\nArrêt des serveurs...")
        chat_server.terminate()
        web_app.terminate()
        chat_server.wait()
        web_app.wait()
        print("Serveurs arrêtés.")
    
    # Enregistrer la fonction de nettoyage pour qu'elle soit appelée à la sortie
    atexit.register(cleanup)
    
    # Gérer l'arrêt propre avec Ctrl+C
    def signal_handler(signum, frame):
        print("\nSignal d'arrêt reçu...")
        sys.exit(0)
    
    signal.signal(signal.SIGINT, signal_handler)
    
    try:
        # Maintenir le script en cours d'exécution
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        pass

if __name__ == '__main__':
    print("Démarrage des serveurs...")
    start_servers()
