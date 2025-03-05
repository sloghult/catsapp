import socket
import threading
import json
import mysql.connector
from database.db import DB_CONFIG
import logging
from datetime import datetime
import queue
from encryption import encrypt_message , decrypt_message

# Configuration du logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

def caesar_encrypt(text):
    result = ""
    for char in text:
        if char.isalpha():
            ascii_offset = 65 if char.isupper() else 97
            result += chr((ord(char) - ascii_offset + 3) % 26 + ascii_offset)
        else:
            result += char
    return result

class ChatServer:
    def __init__(self, host='127.0.0.1', port=5001):
        self.host = host
        self.port = port
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.clients = {}  # {user_id: {'socket': socket, 'queue': Queue}}
        self.lock = threading.Lock()

    def get_db_connection(self):
        config = DB_CONFIG.copy()
        config['database'] = 'catsapp'
        return mysql.connector.connect(**config)

    def broadcast_message(self, message_data, exclude_user=None):
        with self.lock:
            for user_id, client_info in self.clients.items():
                if user_id != exclude_user:
                    try:
                        client_info['queue'].put(message_data)
                    except Exception as e:
                        logger.error(f"Erreur lors de l'envoi du message à {user_id}: {e}")

    def send_to_user(self, user_id, message_data):
        with self.lock:
            if user_id in self.clients:
                try:
                    self.clients[user_id]['queue'].put(message_data)
                    return True
                except Exception as e:
                    logger.error(f"Erreur lors de l'envoi du message à {user_id}: {e}")
            return False

    def handle_client_write(self, client_socket, user_id):
        while True:
            try:
                if user_id not in self.clients:
                    break
                message_data = self.clients[user_id]['queue'].get()
                try:
                    client_socket.send(json.dumps(message_data).encode('utf-8'))
                except Exception as e:
                    logger.error(f"Erreur d'écriture pour {user_id}: {e}")
                    break
            except queue.Empty:
                continue
            except Exception as e:
                logger.error(f"Erreur dans le thread d'écriture pour {user_id}: {e}")
                break

    def handle_client(self, client_socket, address):
        logger.info(f"Nouvelle connexion de {address}")
        user_id = None
        
        try:
            # Authentification
            auth_data = client_socket.recv(4096).decode('utf-8')
            auth_info = json.loads(auth_data)
            user_id = auth_info.get('user_id')
            
            if not user_id:
                client_socket.close()
                return

            # Initialiser la file d'attente des messages pour ce client
            message_queue = queue.Queue()
            
            with self.lock:
                # Fermer l'ancienne connexion si elle existe
                if user_id in self.clients:
                    try:
                        old_socket = self.clients[user_id]['socket']
                        old_socket.close()
                    except:
                        pass
                
                self.clients[user_id] = {
                    'socket': client_socket,
                    'queue': message_queue
                }

            # Démarrer le thread d'écriture
            write_thread = threading.Thread(target=self.handle_client_write, args=(client_socket, user_id))
            write_thread.daemon = True
            write_thread.start()

            # Envoyer un message de confirmation
            self.send_to_user(user_id, {
                'type': 'connection_success',
                'message': 'Connecté au serveur de chat'
            })

            logger.info(f"Utilisateur {user_id} authentifié")

            while True:
                try:
                    data = client_socket.recv(4096).decode('utf-8')
                    if not data:
                        break

                    message_data = json.loads(data)
                    message_type = message_data.get('type')
                    
                    if message_type == 'message':
                        # Sauvegarder le message dans la base de données
                        conn = self.get_db_connection()
                        cursor = conn.cursor()
                        
                        try:
                            # Chiffrer le message avant de le sauvegarder
                            encrypted_content = encrypt(message_data['content'])
                            
                            cursor.execute('''
                                INSERT INTO messages (sender_id, receiver_id, content, is_read)
                                VALUES (%s, %s, %s, FALSE)
                            ''', (message_data['sender_id'], message_data['receiver_id'], encrypted_content))
                            
                            conn.commit()
                            message_id = cursor.lastrowid
                            
                            # Préparer le message à envoyer (toujours chiffré)
                            response_message = {
                                'type': 'new_message',
                                'message_id': message_id,
                                'sender_id': message_data['sender_id'],
                                'content': encrypted_content,
                                'timestamp': datetime.now().isoformat()
                            }
                            
                            # Envoyer le message chiffré au destinataire
                            self.send_to_user(message_data['receiver_id'], response_message)
                            
                            # Envoyer une confirmation à l'expéditeur
                            self.send_to_user(message_data['sender_id'], {
                                'type': 'message_sent',
                                'message_id': message_id,
                                'timestamp': datetime.now().isoformat()
                            })
                            
                            logger.debug(f"Message chiffré envoyé et sauvegardé: {message_id}")
                        
                        except Exception as e:
                            logger.error(f"Erreur lors du traitement du message: {e}")
                            self.send_to_user(message_data['sender_id'], {
                                'type': 'error',
                                'message': 'Erreur lors de l\'envoi du message'
                            })
                        
                        finally:
                            cursor.close()
                            conn.close()
                    
                    elif message_type == 'typing':
                        # Informer le destinataire que l'expéditeur est en train d'écrire
                        typing_message = {
                            'type': 'typing',
                            'sender_id': message_data['sender_id']
                        }
                        self.send_to_user(message_data['receiver_id'], typing_message)

                except json.JSONDecodeError as e:
                    logger.error(f"Erreur de décodage JSON: {e}")
                    continue
                except Exception as e:
                    logger.error(f"Erreur avec le client {address}: {e}")
                    break

        except Exception as e:
            logger.error(f"Erreur avec le client {address}: {e}")
        finally:
            with self.lock:
                if user_id in self.clients:
                    del self.clients[user_id]
            client_socket.close()
            logger.info(f"Connexion fermée avec {address}")

    def start(self):
        self.server_socket.bind((self.host, self.port))
        self.server_socket.listen(5)
        logger.info(f"Serveur démarré sur {self.host}:{self.port}")

        try:
            while True:
                client_socket, address = self.server_socket.accept()
                client_thread = threading.Thread(target=self.handle_client, args=(client_socket, address))
                client_thread.daemon = True
                client_thread.start()
        except KeyboardInterrupt:
            logger.info("Arrêt du serveur...")
        finally:
            self.server_socket.close()

if __name__ == '__main__':
    server = ChatServer()
    server.start()
