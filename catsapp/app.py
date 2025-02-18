from flask import Flask, render_template, request, flash, redirect, url_for, session, jsonify
from database.db import init_db, DB_CONFIG
import mysql.connector
from werkzeug.security import generate_password_hash, check_password_hash
import logging
import socket
import json
import threading
from functools import wraps
from datetime import datetime
from encryption import caesar_encrypt, caesar_decrypt

# Configuration du logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

app = Flask(__name__)
app.secret_key = 'votre_cle_secrete_ici'  # À changer en production

# Configuration du socket client
socket_clients = {}  # {user_id: socket}
socket_lock = threading.Lock()

def get_socket_client(user_id):
    with socket_lock:
        if user_id not in socket_clients:
            try:
                client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                client.connect(('127.0.0.1', 5001))  # Mise à jour du port à 5001
                
                # Authentification
                auth_data = {
                    'user_id': user_id
                }
                client.send(json.dumps(auth_data).encode('utf-8'))
                
                # Démarrer un thread pour écouter les messages
                def listen_for_messages(sock, uid):
                    while True:
                        try:
                            data = sock.recv(4096).decode('utf-8')
                            if not data:
                                break
                            
                            message = json.loads(data)
                            logger.debug(f"Message reçu pour l'utilisateur {uid}: {message}")
                            
                            # Traiter le message selon son type
                            if message['type'] == 'new_message':
                                # Stocker le message dans la base de données si nécessaire
                                pass
                            
                        except Exception as e:
                            logger.error(f"Erreur lors de la réception du message: {e}")
                            break
                    
                    # Si on sort de la boucle, fermer la connexion
                    with socket_lock:
                        if uid in socket_clients:
                            del socket_clients[uid]
                            try:
                                sock.close()
                            except:
                                pass
                
                # Démarrer le thread d'écoute
                listener_thread = threading.Thread(target=listen_for_messages, args=(client, user_id))
                listener_thread.daemon = True
                listener_thread.start()
                
                socket_clients[user_id] = client
                logger.debug(f"Nouvelle connexion socket créée pour l'utilisateur {user_id}")
            
            except Exception as e:
                logger.error(f"Erreur lors de la création du socket: {e}")
                return None
        
        return socket_clients.get(user_id)

def get_db_connection():
    try:
        config = DB_CONFIG.copy()
        config['database'] = 'catsapp'
        connection = mysql.connector.connect(**config)
        logger.debug("Connexion à la base de données réussie")
        return connection
    except Exception as e:
        logger.error(f"Erreur de connexion à la base de données: {e}")
        raise

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Veuillez vous connecter pour accéder à cette page')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            logger.debug(f"Pas d'user_id dans la session: {session}")
            flash('Veuillez vous connecter d\'abord.', 'error')
            return redirect(url_for('login'))
        
        # Vérifier si l'utilisateur est admin
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        cursor.execute('SELECT * FROM users WHERE id = %s', (session['user_id'],))
        user = cursor.fetchone()
        cursor.close()
        conn.close()
        
        logger.debug(f"User trouvé dans la DB: {user}")
        logger.debug(f"Session actuelle: {session}")
        
        if not user or user['username'].lower() != 'admin':
            logger.debug(f"Utilisateur non admin: username={user['username'] if user else 'None'}")
            flash('Accès non autorisé.', 'error')
            return redirect(url_for('index'))
        return f(*args, **kwargs)
    return decorated_function

@app.route('/')
def index():
    if 'user_id' in session:
        return redirect(url_for('chat'))
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        try:
            conn = get_db_connection()
            cursor = conn.cursor(dictionary=True)
            
            cursor.execute('SELECT * FROM users WHERE username = %s', (username,))
            user = cursor.fetchone()
            
            if user and check_password_hash(user['password'], password):
                session['user_id'] = user['id']
                session['username'] = user['username']
                session['nom'] = user['nom']
                session['prenom'] = user['prenom']
                
                # Si c'est l'admin, rediriger vers le dashboard admin
                if user['username'] == 'admin':
                    return redirect(url_for('admin_dashboard'))
                    
                # Créer une connexion socket pour l'utilisateur
                get_socket_client(user['id'])
                
                return redirect(url_for('chat'))
            else:
                flash('Nom d\'utilisateur ou mot de passe incorrect.', 'error')
        except Exception as e:
            logger.error(f"Erreur lors de la connexion: {e}")
            flash('Une erreur est survenue lors de la connexion.', 'error')
        finally:
            cursor.close()
            conn.close()
    
    return render_template('/index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        nom = request.form.get('nom')
        prenom = request.form.get('prenom')
        
        try:
            hashed_password = generate_password_hash(password)
            
            conn = get_db_connection()
            cursor = conn.cursor()
            
            cursor.execute(
                'INSERT INTO users (username, password, nom, prenom) VALUES (%s, %s, %s, %s)',
                (username, hashed_password, nom, prenom)
            )
            conn.commit()
            flash('Inscription réussie ! Vous pouvez maintenant vous connecter.')
            return redirect(url_for('login'))
        except mysql.connector.IntegrityError:
            flash('Ce nom d\'utilisateur existe déjà')
            return redirect(url_for('register'))
        except Exception as e:
            logger.error(f"Erreur lors de l'inscription: {e}")
            flash('Une erreur est survenue lors de l\'inscription')
            return redirect(url_for('register'))
        finally:
            cursor.close()
            conn.close()
    
    return render_template('register.html')

@app.route('/chat')
@app.route('/chat/<int:contact_id>')
@login_required
def chat(contact_id=None):
    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        
        # Récupérer tous les contacts (sauf l'utilisateur actuel)
        cursor.execute("""
            SELECT id, username 
            FROM users 
            WHERE id != %s
        """, (session['user_id'],))
        contacts = cursor.fetchall()
        
        # Récupérer les derniers messages pour chaque contact
        for contact in contacts:
            cursor.execute("""
                SELECT content 
                FROM messages 
                WHERE (sender_id = %s AND receiver_id = %s) 
                   OR (sender_id = %s AND receiver_id = %s) 
                ORDER BY created_at DESC 
                LIMIT 1
            """, (session['user_id'], contact['id'], contact['id'], session['user_id']))
            last_message = cursor.fetchone()
            if last_message:
                # Déchiffrer le dernier message pour l'aperçu
                contact['last_message'] = caesar_decrypt(last_message['content'])
            else:
                contact['last_message'] = None

        # Si un contact est sélectionné, récupérer les messages
        current_contact = None
        messages = []
        if contact_id:
            # Récupérer les informations du contact
            cursor.execute("SELECT id, username FROM users WHERE id = %s", (contact_id,))
            current_contact = cursor.fetchone()
            
            if current_contact:
                # Récupérer les messages
                cursor.execute("""
                    SELECT sender_id, content, created_at 
                    FROM messages 
                    WHERE (sender_id = %s AND receiver_id = %s) 
                       OR (sender_id = %s AND receiver_id = %s) 
                    ORDER BY created_at
                """, (session['user_id'], contact_id, contact_id, session['user_id']))
                encrypted_messages = cursor.fetchall()
                
                # Déchiffrer les messages
                messages = []
                for msg in encrypted_messages:
                    decrypted_msg = msg.copy()
                    decrypted_msg['content'] = caesar_decrypt(msg['content'])
                    messages.append(decrypted_msg)
        
        return render_template('user/chat.html', 
                             contacts=contacts,
                             current_contact=current_contact,
                             messages=messages)
                             
    except Exception as e:
        logger.error(f"Erreur lors du chargement du chat: {e}")
        flash('Une erreur est survenue')
        return redirect(url_for('index'))
    finally:
        cursor.close()
        conn.close()

@app.route('/send_message', methods=['POST'])
@login_required
def send_message():
    try:
        data = request.get_json()
        receiver_id = data.get('receiver_id')
        content = data.get('content')
        
        if not receiver_id or not content:
            return jsonify({'success': False, 'error': 'Données manquantes'})
        
        # Obtenir le socket client
        client_socket = get_socket_client(session['user_id'])
        if not client_socket:
            return jsonify({'success': False, 'error': 'Impossible de se connecter au serveur de chat'})
        
        # Envoyer le message via le socket
        message_data = {
            'type': 'message',
            'sender_id': session['user_id'],
            'receiver_id': int(receiver_id),
            'content': content
        }
        
        try:
            client_socket.send(json.dumps(message_data).encode('utf-8'))
            return jsonify({'success': True})
        except Exception as e:
            logger.error(f"Erreur lors de l'envoi du message: {e}")
            # Supprimer le socket en cas d'erreur pour forcer une nouvelle connexion
            with socket_lock:
                if session['user_id'] in socket_clients:
                    del socket_clients[session['user_id']]
            return jsonify({'success': False, 'error': 'Erreur lors de l\'envoi du message'})
        
    except Exception as e:
        logger.error(f"Erreur lors de l'envoi du message: {e}")
        return jsonify({'success': False, 'error': str(e)})

@app.route('/typing', methods=['POST'])
@login_required
def typing():
    try:
        data = request.get_json()
        receiver_id = data.get('receiver_id')
        
        if not receiver_id:
            return jsonify({'success': False, 'error': 'ID du destinataire manquant'})
        
        # Obtenir le socket client
        client_socket = get_socket_client(session['user_id'])
        if not client_socket:
            return jsonify({'success': False, 'error': 'Impossible de se connecter au serveur de chat'})
        
        # Envoyer l'événement de frappe
        typing_data = {
            'type': 'typing',
            'sender_id': session['user_id'],
            'receiver_id': int(receiver_id)
        }
        
        try:
            client_socket.send(json.dumps(typing_data).encode('utf-8'))
            return jsonify({'success': True})
        except Exception as e:
            logger.error(f"Erreur lors de l'envoi de l'événement de frappe: {e}")
            return jsonify({'success': False, 'error': 'Erreur lors de l\'envoi de l\'événement'})
        
    except Exception as e:
        logger.error(f"Erreur lors de l'envoi de l'événement de frappe: {e}")
        return jsonify({'success': False, 'error': str(e)})

@app.route('/admin')
@login_required
@admin_required
def admin_dashboard():
    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        
        # Récupérer tous les utilisateurs sauf l'admin
        cursor.execute("""
            SELECT id, username, nom, prenom, created_at 
            FROM users 
            WHERE id != %s
            ORDER BY created_at DESC
        """, (session['user_id'],))
        
        users = cursor.fetchall()
        
        return render_template('admin/admin_dashboard.html', users=users)
    except Exception as e:
        logger.error(f"Erreur dans le dashboard admin: {e}")
        flash('Une erreur est survenue', 'error')
        return redirect(url_for('index'))
    finally:
        cursor.close()
        conn.close()

@app.route('/admin/add-user', methods=['POST'])
@login_required
@admin_required
def add_user():
    try:
        data = request.get_json()
        username = data.get('username')
        password = data.get('password')
        nom = data.get('nom')
        prenom = data.get('prenom')
        
        if not all([username, password, nom, prenom]):
            return jsonify({'success': False, 'error': 'Tous les champs sont requis'})
        
        # Vérifier si l'utilisateur existe déjà
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        
        cursor.execute('SELECT id FROM users WHERE username = %s', (username,))
        if cursor.fetchone():
            return jsonify({'success': False, 'error': 'Ce nom d\'utilisateur existe déjà'})
        
        # Créer le nouvel utilisateur
        hashed_password = generate_password_hash(password)
        cursor.execute(
            'INSERT INTO users (username, password, nom, prenom) VALUES (%s, %s, %s, %s)',
            (username, hashed_password, nom, prenom)
        )
        conn.commit()
        
        cursor.close()
        conn.close()
        
        return jsonify({'success': True})
    except Exception as e:
        logger.error(f"Erreur lors de l'ajout de l'utilisateur: {e}")
        return jsonify({'success': False, 'error': str(e)})

@app.route('/admin/reset-password/<int:user_id>', methods=['POST'])
@login_required
@admin_required
def reset_password(user_id):
    try:
        # Générer un nouveau mot de passe par défaut
        default_password = '123'
        hashed_password = generate_password_hash(default_password)
        
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Vérifier que l'utilisateur existe
        cursor.execute('SELECT username FROM users WHERE id = %s', (user_id,))
        user = cursor.fetchone()
        
        if not user:
            return jsonify({'success': False, 'error': 'Utilisateur non trouvé'})
        
        # Mettre à jour le mot de passe
        cursor.execute('UPDATE users SET password = %s WHERE id = %s', 
                      (hashed_password, user_id))
        conn.commit()
        
        cursor.close()
        conn.close()
        
        return jsonify({'success': True})
    except Exception as e:
        logger.error(f"Erreur lors de la réinitialisation du mot de passe: {e}")
        return jsonify({'success': False, 'error': str(e)})

@app.route('/admin/delete-user/<int:user_id>', methods=['POST'])
@login_required
@admin_required
def delete_user(user_id):
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Vérifier que l'utilisateur existe et n'est pas admin
        cursor.execute('SELECT username FROM users WHERE id = %s', (user_id,))
        user = cursor.fetchone()
        
        if not user:
            return jsonify({'success': False, 'error': 'Utilisateur non trouvé'})
        
        if user[0] == 'admin':
            return jsonify({'success': False, 'error': 'Impossible de supprimer l\'administrateur'})
        
        # Supprimer les messages de l'utilisateur
        cursor.execute('DELETE FROM messages WHERE sender_id = %s OR receiver_id = %s', 
                      (user_id, user_id))
        
        # Supprimer l'utilisateur
        cursor.execute('DELETE FROM users WHERE id = %s', (user_id,))
        conn.commit()
        
        cursor.close()
        conn.close()
        
        return jsonify({'success': True})
    except Exception as e:
        logger.error(f"Erreur lors de la suppression de l'utilisateur: {e}")
        return jsonify({'success': False, 'error': str(e)})

@app.route('/logout')
def logout():
    # Fermer la connexion socket si elle existe
    with socket_lock:
        if 'user_id' in session and session['user_id'] in socket_clients:
            try:
                socket_clients[session['user_id']].close()
            except:
                pass
            del socket_clients[session['user_id']]
    
    session.clear()
    return redirect(url_for('login'))

@app.route('/check_admin_status')
@login_required
def check_admin_status():
    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        cursor.execute('SELECT * FROM users WHERE id = %s', (session['user_id'],))
        user = cursor.fetchone()
        cursor.close()
        conn.close()
        
        return jsonify({
            'is_logged_in': True,
            'session_user_id': session.get('user_id'),
            'session_username': session.get('username'),
            'db_user': user
        })
    except Exception as e:
        return jsonify({
            'error': str(e),
            'session': dict(session)
        })

if __name__ == '__main__':
    # Initialiser la base de données au démarrage
    init_db()
    app.run(debug=True)
