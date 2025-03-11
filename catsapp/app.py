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
from encryption import generate_rsa_keys, encrypt_message, decrypt_message, generate_symmetric_key, encrypt_symmetric_key, decrypt_symmetric_key



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
        logger.info(f"Vérification de la session: {session}")
        if 'user_id' not in session:
            logger.error("Tentative d'accès sans session valide")
            if request.is_json:
                return jsonify({'success': False, 'error': 'Veuillez vous connecter'}), 401
            flash('Veuillez vous connecter pour accéder à cette page', 'error')
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
            private_key_pem, public_key_pem = generate_rsa_keys()
            logger.debug(f"Clé publique: {public_key_pem.decode('utf-8')}")
            logger.debug(f"Clé privée: {private_key_pem.decode('utf-8')}")

            conn = get_db_connection()
            cursor = conn.cursor()

            cursor.execute(
                'INSERT INTO users (username, password, nom, prenom, public_key, private_key) VALUES (%s, %s, %s, %s, %s, %s)',
                (username, hashed_password, nom, prenom, public_key_pem.decode('utf-8'), private_key_pem.decode('utf-8'))
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

        # Récupère les contacts de l'utilisateur et trie par date du dernier message
        cursor.execute("""
            SELECT users.id, users.username, contacts.contact_key,
                   (SELECT MAX(created_at) FROM messages
                    WHERE (sender_id = users.id AND receiver_id = %s)
                       OR (sender_id = %s AND receiver_id = users.id)) AS last_message_date,
                   (SELECT 1 FROM sessions WHERE user_id = users.id LIMIT 1) AS is_active
            FROM contacts
            JOIN users ON contacts.contact_id = users.id
            WHERE contacts.user_id = %s AND contacts.status = 'accepted'
            ORDER BY last_message_date IS NULL DESC, last_message_date DESC
        """, (session['user_id'], session['user_id'], session['user_id']))
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
                try:
                    symmetric_key = decrypt_symmetric_key(contact['contact_key'], session['private_key'].encode('utf-8'))
                    decrypted_message = decrypt_message(last_message['content'], symmetric_key)
                    contact['last_message'] = decrypted_message
                    logger.debug(f"Dernier message déchiffré: {contact['last_message']}")
                except Exception as e:
                    logger.error(f"Erreur lors du déchiffrement du dernier message: {e}")
                    contact['last_message'] = "Erreur de déchiffrement"
            else:
                contact['last_message'] = None

        # Si un contact est sélectionné, récupérer les messages
        current_contact = None
        messages = []
        if contact_id:
            # Vérifier que l'utilisateur sélectionné est bien un contact accepté
            cursor.execute("""
                SELECT users.id, users.username, contacts.contact_key
                FROM contacts
                JOIN users ON contacts.contact_id = users.id
                WHERE contacts.user_id = %s AND contacts.contact_id = %s AND contacts.status = 'accepted'
            """, (session['user_id'], contact_id))

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
                    # Déchiffrer le message
                    try:
                        symmetric_key = decrypt_symmetric_key(current_contact['contact_key'], session['private_key'].encode('utf-8'))
                        decrypted_content = decrypt_message(msg['content'], symmetric_key)
                        decrypted_msg['content'] = decrypted_content
                        logger.debug(f"Message déchiffré: {decrypted_msg['content']}")
                    except Exception as e:
                        logger.error(f"Erreur lors du déchiffrement du message: {e}")
                        decrypted_msg['content'] = "Erreur de déchiffrement"
                    messages.append(decrypted_msg)

        # Récupérer l'utilisateur connecté
        cursor.execute("SELECT id, username, private_key FROM users WHERE id = %s", (session['user_id'],))
        user = cursor.fetchone()
        session['private_key'] = user['private_key']

        # Passer l'utilisateur connecté et l'heure actuelle au template
        return render_template('user/chat.html',
                             user=user,
                             contacts=contacts,
                             current_contact=current_contact,
                             messages=messages,
                             current_time=datetime.now())

    except Exception as e:
        logger.error(f"Erreur lors du chargement du chat: {e}")
        flash('Une erreur est survenue')
        return redirect(url_for('index'))
    finally:
        cursor.close()
        conn.close()


@app.route('/contacts/add', methods=['POST'])
@login_required
def add_contact():
    data = request.get_json()
    contact_username = data.get('username')

    if not contact_username:
        return jsonify({"success": False, "message": "Nom d'utilisateur requis"}), 400

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    # Vérifier si l'utilisateur existe
    cursor.execute("SELECT id FROM users WHERE username = %s", (contact_username,))
    contact = cursor.fetchone()

    if not contact:
        return jsonify({"success": False, "message": "Utilisateur non trouvé"}), 404

    contact_id = contact['id']
    user_id = session['user_id']

    if user_id == contact_id:
        return jsonify({"success": False, "message": "Vous ne pouvez pas vous ajouter vous-même"}), 400

    # Vérifier si une relation existe déjà
    cursor.execute("""
        SELECT * FROM friend_requests
        WHERE sender_id = %s AND receiver_id = %s
    """, (user_id, contact_id))

    if cursor.fetchone():
        return jsonify({"success": False, "message": "Demande déjà envoyée"}), 400

    # Insérer la demande d'ami
    cursor.execute("INSERT INTO friend_requests (sender_id, receiver_id, status) VALUES (%s, %s, 'pending')",
                   (user_id, contact_id))

    conn.commit()
    cursor.close()
    conn.close()

    return jsonify({"success": True, "message": "Demande d'ami envoyée"}), 201


@app.route('/contacts/accept', methods=['POST'])
@login_required
def accept_contact():
    data = request.get_json()
    sender_id = data.get('sender_id')

    if not sender_id:
        return jsonify({"success": False, "message": "ID de l'expéditeur requis"}), 400

    user_id = session['user_id']

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    # Vérifier si une demande est en attente
    cursor.execute("""
        SELECT * FROM friend_requests WHERE sender_id = %s AND receiver_id = %s AND status = 'pending'
    """, (sender_id, user_id))

    pending_request = cursor.fetchone()

    if not pending_request:
        return jsonify({"success": False, "message": "Aucune demande en attente trouvée"}), 404

    # Générer une clé symétrique
    symmetric_key = generate_symmetric_key()

    # Récupérer les clés publiques des deux utilisateurs
    cursor.execute("SELECT public_key FROM users WHERE id = %s", (sender_id,))
    sender_public_key_result = cursor.fetchone()
    if not sender_public_key_result or not sender_public_key_result['public_key']:
        return jsonify({"success": False, "message": "Clé publique de l'expéditeur non trouvée"}), 500
    sender_public_key = sender_public_key_result['public_key']

    cursor.execute("SELECT public_key FROM users WHERE id = %s", (user_id,))
    receiver_public_key_result = cursor.fetchone()
    if not receiver_public_key_result or not receiver_public_key_result['public_key']:
        return jsonify({"success": False, "message": "Clé publique du receveur non trouvée"}), 500
    receiver_public_key = receiver_public_key_result['public_key']

    # Chiffrer la clé symétrique avec les clés publiques des deux utilisateurs
    try:
        encrypted_symmetric_key_for_sender = encrypt_symmetric_key(symmetric_key, sender_public_key.encode('utf-8'))
        encrypted_symmetric_key_for_receiver = encrypt_symmetric_key(symmetric_key, receiver_public_key.encode('utf-8'))
    except Exception as e:
        return jsonify({"success": False, "message": f"Erreur lors du chiffrement de la clé symétrique: {str(e)}"}), 500

    # Insérer les contacts avec la clé symétrique chiffrée pour les deux utilisateurs
    try:
        cursor.execute("INSERT INTO contacts (user_id, contact_id, status, contact_key) VALUES (%s, %s, 'accepted', %s)",
                       (sender_id, user_id, encrypted_symmetric_key_for_sender))

        cursor.execute("INSERT INTO contacts (user_id, contact_id, status, contact_key) VALUES (%s, %s, 'accepted', %s)",
                       (user_id, sender_id, encrypted_symmetric_key_for_receiver))
    except Exception as e:
        conn.rollback()
        return jsonify({"success": False, "message": f"Erreur lors de l'insertion des contacts: {str(e)}"}), 500

    # Supprimer la demande d'ami
    cursor.execute("DELETE FROM friend_requests WHERE sender_id = %s AND receiver_id = %s", (sender_id, user_id))

    conn.commit()
    cursor.close()
    conn.close()

    return jsonify({"success": True, "message": "Contact accepté"}), 200


@app.route('/contacts/list', methods=['GET'])
@login_required
def list_contacts():
    user_id = session['user_id']

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    cursor.execute("""
        SELECT users.id, users.username
        FROM contacts
        JOIN users ON contacts.contact_id = users.id
        WHERE contacts.user_id = %s AND contacts.status = 'accepted'
    """, (user_id,))

    contacts = cursor.fetchall()
    cursor.close()
    conn.close()

    return jsonify({"success": True, "contacts": contacts})


@app.route('/friend_requests', methods=['GET'])
@login_required
def get_friend_requests():
    user_id = session['user_id']

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    # Récupérer les demandes d'amis en attente
    cursor.execute("""
        SELECT users.id, users.username
        FROM friend_requests
        JOIN users ON friend_requests.sender_id = users.id
        WHERE friend_requests.receiver_id = %s AND friend_requests.status = 'pending'
    """, (user_id,))

    friend_requests = cursor.fetchall()
    cursor.close()
    conn.close()

    return jsonify({"success": True, "friend_requests": friend_requests})


@app.route('/set_active_status', methods=['POST'])
@login_required
def set_active_status():
    data = request.get_json()
    status = data.get('status')
    user_id = session.get('user_id')

    if user_id and status:
        conn = get_db_connection()
        cursor = conn.cursor()

        if status == 'active':
            # Mettre à jour l'entrée dans la table sessions
            cursor.execute("INSERT INTO sessions (user_id, last_active) VALUES (%s, NOW()) ON DUPLICATE KEY UPDATE last_active = NOW()", (user_id,))
        elif status == 'inactive':
            # Supprimer l'entrée de la table sessions
            cursor.execute("DELETE FROM sessions WHERE user_id = %s", (user_id,))

        conn.commit()
        cursor.close()
        conn.close()

    return jsonify({'success': True})

@app.route('/send_message', methods=['POST'])
@login_required
def send_message():
    logger.info("Début de la fonction send_message")
    logger.info(f"Session: {session}")

    conn = None
    cursor = None
    try:
        data = request.get_json()
        logger.info(f"Données reçues: {data}")

        if not data:
            logger.error("Données JSON invalides ou manquantes")
            return jsonify({'success': False, 'error': 'Données JSON invalides'}), 400

        contact_id = data.get('contact_id')
        message = data.get('message')

        if not contact_id or not message:
            logger.error("Contact ID ou message manquant")
            return jsonify({'success': False, 'error': 'Contact ID et message requis'}), 400

        logger.info(f"Message écrit: {message}")

        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True, buffered=True)

        # Vérifier si le contact existe et est accepté
        cursor.execute('''
            SELECT status, contact_key FROM contacts
            WHERE user_id = %s AND contact_id = %s
        ''', (session['user_id'], contact_id))

        contact = cursor.fetchone()

        if not contact:
            logger.error(f"Contact non trouvé: user_id={session['user_id']}, contact_id={contact_id}")
            return jsonify({'success': False, 'error': 'Contact non trouvé'}), 404

        if contact['status'] != 'accepted':
            logger.error(f"Contact non accepté: status={contact['status']}")
            return jsonify({'success': False, 'error': 'Contact non accepté'}), 403

        # Déchiffrer la clé symétrique avec ma clé privée
        private_key_pem = session['private_key'].encode('utf-8')
        try:
            symmetric_key = decrypt_symmetric_key(contact['contact_key'], private_key_pem)
            logger.info("Clé symétrique déchiffrée avec succès.")
        except Exception as e:
            logger.error(f"Erreur lors du déchiffrement de la clé symétrique: {e}")
            return jsonify({'success': False, 'error': 'Erreur lors du déchiffrement de la clé symétrique'}), 500

        # Chiffrer le message avec la clé symétrique
        try:
            encrypted_message = encrypt_message(message, symmetric_key)
            logger.info("Message chiffré avec succès.")
        except Exception as e:
            logger.error(f"Erreur lors du chiffrement du message: {e}")
            return jsonify({'success': False, 'error': 'Erreur lors du chiffrement du message'}), 500

        # Insérer le message chiffré dans la base de données
        try:
            cursor.execute('''
                INSERT INTO messages (sender_id, receiver_id, content, created_at)
                VALUES (%s, %s, %s, NOW())
            ''', (session['user_id'], contact_id, encrypted_message))
            conn.commit()
            logger.info("Message inséré dans la base de données avec succès.")
        except Exception as e:
            conn.rollback()
            logger.error(f"Erreur lors de l'insertion du message dans la base de données: {e}")
            return jsonify({'success': False, 'error': 'Erreur lors de l\'insertion du message dans la base de données'}), 500

        return jsonify({'success': True})

    except Exception as e:
        logger.error(f"Erreur lors de l'envoi du message: {str(e)}")
        if conn:
            conn.rollback()
        return jsonify({'success': False, 'error': str(e)}), 500

    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()


@app.route('/contacts/pending', methods=['GET'])
@login_required
def pending_contacts():
    user_id = session['user_id']

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    cursor.execute("""
        SELECT users.id, users.username
        FROM contacts
        JOIN users ON contacts.user_id = users.id
        WHERE contacts.contact_id = %s AND contacts.status = 'pending'
    """, (user_id,))

    contacts = cursor.fetchall()
    cursor.close()
    conn.close()

    return jsonify({"success": True, "contacts": contacts})

@app.route('/contacts/block', methods=['POST'])
@login_required
def block_contact():
    data = request.get_json()
    contact_id = data.get('contact_id')

    if not contact_id:
        return jsonify({"success": False, "message": "ID du contact requis"}), 400

    user_id = session['user_id']

    conn = get_db_connection()
    cursor = conn.cursor()

    # Vérifier si une demande existe
    cursor.execute("""
        SELECT * FROM contacts WHERE user_id = %s AND contact_id = %s
    """, (contact_id, user_id))

    if not cursor.fetchone():
        return jsonify({"success": False, "message": "Aucune demande trouvée"}), 404

    # Mettre à jour le statut à "blocked"
    cursor.execute("""
        UPDATE contacts SET status = 'blocked'
        WHERE user_id = %s AND contact_id = %s
    """, (contact_id, user_id))
    conn.commit()

    cursor.close()
    conn.close()

    return jsonify({"success": True, "message": "Contact bloqué"}), 200

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


@app.route('/get_new_messages/<int:contact_id>', methods=['GET'])
@login_required
def get_new_messages(contact_id):
    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)

        # Récupérer les nouveaux messages
        cursor.execute("""
            SELECT sender_id, content, created_at
            FROM messages
            WHERE (sender_id = %s AND receiver_id = %s)
               OR (sender_id = %s AND receiver_id = %s)
            ORDER BY created_at DESC
            LIMIT 10
        """, (session['user_id'], contact_id, contact_id, session['user_id']))
        encrypted_messages = cursor.fetchall()

        # Déchiffrer les messages
        messages = []
        for msg in encrypted_messages:
            decrypted_msg = msg.copy()
            # Déchiffrer le message
            try:
                symmetric_key = decrypt_symmetric_key(current_contact['contact_key'], session['private_key'].encode('utf-8'))
                decrypted_content = decrypt_message(msg['content'], symmetric_key)
                decrypted_msg['content'] = decrypted_content
                logger.debug(f"Message déchiffré: {decrypted_msg['content']}")
            except Exception as e:
                logger.error(f"Erreur lors du déchiffrement du message: {e}")
                decrypted_msg['content'] = "Erreur de déchiffrement"
            messages.append(decrypted_msg)

        return jsonify(messages)

    except Exception as e:
        logger.error(f"Erreur lors de la récupération des nouveaux messages: {e}")
        return jsonify([]), 500
    finally:
        cursor.close()
        conn.close()


@app.route('/settings', methods=['GET'])
@login_required
def settings():
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT id, username, nom, prenom FROM users WHERE id = %s", (session['user_id'],))
    user = cursor.fetchone()
    cursor.close()
    conn.close()
    return render_template('settings.html', user=user)

@app.route('/update_settings', methods=['POST'])
@login_required
def update_settings():
    try:
        nom = request.form.get('nom')
        prenom = request.form.get('prenom')
        username = request.form.get('username')
        password = request.form.get('password')
        profile_picture = request.files.get('profilePicture')

        conn = get_db_connection()
        cursor = conn.cursor()

        if profile_picture:
            # Enregistrer la photo de profil (vous pouvez ajouter le code pour enregistrer l'image ici)
            pass

        if password:
            hashed_password = generate_password_hash(password)
            cursor.execute('UPDATE users SET password = %s WHERE id = %s', (hashed_password, session['user_id']))

        cursor.execute('UPDATE users SET nom = %s, prenom = %s, username = %s WHERE id = %s',
                       (nom, prenom, username, session['user_id']))
        conn.commit()
        cursor.close()
        conn.close()

        return jsonify({'success': True})
    except Exception as e:
        logger.error(f"Erreur lors de la mise à jour des paramètres: {e}")
        return jsonify({'success': False})

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
        private_key_pem, public_key_pem = generate_rsa_keys()
        cursor.execute(
            'INSERT INTO users (username, password, nom, prenom, public_key, private_key) VALUES (%s, %s, %s, %s, %s, %s)',
            (username, hashed_password, nom, prenom, public_key_pem.decode('utf-8'), private_key_pem.decode('utf-8'))
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
