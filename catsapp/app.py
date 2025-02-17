from flask import Flask, render_template, request, flash, redirect, url_for, session, jsonify
from database.db import init_db, DB_CONFIG
import mysql.connector
from werkzeug.security import generate_password_hash, check_password_hash
import logging
from functools import wraps

# Configuration du logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

app = Flask(__name__)
app.secret_key = 'votre_cle_secrete_ici'  # À changer en production

def get_db_connection():
    try:
        config = DB_CONFIG.copy()
        config['database'] = 'catsapp'  # Changement du nom de la base de données
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
            flash('Veuillez vous connecter pour accéder à cette page')
            return redirect(url_for('login'))
        if session.get('role') != 'admin':
            flash('Accès non autorisé')
            return redirect(url_for('user_dashboard'))
        return f(*args, **kwargs)
    return decorated_function

@app.route('/')
def index():
    if 'user_id' in session:
        if session.get('role') == 'admin':
            return redirect(url_for('admin_dashboard'))
        return redirect(url_for('chat'))
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        logger.debug(f"Tentative de connexion pour l'utilisateur: {username}")
        
        try:
            conn = get_db_connection()
            cursor = conn.cursor(dictionary=True)
            
            cursor.execute('SELECT * FROM users WHERE username = %s', (username,))
            user = cursor.fetchone()
            
            if user:
                logger.debug("Utilisateur trouvé dans la base de données")
                if check_password_hash(user['password'], password):
                    logger.debug("Mot de passe correct")
                    session['user_id'] = user['id']
                    session['username'] = user['username']
                    session['role'] = user['role']
                    session['nom'] = user['nom']
                    session['prenom'] = user['prenom']
                    logger.debug(f"Rôle de l'utilisateur: {user['role']}")
                    
                    if user['role'] == 'admin':
                        return redirect(url_for('admin_dashboard'))
                    return redirect(url_for('chat'))
                else:
                    logger.debug("Mot de passe incorrect")
            else:
                logger.debug("Utilisateur non trouvé")
                
            flash('Nom d\'utilisateur ou mot de passe incorrect')
            return redirect(url_for('login'))
        except Exception as e:
            logger.error(f"Erreur lors de la connexion: {e}")
            flash('Une erreur est survenue lors de la connexion')
            return redirect(url_for('login'))
        finally:
            cursor.close()
            conn.close()
    
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        nom = request.form.get('nom')
        prenom = request.form.get('prenom')
        role = request.form.get('role', 'user')
        
        logger.debug(f"Tentative d'inscription pour l'utilisateur: {username}")
        
        try:
            hashed_password = generate_password_hash(password)
            
            conn = get_db_connection()
            cursor = conn.cursor()
            
            cursor.execute(
                'INSERT INTO users (username, password, nom, prenom, role) VALUES (%s, %s, %s, %s, %s)',
                (username, hashed_password, nom, prenom, role)
            )
            conn.commit()
            logger.debug("Inscription réussie")
            flash('Inscription réussie ! Vous pouvez maintenant vous connecter.')
            return redirect(url_for('login'))
        except mysql.connector.IntegrityError:
            logger.error("Nom d'utilisateur déjà existant")
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

@app.route('/admin')
@admin_required
def admin_dashboard():
    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        
        # Récupérer les statistiques
        cursor.execute('SELECT COUNT(*) as total FROM users')
        total_users = cursor.fetchone()['total']
        
        # Vous pouvez ajouter d'autres statistiques ici
        stats = {
            'total_users': total_users,
            'messages_today': 0,  # À implémenter
            'new_users': 0  # À implémenter
        }
        
        return render_template('admin_dashboard.html', stats=stats)
    except Exception as e:
        logger.error(f"Erreur lors du chargement du tableau de bord admin: {e}")
        flash('Une erreur est survenue')
        return redirect(url_for('index'))
    finally:
        cursor.close()
        conn.close()

@app.route('/dashboard')
@login_required
def user_dashboard():
    return redirect(url_for('chat'))

@app.route('/admin/users')
@admin_required
def admin_users():
    return "Page de gestion des utilisateurs"

@app.route('/admin/messages')
@admin_required
def admin_messages():
    return "Page de gestion des messages"

@app.route('/admin/stats')
@admin_required
def admin_stats():
    return "Page des statistiques"

@app.route('/chat')
@app.route('/chat/<int:contact_id>')
@login_required
def chat(contact_id=None):
    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        
        # Récupérer la liste des contacts avec leurs derniers messages
        cursor.execute('''
            SELECT u.id, u.username,
                   (SELECT content FROM messages m 
                    WHERE (m.sender_id = u.id AND m.receiver_id = %s)
                       OR (m.sender_id = %s AND m.receiver_id = u.id)
                    ORDER BY created_at DESC LIMIT 1) as last_message,
                   (SELECT COUNT(*) FROM messages m 
                    WHERE m.sender_id = u.id 
                      AND m.receiver_id = %s 
                      AND m.is_read = FALSE) as unread_count
            FROM users u
            WHERE u.id != %s
        ''', (session['user_id'], session['user_id'], session['user_id'], session['user_id']))
        
        contacts = cursor.fetchall()
        
        current_contact = None
        messages = []
        
        if contact_id:
            # Récupérer les informations du contact actuel
            cursor.execute('SELECT id, username FROM users WHERE id = %s', (contact_id,))
            current_contact = cursor.fetchone()
            
            if current_contact:
                # Récupérer les messages de la conversation
                cursor.execute('''
                    SELECT * FROM messages 
                    WHERE (sender_id = %s AND receiver_id = %s)
                       OR (sender_id = %s AND receiver_id = %s)
                    ORDER BY created_at
                ''', (session['user_id'], contact_id, contact_id, session['user_id']))
                messages = cursor.fetchall()
                
                # Marquer les messages comme lus
                cursor.execute('''
                    UPDATE messages 
                    SET is_read = TRUE 
                    WHERE sender_id = %s AND receiver_id = %s AND is_read = FALSE
                ''', (contact_id, session['user_id']))
                conn.commit()
        
        return render_template('chat.html', 
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
        receiver_id = request.form.get('receiver_id')
        content = request.form.get('content')
        
        if not receiver_id or not content:
            return jsonify({'success': False, 'error': 'Données manquantes'})
        
        conn = get_db_connection()
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO messages (sender_id, receiver_id, content)
            VALUES (%s, %s, %s)
        ''', (session['user_id'], receiver_id, content))
        
        conn.commit()
        
        return jsonify({'success': True})
        
    except Exception as e:
        logger.error(f"Erreur lors de l'envoi du message: {e}")
        return jsonify({'success': False, 'error': str(e)})
    finally:
        cursor.close()
        conn.close()

@app.route('/get_messages/<int:contact_id>')
@login_required
def get_messages(contact_id):
    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        
        cursor.execute('''
            SELECT * FROM messages 
            WHERE (sender_id = %s AND receiver_id = %s)
               OR (sender_id = %s AND receiver_id = %s)
            ORDER BY created_at
        ''', (session['user_id'], contact_id, contact_id, session['user_id']))
        
        messages = cursor.fetchall()
        
        # Convertir les timestamps en chaînes pour la sérialisation JSON
        for message in messages:
            message['created_at'] = message['created_at'].isoformat()
        
        return jsonify({'success': True, 'messages': messages})
        
    except Exception as e:
        logger.error(f"Erreur lors de la récupération des messages: {e}")
        return jsonify({'success': False, 'error': str(e)})
    finally:
        cursor.close()
        conn.close()

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True)
