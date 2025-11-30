from flask import Flask, render_template, request, redirect, url_for, flash, jsonify
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from flask_cors import CORS
from werkzeug.security import check_password_hash
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5

import base64
import os
import secrets

from database.database import db_init, db_get_user_by_id, db_get_user_by_name, db_set_pubkey, db_get_pubkey, db_get_quotes

# --- App Setup ---
app = Flask(__name__)
CORS(app)
app.config['SECRET_KEY'] = os.urandom(24)
FLAG = os.getenv('FLAG')

# --- User and Login Management ---
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

class User(UserMixin):
    # User model no longer needs to hold keys
    def __init__(self, id, username, is_admin):
        self.id = id
        self.username = username
        self.is_admin = is_admin

@login_manager.user_loader
def load_user(user_id):
    user_data = db_get_user_by_id(user_id)
    if user_data:
        return User(id=user_data[0], username=user_data[1], is_admin=user_data[3])
    return None

# --- Cryptography Functions ---
def encrypt_message(public_key_pem, message):
    """Encrypts a message using a provided public key PEM."""
    public_key = RSA.import_key(public_key_pem)
    cipher_rsa = PKCS1_v1_5.new(public_key)
    encrypted_message = cipher_rsa.encrypt(message.encode('utf-8'))
    return base64.b64encode(encrypted_message).decode('utf-8')

# --- Routes ---
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        publicKey = request.form['publicKey']

        user_data = db_get_user_by_name(username)
        if user_data and check_password_hash(user_data[2], password):
            db_set_pubkey(user_data[0], publicKey)
            user = User(id=user_data[0], username=user_data[1], is_admin=user_data[3])
            login_user(user)
            return redirect(url_for('index'))
        
        else:
            check_password_hash(password, "") # Avoid timing attacks by hashing the password anyway
            flash('Invalid username or password')
    
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/')
@login_required
def index():
    pubkey = db_get_pubkey(current_user.username)[0]
    return render_template('index.html', username=current_user.username, pubkey=pubkey, is_admin=current_user.is_admin)

@app.route('/request_encrypted', methods=['POST'])
@login_required
def request_encrypted():
    data = request.get_json()
    is_flag_request = data.get('flag', False)

    if is_flag_request and not current_user.is_admin:
        return jsonify({'error': 'Only the admin can request the flag.'}), 403

    result = db_get_pubkey(current_user.username)
    if not result or not result[0]:
        return jsonify({'error': f'No public key found for user {current_user.username}. Please log in to set a key.'}), 404
    client_public_key = result[0]

    if is_flag_request:
        content = FLAG
    else:
        quotes = db_get_quotes()
        content = secrets.choice(quotes)[0]

    try:
        encrypted_content = encrypt_message(client_public_key, content)
        return jsonify({
            'encrypted_content': encrypted_content
        })
    except Exception as e:
        return jsonify({'error': f'Encryption failed: {str(e)}'}), 500

if __name__ == '__main__':
    db_init()
    app.run(host='0.0.0.0', port=80, debug=False)
