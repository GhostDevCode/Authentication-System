from flask import Flask, render_template, request, jsonify, redirect, url_for, session, Response
import os
import base64
import json
import shutil
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend
from html import escape
import modules.mongointf


# Initialize Flask app
app = Flask(__name__, template_folder="pages")
app.secret_key = os.urandom(12)  # Secret key for session management

# In-memory storage for users and their public keys
users = {}


# Utility Functions
def generate_key_pair():
    """Generate RSA key pair for a user."""
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    return private_key, public_key


def serialize_public_key(public_key):
    """Serialize a public key to PEM format."""
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode('utf-8')


# Routes
@app.route('/')
def home():
    """Render the home page with optional error messages."""
    error_message = request.args.get('error', '')
    safe_error_message = escape(error_message)  # Escape error message to prevent XSS

    # Validate error messages
    if safe_error_message not in ["", "Invalid credentials, please try again."]:
        return Response("Unauthorized", status=401)

    return render_template('index.html', error_message=safe_error_message)


@app.route('/register', methods=['POST'])
def register():
    """Register a new user and generate a passkey."""
    username = request.json.get('username')
    if not username:
        return jsonify({"error": "Username is required"}), 400

    if username in users:
        return jsonify({"error": "User already exists"}), 400

    private_key, public_key = generate_key_pair()
    users[username] = {
        'private_key': private_key,
        'public_key': serialize_public_key(public_key)
    }
    return jsonify({"message": "User registered successfully"}), 201


@app.route('/login', methods=['POST'])
def login():
    """Login user via username and password (basic functionality)."""
    username = request.form.get('username')
    if not username:
        return jsonify({"error": "Username is required"}), 400

    # Check if the user exists
    if username in users:
        session['username'] = username
        return f"Welcome, {username}!"
    else:
        error_message = "Invalid credentials, please try again."
        return redirect(url_for('home', error=error_message))


@app.route('/passkey_login', methods=['POST'])
def passkey_login():
    """Login user using passkey (passwordless authentication)."""
    username = request.json.get('username')
    signature = request.json.get('signature')

    if not username or not signature:
        return jsonify({"error": "Username and signature are required"}), 400

    if username not in users:
        return jsonify({"error": "User not found"}), 404

    user_data = users[username]
    public_key = serialization.load_pem_public_key(
        user_data['public_key'].encode('utf-8'),
        backend=default_backend()
    )

    try:
        # Verify the signature
        public_key.verify(
            base64.b64decode(signature),
            b"Login request",  # Example message signed by the client
            padding.PKCS1v15(),
            hashes.SHA256()
        )
        session['username'] = username
        return jsonify({"message": "Login successful"}), 200
    except Exception:
        return jsonify({"error": "Invalid signature"}), 403


@app.route('/logout', methods=['POST'])
def logout():
    """Logout the currently logged-in user."""
    session.pop('username', None)
    return jsonify({"message": "Logged out successfully"}), 200


@app.route('/protected', methods=['GET'])
def protected():
    """Access a protected route that requires login."""
    if 'username' not in session:
        return jsonify({"error": "Unauthorized"}), 401
    return jsonify({"message": f"Hello, {session['username']}!"}), 200


# Configuration Loader
def load_config():
    """Load application configuration from file."""
    config_path = 'conf/config.json'
    default_config_path = 'conf/default_config.json'

    if os.path.exists(config_path):
        with open(config_path, 'r') as f:
            return json.load(f)
    elif os.path.exists(default_config_path):
        print("Config file not found. Copying from default configuration.")
        os.makedirs(os.path.dirname(config_path), exist_ok=True)
        shutil.copy(default_config_path, config_path)
        with open(config_path, 'r') as f:
            return json.load(f)
    else:
        raise FileNotFoundError("Neither config.json nor default_config.json found.")


# Run the Application
if __name__ == '__main__':
    app_config = load_config()
    app.run(debug=True)
