from flask import *
import json
import os
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
import base64
from html import *
import modules.mongointf
import shutil


app = Flask(__name__,template_folder="pages")
app.secret_key = os.urandom(12)  # Secret key for session management

# In-memory storage for users and their public keys
users = {}

def generate_key_pair():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    return private_key, public_key

def serialize_public_key(public_key):
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode('utf-8')

@app.route('/')
def home():
    error_message = request.args.get('error', '')
    safe_error_message = escape(error_message)  # Escape error message to prevent XSS

    # Check if the error message is valid
    if safe_error_message not in ["", "Invalid credentials, please try again."]:
        # Return a 401 Unauthorized response for invalid messages
        return Response("Unauthorized", status=401)

    # Render the template with the valid error message
    return render_template('index.html', error_message=safe_error_message)

@app.route('/register', methods=['POST'])
def register():
    username = request.json.get('username')
    if username in users:
        return jsonify({"error": "User  already exists"}), 400

    private_key, public_key = generate_key_pair()
    users[username] = {
        'private_key': private_key,
        'public_key': serialize_public_key(public_key)
    }
    return jsonify({"message": "User  registered successfully"}), 201

@app.route('/login', methods=['POST'])
def login():
    username = request.form['username']
    password = request.form['password']

    # Here you would typically check the username and password against your user database.
    if username in users:  # Check if user exists
        # For simplicity, we are not checking the password here
        session['username'] = username
        return f"Welcome, {username}!"
    else:
        error_message = "Invalid credentials, please try again."
        return redirect(url_for('home', error=error_message))

@app.route('/passkey_login', methods=['POST'])
def passkey_login():
    username = request.json.get('username')
    signature = request.json.get('signature')

    if username not in users:
        return jsonify({"error": "User  not found"}), 404

    user_data = users[username]
    public_key = serialization.load_pem_public_key(
        user_data['public_key'].encode('utf-8'),
        backend=default_backend()
    )

    # Verify the signature (this is a simplified example)
    try:
        public_key.verify(
            base64.b64decode(signature),
            b"Login request",
            padding.PKCS1v15(),
            hashes.SHA256()
        )
        session['username'] = username
        return jsonify({"message": "Login successful"}), 200
    except Exception as e:
        return jsonify({"error": "Invalid signature"}), 403

@app.route('/logout', methods=['POST'])
def logout():
    session.pop('username', None)
    return jsonify({"message": "Logged out successfully"}), 200

@app.route('/protected', methods=['GET'])
def protected():
    if 'username' not in session:
        return jsonify({"error": "Unauthorized"}), 401
    return jsonify({"message": f"Hello, {session['username']}!"}), 200


def load_config():
    config_path = 'conf/config.json'
    default_config_path = 'conf/default_config.json'

    if os.path.exists(config_path):
        # Load the existing config.json
        with open(config_path, 'r') as f:
            return json.load(f)
    elif os.path.exists(default_config_path):
        # If config.json is missing, copy from default_config.json
        print("Config file not found. Copying from default configuration.")
        os.makedirs(os.path.dirname(config_path), exist_ok=True)
        shutil.copy(default_config_path, config_path)
        with open(config_path, 'r') as f:
            return json.load(f)
    else:
        # If both are missing, raise an error
        raise FileNotFoundError("Neither config.json nor default_config.json found.")



if __name__ == '__main__':
    app_config = load_config()
    app.run(debug=True)