from flask import Flask, render_template, request, redirect, url_for, session

from googletrans import Translator
from cryptography.fernet import Fernet
import hashlib
 
app = Flask(__name__)
app.secret_key = "supersecretkey"  # Secret key for session management

# Dummy user credentials (you can replace these with real authentication logic)
VALID_USERNAME = "user"
VALID_PASSWORD = "password123"
VALID_MFA_TOKEN = "123456"

# Module 1: Natural Language Processing (NLP) for Real-Time Translation
translator = Translator()

def translate_text(text, src_language='auto', dest_language='en'):
    translated = translator.translate(text, src=src_language, dest=dest_language)
    return translated.text

# Module 2: End-to-End Encryption
key = Fernet.generate_key()
cipher_suite = Fernet(key)

def encrypt_message(message):
    return cipher_suite.encrypt(message.encode())

def decrypt_message(encrypted_message):
    return cipher_suite.decrypt(encrypted_message).decode()

# Module 6: Data Integrity and Message Authentication
def hash_message(message):
    return hashlib.sha256(message.encode()).hexdigest()

@app.route("/", methods=["GET", "POST"])
def login():
    # Check if the user is authenticated (skip login)
    if session.get("authenticated"):
        return redirect(url_for("mfa"))
    
    error = None
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]

        # Validate username and password
        if username == VALID_USERNAME and password == VALID_PASSWORD:
            session["authenticated"] = True
            return redirect(url_for("mfa"))
        else:
            error = "Invalid username or password"

    return render_template("index.html", error=error)

@app.route("/mfa", methods=["GET", "POST"])
def mfa():
    # Redirect to login if not authenticated
    if not session.get("authenticated"):
        return redirect(url_for("login"))

    error = None
    if request.method == "POST":
        mfa_token = request.form["mfa_token"]

        # Validate MFA token
        if mfa_token == VALID_MFA_TOKEN:
            session["mfa_verified"] = True
            return redirect(url_for("secure_message"))
        else:
            error = "Invalid MFA token"

    return render_template("index.html", error=error)

@app.route("/secure_message", methods=["GET", "POST"])
def secure_message():
    # Redirect to login if not authenticated
    if not session.get("authenticated"):
        return redirect(url_for("login"))
    # Redirect to MFA if MFA is not verified
    if not session.get("mfa_verified"):
        return redirect(url_for("mfa"))

    translated_message = None
    original_hash = None
    encrypted_message = None
    decrypted_message = None

    if request.method == "POST":
        original_message = request.form["message"]
        dest_language = request.form["language"]

        # Perform translation
        translated_message = translate_text(original_message, dest_language=dest_language)

        # Hash the message for integrity
        original_hash = hash_message(translated_message)

        # Encrypt the translated message
        encrypted_message = encrypt_message(translated_message).decode()

        # Decrypt the message for display (for demo purposes)
        decrypted_message = decrypt_message(encrypted_message.encode())

    return render_template("index.html",
                           translated_message=translated_message,
                           original_hash=original_hash,
                           encrypted_message=encrypted_message,
                           decrypted_message=decrypted_message)

if __name__ == "__main__":
    app.run(debug=True)
