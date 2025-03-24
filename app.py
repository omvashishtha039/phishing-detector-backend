from flask import Flask, request, jsonify
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from flask_sqlalchemy import SQLAlchemy
from flask_cors import CORS
import requests
import datetime
import hashlib
import os

app = Flask(__name__)
CORS(app)

# 🔹 PostgreSQL Configuration (Replace with your actual Render database URL)
app.config["SQLALCHEMY_DATABASE_URI"] = "postgresql://phishing_detector_user:eeWmk2IW9pTXqrap4F6bDFGW87i1DQZv@dpg-cvguq0dumphs73d02r7g-a/phishing_detector"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

db = SQLAlchemy(app)

# 🔹 JWT Configuration
app.config["JWT_SECRET_KEY"] = os.getenv("JWT_SECRET_KEY", "FOMM04122004@CyberSecurity")
jwt = JWTManager(app)

# 🔹 Google Safe Browsing API Configuration
GOOGLE_API_KEY = os.getenv("GOOGLE_SAFE_BROWSING_API_KEY", "YOUR_GOOGLE_API_KEY_HERE")
GOOGLE_SAFE_BROWSING_URL = "https://safebrowsing.googleapis.com/v4/threatMatches:find"

# ---------------------- DATABASE MODELS ----------------------
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)

class Scan(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    url = db.Column(db.String(500), nullable=False)
    status = db.Column(db.String(20), nullable=False)
    scan_date = db.Column(db.DateTime, default=datetime.datetime.utcnow)

# Create Tables
with app.app_context():
    db.create_all()

# ---------------------- 1️⃣ HOME ROUTE ----------------------
@app.route('/')
def home():
    return jsonify({"message": "Backend is running successfully with PostgreSQL!"}), 200

# ---------------------- 2️⃣ USER REGISTRATION ----------------------
@app.route("/signup", methods=["POST"])
def signup():
    data = request.get_json()
    email = data.get("email")
    password = data.get("password")

    if not email or not password:
        return jsonify({"error": "Email and password are required!"}), 400

    hashed_password = hashlib.sha256(password.encode()).hexdigest()

    existing_user = User.query.filter_by(email=email).first()
    if existing_user:
        return jsonify({"error": "User already exists!"}), 409

    new_user = User(email=email, password_hash=hashed_password)
    db.session.add(new_user)
    db.session.commit()

    return jsonify({"message": "User registered successfully!"}), 201

# ---------------------- 3️⃣ USER LOGIN (JWT TOKEN) ----------------------
@app.route("/login", methods=["POST"])
def login():
    data = request.get_json()
    email = data.get("email")
    password = data.get("password")

    if not email or not password:
        return jsonify({"error": "Email and password are required!"}), 400

    hashed_password = hashlib.sha256(password.encode()).hexdigest()
    user = User.query.filter_by(email=email, password_hash=hashed_password).first()

    if user:
        access_token = create_access_token(identity=str(user.id), expires_delta=datetime.timedelta(days=1))
        return jsonify({"message": "Login successful!", "token": access_token}), 200
    else:
        return jsonify({"error": "Invalid email or password"}), 401

# ---------------------- 4️⃣ SCAN URL (JWT PROTECTED) ----------------------
@app.route("/scan", methods=["POST"])
@jwt_required()
def scan_url():
    data = request.get_json()
    url = data.get("url")
    user_id = get_jwt_identity()

    if not url:
        return jsonify({"error": "URL is required!"}), 400

    payload = {
        "client": {"clientId": "yourcompany", "clientVersion": "1.0"},
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}],
        },
    }

    try:
        response = requests.post(GOOGLE_SAFE_BROWSING_URL, params={"key": GOOGLE_API_KEY}, json=payload)
        result = response.json()

        # Determine scan result
        if "matches" in result:
            status = "dangerous"
            message = "⚠️ This URL is a phishing/malicious site!"
        else:
            status = "safe"
            message = "✅ This URL is safe!"

        # 🔹 Store Scan History in MySQL
        cursor = mysql.connection.cursor()
        cursor.execute("INSERT INTO scans (user_id, url, status) VALUES (%s, %s, %s)", (user_id, url, status))
        mysql.connection.commit()
        cursor.close()

        return jsonify({"status": status, "message": message, "scan_data": result})

    except requests.exceptions.RequestException as e:
        return jsonify({"error": "Google Safe Browsing API error: " + str(e)}), 500



# ---------------------- 5️⃣ FETCH SCAN HISTORY (JWT PROTECTED) ----------------------
@app.route("/scan-history", methods=["GET"])
@jwt_required()
def get_scan_history():
    user_id = get_jwt_identity()
    history = Scan.query.filter_by(user_id=user_id).order_by(Scan.scan_date.desc()).all()
    
    scan_data = [{"id": scan.id, "url": scan.url, "status": scan.status, "scan_date": scan.scan_date.strftime("%Y-%m-%d %H:%M:%S")} for scan in history]

    return jsonify({"scan_history": scan_data})

# ---------------------- 6️⃣ TEST DATABASE CONNECTION ----------------------
@app.route("/test-db")
def test_db():
    try:
        db.session.execute("SELECT 1")
        return jsonify({"message": "Connected to PostgreSQL successfully!"}), 200
    except Exception as e:
        return jsonify({"error": "Database connection error: " + str(e)}), 500

# ---------------------- 7️⃣ RUN FLASK APP ----------------------
if __name__ == "__main__":
    app.run(debug=True)
