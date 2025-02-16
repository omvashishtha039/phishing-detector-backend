from flask import Flask, request, jsonify
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from flask_mysqldb import MySQL
import requests
import datetime
import hashlib
import os

app = Flask(__name__)

# 🔹 MySQL Configuration (Use environment variables for security)
app.config["MYSQL_HOST"] = "localhost"
app.config["MYSQL_USER"] = "root"
app.config["MYSQL_PASSWORD"] = "FOMM04122004"
app.config["MYSQL_DB"] = "phishing_detector"
app.config["MYSQL_CURSORCLASS"] = "DictCursor"

mysql = MySQL(app)

# 🔹 JWT Configuration
app.config["JWT_SECRET_KEY"] = os.getenv("JWT_SECRET_KEY", "FOMM04122004@CyberSecurity")
jwt = JWTManager(app)

# 🔹 Google Safe Browsing API Configuration
GOOGLE_API_KEY = os.getenv("GOOGLE_SAFE_BROWSING_API_KEY", "AIzaSyC4L5wYzsKIDpkUmcwqP5Lx_oGvquYMbyk")
GOOGLE_SAFE_BROWSING_URL = "https://safebrowsing.googleapis.com/v4/threatMatches:find"

# ---------------------- 1️⃣ USER REGISTRATION ----------------------
@app.route("/signup", methods=["POST"])
def signup():
    data = request.get_json()
    email = data.get("email")
    password = data.get("password")

    if not email or not password:
        return jsonify({"error": "Email and password are required!"}), 400

    hashed_password = hashlib.sha256(password.encode()).hexdigest()

    try:
        cursor = mysql.connection.cursor()
        # Check if user already exists
        cursor.execute("SELECT * FROM users WHERE email = %s", (email,))
        existing_user = cursor.fetchone()

        if existing_user:
            return jsonify({"error": "User already exists!"}), 409

        cursor.execute("INSERT INTO users (email, password_hash) VALUES (%s, %s)", (email, hashed_password))
        mysql.connection.commit()
        cursor.close()
        return jsonify({"message": "User registered successfully!"}), 201
    except Exception as e:
        return jsonify({"error": "Database error: " + str(e)}), 500

# ---------------------- 2️⃣ USER LOGIN (JWT TOKEN) ----------------------
@app.route("/login", methods=["POST"])
def login():
    data = request.get_json()
    email = data.get("email")
    password = data.get("password")

    if not email or not password:
        return jsonify({"error": "Email and password are required!"}), 400

    hashed_password = hashlib.sha256(password.encode()).hexdigest()

    cursor = mysql.connection.cursor()
    cursor.execute("SELECT id FROM users WHERE email = %s AND password_hash = %s", (email, hashed_password))
    user = cursor.fetchone()
    cursor.close()

    if user:
        access_token = create_access_token(identity=str(user["id"]), expires_delta=datetime.timedelta(days=1))
        return jsonify({"message": "Login successful!", "token": access_token}), 200
    else:
        return jsonify({"error": "Invalid email or password"}), 401

# ---------------------- 3️⃣ SCAN URL (JWT PROTECTED) ----------------------
@app.route("/scan", methods=["POST"])
@jwt_required()
def scan_url():
    data = request.get_json()
    url = data.get("url")
    user_id = get_jwt_identity()

    if not url:
        return jsonify({"error": "URL is required!"}), 400

    # 🔹 Check URL with Google Safe Browsing API
    payload = {
        "client": {"clientId": "yourcompany", "clientVersion": "1.0"},
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}],
        },
    }

    try:
        response = requests.post(GOOGLE_SAFE_BROWSING_URL, params={"key": GOOGLE_API_KEY}, json=payload)
        response.raise_for_status()
        result = response.json()

        if "matches" in result:
            status = "dangerous"
            message = "⚠️ This URL is a phishing/malicious site!"
        else:
            status = "safe"
            message = "✅ This URL is safe!"

        # 🔹 Store Scan History in MySQL
        cursor = mysql.connection.cursor()
        cursor.execute("INSERT INTO scans (user_id, url, status, scan_date) VALUES (%s, %s, %s, NOW())", (user_id, url, status))
        mysql.connection.commit()
        cursor.close()

        return jsonify({"status": status, "message": message})

    except requests.exceptions.RequestException as e:
        return jsonify({"error": "Google Safe Browsing API error: " + str(e)}), 500

# ---------------------- 4️⃣ FETCH SCAN HISTORY (JWT PROTECTED) ----------------------
@app.route("/scan-history", methods=["GET"])
@jwt_required()
def get_scan_history():
    user_id = get_jwt_identity()

    cursor = mysql.connection.cursor()
    cursor.execute("SELECT id, url, status, DATE_FORMAT(scan_date, '%%Y-%%m-%%d %%H:%%i:%%s') as scan_date FROM scans WHERE user_id = %s ORDER BY scan_date DESC", (user_id,))
    history = cursor.fetchall()
    cursor.close()

    return jsonify({"scan_history": history})

# ---------------------- 5️⃣ TEST DATABASE CONNECTION ----------------------
@app.route("/test-db")
def test_db():
    try:
        cursor = mysql.connection.cursor()
        cursor.execute("SELECT DATABASE();")
        db_name = cursor.fetchone()
        return jsonify({"message": f"Connected to database: {db_name['DATABASE()']}"}), 200
    except Exception as e:
        return jsonify({"error": "Database connection error: " + str(e)}), 500

# ---------------------- 6️⃣ RUN FLASK APP ----------------------
if __name__ == "__main__":
    app.run(debug=True)
