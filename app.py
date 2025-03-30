from flask import Flask, request, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from flask_mysqldb import MySQL
from flask_cors import CORS  
import requests

app = Flask(__name__)
CORS(app, supports_credentials=True)  # ✅ Allow CORS with credentials

# 🔹 MySQL Configuration
app.config["MYSQL_HOST"] = "localhost"
app.config["MYSQL_USER"] = "root"
app.config["MYSQL_PASSWORD"] = "FOMM04122004"
app.config["MYSQL_DB"] = "phishing_detector"
app.config["MYSQL_CURSORCLASS"] = "DictCursor"

mysql = MySQL(app)

# 🔹 JWT Configuration
app.config["JWT_SECRET_KEY"] = "FOMM04122004@CyberSecurity"
jwt = JWTManager(app)

# 🔹 Google Safe Browsing API Configuration
GOOGLE_API_KEY = "AIzaSyCBHBBeln-E6fSLMt4r6QGlstGEKvmG9jY"
GOOGLE_SAFE_BROWSING_URL = "https://safebrowsing.googleapis.com/v4/threatMatches:find"


@app.route('/')
def home():
    return jsonify({"message": "Backend is running successfully!"}), 200


# ---------------------- 1️⃣ USER REGISTRATION ----------------------
@app.route('/signup', methods=['POST'])
def signup():
    data = request.get_json() or request.form
    if not data or not all(k in data for k in ["name", "email", "password"]):
        return jsonify({"error": "Missing fields"}), 400

    hashed_password = generate_password_hash(data["password"])  # Encrypt password

    cursor = mysql.connection.cursor()
    cursor.execute("INSERT INTO users (name, email, password) VALUES (%s, %s, %s)", 
                   (data["name"], data["email"], hashed_password))
    mysql.connection.commit()
    cursor.close()
    
    return jsonify({"message": "Signup successful!"}), 201


# ---------------------- 2️⃣ USER LOGIN (JWT TOKEN) ----------------------
@app.route('/login', methods=['POST'])
def login():
    data = request.get_json() or request.form
    if not data or not all(k in data for k in ["email", "password"]):
        return jsonify({"error": "Missing credentials"}), 400

    cursor = mysql.connection.cursor()
    cursor.execute("SELECT * FROM users WHERE email=%s", (data["email"],))
    user = cursor.fetchone()
    cursor.close()

    if user and check_password_hash(user["password"], data["password"]):
        access_token = create_access_token(identity=user["id"])
        return jsonify({"message": "Login successful!", "token": access_token}), 200
    return jsonify({"message": "Invalid email or password!"}), 401


# ---------------------- 3️⃣ SCAN URL (JWT PROTECTED) ----------------------
@app.route('/scan', methods=['POST'])
def scan_url():
    try:
        data = request.get_json()
        if not data or 'url' not in data:
            return jsonify({"error": "Missing URL"}), 400

        url = data["url"]
        
        # Placeholder logic for phishing detection
        safe = "phishing" not in url.lower()  # Example detection logic

        return jsonify({"safe": safe})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

if __name__ == '__main__':
    app.run(debug=True)
    
# ---------------------- 4️⃣ FETCH SCAN HISTORY ----------------------
@app.route("/scan-history", methods=["GET"])
@jwt_required()
def get_scan_history():
    user_id = get_jwt_identity()

    cursor = mysql.connection.cursor()
    cursor.execute("SELECT url, status, DATE_FORMAT(scan_date, '%%Y-%%m-%%d %%H:%%i:%%s') as scan_date FROM scans WHERE user_id = %s ORDER BY scan_date DESC", (user_id,))
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
        return jsonify({"error": "Database connection error", "details": str(e)}), 500


# ---------------------- 6️⃣ RUN FLASK APP ----------------------
if __name__ == "__main__":
    app.run(debug=True)
