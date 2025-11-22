import os
import mysql.connector
from flask import Flask, request, jsonify, send_from_directory
from dotenv import load_dotenv
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename

# =========================
# CLEAN VERSION (NO INTENTIONAL VULN)
# Untuk test pipeline (SQ + Semgrep) end-to-end
# =========================

load_dotenv()

app = Flask(__name__)

# batasan upload sederhana
UPLOAD_DIR = "uploads"
os.makedirs(UPLOAD_DIR, exist_ok=True)
ALLOWED_EXTENSIONS = {"txt", "log", "csv", "json"}
BASE_DIR = os.path.dirname(os.path.abspath(__file__))


def allowed_file(filename: str) -> bool:
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS


# =========================
# Database Connection (pakai ENV)
# =========================
def get_db():
    conn = mysql.connector.connect(
        host=os.getenv("DB_HOST", "localhost"),
        user=os.getenv("DB_USER", "root"),
        password=os.getenv("DB_PASS", "password"),
        database=os.getenv("DB_NAME", "demo_app"),
    )
    return conn


# =========================
# Healthcheck
# =========================
@app.route("/health", methods=["GET"])
def health():
    try:
        conn = get_db()
        conn.close()
        return jsonify({"status": "ok", "db": "connected"}), 200
    except Exception as e:
        return jsonify({"status": "error", "db_error": str(e)}), 500



@app.route("/openapi.json", methods=["GET"])
def openapi_json():
    # kirim YAML tapi ZAP gak masalah, dia bisa baca YAML
    return send_from_directory(
        BASE_DIR,
        "openapi.yaml",
        mimetype="application/yaml"
    )
# =========================
# 1. LOGIN (clean: parameterized + hashed password)
# =========================
@app.route("/login", methods=["POST"])
def login():
    """
    Body:
    {
      "username": "admin",
      "password": "admin123"
    }

    - Pakai query parameterized (menghindari SQLi)
    - Password disimpan dalam bentuk hash (bcrypt / pbkdf2_*)
    """
    data = request.get_json() or request.form
    username = data.get("username", "")
    password = data.get("password", "")

    if not username or not password:
        return jsonify({"message": "username & password required"}), 400

    conn = get_db()
    cursor = conn.cursor(dictionary=True)

    # aman: gunakan placeholder %s
    cursor.execute(
        "SELECT id, username, password, email FROM users WHERE username = %s",
        (username,),
    )
    user = cursor.fetchone()

    cursor.close()
    conn.close()

    if not user:
        return jsonify({"message": "Invalid credentials"}), 401

    hashed = user["password"]

    # kalau di DB masih plaintext (contoh awal), bisa di-migrate pelan-pelan
    # untuk clean version, anggap semua password sudah di-hash pakai generate_password_hash
    if not check_password_hash(hashed, password):
        return jsonify({"message": "Invalid credentials"}), 401

    # di dunia nyata, jangan balikin password / hash
    return jsonify(
        {
            "message": "Login success",
            "user": {
                "id": user["id"],
                "username": user["username"],
                "email": user["email"],
            },
        }
    )


# =========================
# 2. USER DETAIL (clean: parameterized query)
# =========================
@app.route("/users/<int:user_id>", methods=["GET"])
def get_user(user_id):
    """
    NOTE:
    - Untuk benar-benar secure harus pakai auth/token + cek ownership.
    - Di sini fokusnya: query param aman (parameterized).
    """
    conn = get_db()
    cursor = conn.cursor(dictionary=True)

    cursor.execute(
        "SELECT id, username, email FROM users WHERE id = %s",
        (user_id,),
    )
    user = cursor.fetchone()

    cursor.close()
    conn.close()

    if user:
        return jsonify(user)
    else:
        return jsonify({"message": "User not found"}), 404


# =========================
# 3. SEARCH (clean: parameterized LIKE)
# =========================
@app.route("/search", methods=["GET"])
def search_users():
    """
    Contoh: /search?q=admin

    - Clean: gunakan parameterized query untuk LIKE.
    """
    q = request.args.get("q", "").strip()

    conn = get_db()
    cursor = conn.cursor(dictionary=True)

    like_pattern = f"%{q}%"
    cursor.execute(
        "SELECT id, username, email FROM users WHERE username LIKE %s",
        (like_pattern,),
    )
    results = cursor.fetchall()

    cursor.close()
    conn.close()

    return jsonify({"results": results})


# =========================
# 4. CHANGE PASSWORD (clean: pakai hash kuat, tetap parameterized)
# =========================
@app.route("/change_password", methods=["POST"])
def change_password():
    """
    Body:
    {
      "user_id": 1,
      "new_password": "admin123"
    }

    - Clean: password di-hash dengan generate_password_hash.
    - Masih belum ada auth benar (ini demo). Di real app harus cek user login.
    """
    data = request.get_json() or request.form
    user_id = data.get("user_id")
    new_password = data.get("new_password", "")

    if not user_id or not new_password:
        return jsonify({"message": "user_id & new_password required"}), 400

    hashed = generate_password_hash(new_password)  # default pbkdf2: aman untuk demo

    conn = get_db()
    cursor = conn.cursor()
    cursor.execute(
        "UPDATE users SET password = %s WHERE id = %s",
        (hashed, user_id),
    )
    conn.commit()
    cursor.close()
    conn.close()

    return jsonify({"message": "Password changed successfully"})


# =========================
# 5. FILE UPLOAD (clean: secure_filename + allowed extensions)
# =========================
@app.route("/upload", methods=["POST"])
def upload_file():
    """
    Form-data:
    - file: <file>

    Clean version:
    - Gunakan secure_filename
    - Batasi extension
    - Directory upload fixed
    """
    if "file" not in request.files:
        return jsonify({"message": "No file part"}), 400

    f = request.files["file"]
    if f.filename == "":
        return jsonify({"message": "No selected file"}), 400

    if not allowed_file(f.filename):
        return jsonify({"message": "File type not allowed"}), 400

    filename = secure_filename(f.filename)
    save_path = os.path.join(UPLOAD_DIR, filename)
    f.save(save_path)

    return jsonify({"message": "File uploaded", "path": save_path})


# =========================
# 6. CONFIG (clean: tidak expose secret)
# =========================
@app.route("/config", methods=["GET"])
def config_info():
    """
    Clean version:
    - Tidak mengembalikan password / secret.
    - Hanya info high-level.
    """
    config = {
        "db_host": os.getenv("DB_HOST", "localhost"),
        "db_name": os.getenv("DB_NAME", "demo_app"),
        "app_env": os.getenv("APP_ENV", "development"),
    }
    return jsonify(config)


if __name__ == "__main__":
    host = os.getenv("FLASK_RUN_HOST", "0.0.0.0")
    port = int(os.getenv("FLASK_RUN_PORT", "9500"))
    debug = os.getenv("FLASK_DEBUG", "false").lower() == "true"

    app.run(host=host, port=port, debug=debug)