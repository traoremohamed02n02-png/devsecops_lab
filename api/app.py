from flask import Flask, request, jsonify
import sqlite3
import subprocess
import hashlib
import os
import ast
import operator as op

app = Flask(__name__)

DATABASE = "users.db"
FILES_DIR = "files"

# =========================
# 1️⃣ LOGIN – SQL Injection FIX
# =========================
@app.route("/login", methods=["POST"])
def login():
    data = request.get_json()
    username = data.get("username", "")
    password = data.get("password", "")

    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()

    query = "SELECT * FROM users WHERE username=? AND password=?"
    cursor.execute(query, (username, password))
    result = cursor.fetchone()

    conn.close()

    if result:
        return jsonify({"status": "success", "user": username})
    return jsonify({"status": "error", "message": "Invalid credentials"}), 401


# =========================
# 2️⃣ PING – Command Injection FIX
# =========================
@app.route("/ping", methods=["POST"])
def ping():
    data = request.get_json()
    host = data.get("host", "")

    try:
        output = subprocess.check_output(
            ["ping", "-c", "1", host],   # shell=False (par défaut)
            stderr=subprocess.STDOUT
        )
        return jsonify({"output": output.decode()})
    except subprocess.CalledProcessError:
        return jsonify({"error": "Ping failed"}), 400


# =========================
# 3️⃣ COMPUTE – eval() FIX
# =========================
allowed_ops = {
    ast.Add: op.add,
    ast.Sub: op.sub,
    ast.Mult: op.mul,
    ast.Div: op.truediv
}

def safe_eval(expr):
    node = ast.parse(expr, mode="eval")

    def _eval(n):
        if isinstance(n, ast.Expression):
            return _eval(n.body)
        if isinstance(n, ast.Num):
            return n.n
        if isinstance(n, ast.BinOp):
            return allowed_ops[type(n.op)](_eval(n.left), _eval(n.right))
        raise ValueError("Expression non autorisée")

    return _eval(node)

@app.route("/compute", methods=["POST"])
def compute():
    data = request.get_json()
    expression = data.get("expression", "1+1")

    try:
        result = safe_eval(expression)
        return jsonify({"result": result})
    except Exception:
        return jsonify({"error": "Invalid expression"}), 400


# =========================
# 4️⃣ HASH – MD5 autorisé (usedforsecurity=False)
# =========================
@app.route("/hash", methods=["POST"])
def hash_data():
    data = request.get_json()
    value = data.get("data", "")

    md5_hash = hashlib.md5(
        value.encode(),
        usedforsecurity=False   # explicite : pas usage sécurité
    ).hexdigest()

    return jsonify({
        "md5": md5_hash,
        "used_for_security": False
    })


# =========================
# 5️⃣ READ FILE – Path Traversal FIX
# =========================
@app.route("/readfile", methods=["POST"])
def readfile():
    data = request.get_json()
    filename = data.get("filename", "")

    safe_filename = os.path.basename(filename)
    filepath = os.path.join(FILES_DIR, safe_filename)

    if not os.path.isfile(filepath):
        return jsonify({"error": "File not found"}), 404

    with open(filepath, "r") as f:
        content = f.read()

    return jsonify({"content": content})


# =========================
# ENDPOINT TEST
# =========================
@app.route("/hello", methods=["GET"])
def hello():
    return jsonify({"message": "Welcome to the secure DevSecOps API"})


# =========================
# RUN APP
# =========================
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
