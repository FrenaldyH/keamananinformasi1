"""Secure storage web app: every stored item is encrypted with AES, DES and RC4."""
import hashlib
import hmac
import io
import os
import secrets
import sqlite3
import time

from flask import Flask, abort, g, jsonify, request, send_file, session

import ciphers

BASE = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE, "data.db")

app = Flask(__name__, static_folder="static", static_url_path="")
app.secret_key = secrets.token_bytes(32)  # signs the session cookie; restart = everyone logged out
app.config["MAX_CONTENT_LENGTH"] = 200 * 1024 * 1024  # 200 MB upload limit
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"  # basic CSRF protection; cookie is HttpOnly by default

# token -> {"user_id", "username", "keys"}. Keys live only in RAM while the user is logged in.
SESSIONS = {}

# Allowed file extensions per data kind (server-side check, the HTML `accept` is only a hint)
ALLOWED = {
    "profile": {".json"},
    "idcard": {".jpg", ".jpeg", ".png", ".webp"},
    "document": {".pdf", ".doc", ".docx", ".xls", ".xlsx"},
    "video": {".mp4", ".webm", ".mov", ".mkv"},
}

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY,
    username TEXT UNIQUE NOT NULL,
    pw_salt BLOB NOT NULL,   -- salt for the password hash
    pw_hash BLOB NOT NULL,   -- PBKDF2(password, pw_salt)
    key_salt BLOB NOT NULL   -- separate salt for deriving the encryption keys
);
CREATE TABLE IF NOT EXISTS items (
    id INTEGER PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id),
    kind TEXT NOT NULL,
    filename TEXT NOT NULL,
    mime TEXT NOT NULL,
    size INTEGER NOT NULL,
    created TEXT DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS ciphertexts (
    item_id INTEGER NOT NULL REFERENCES items(id),
    algo TEXT NOT NULL,
    iv BLOB NOT NULL,
    data BLOB NOT NULL,
    enc_ms REAL NOT NULL,
    PRIMARY KEY (item_id, algo)
);
"""


def db():
    """One SQLite connection per request, closed in teardown."""
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(_):
    """Close the request's DB connection."""
    conn = g.pop("db", None)
    if conn:
        conn.close()


def hash_password(password: str, salt: bytes) -> bytes:
    """Slow salted hash so a leaked DB can't be brute-forced cheaply."""
    return hashlib.pbkdf2_hmac("sha256", password.encode(), salt, ciphers.KDF_ITERATIONS)


def current_user() -> dict:
    """Return the logged-in session or stop with 401."""
    s = SESSIONS.get(session.get("token"))
    if not s:
        abort(401)
    return s


# ---------- auth ----------

@app.post("/api/register")
def register():
    """Create a user with salted password hash + a salt for key derivation."""
    body = request.get_json(force=True)
    username = str(body.get("username", "")).strip()
    password = str(body.get("password", ""))
    if not (3 <= len(username) <= 32) or len(password) < 8:
        return jsonify(error="Username 3-32 karakter, password minimal 8 karakter"), 400
    pw_salt, key_salt = os.urandom(16), os.urandom(16)
    try:
        with db():
            db().execute("INSERT INTO users (username, pw_salt, pw_hash, key_salt) VALUES (?,?,?,?)",
                         (username, pw_salt, hash_password(password, pw_salt), key_salt))
    except sqlite3.IntegrityError:
        return jsonify(error="Username sudah dipakai"), 409
    return jsonify(ok=True)


@app.post("/api/login")
def login():
    """Verify password, derive the 3 encryption keys, keep them in server RAM."""
    body = request.get_json(force=True)
    username = str(body.get("username", ""))
    password = str(body.get("password", ""))
    row = db().execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
    if not row or not hmac.compare_digest(hash_password(password, row["pw_salt"]), row["pw_hash"]):
        return jsonify(error="Username atau password salah"), 401
    token = secrets.token_urlsafe(32)
    SESSIONS[token] = {"user_id": row["id"], "username": username,
                       "keys": ciphers.derive_keys(password, row["key_salt"])}
    session["token"] = token
    return jsonify(username=username)


@app.post("/api/logout")
def logout():
    """Forget the session and its keys."""
    SESSIONS.pop(session.pop("token", None), None)
    return jsonify(ok=True)


@app.get("/api/me")
def me():
    """Who is logged in (used by the page on load)."""
    return jsonify(username=current_user()["username"])


# ---------- data ----------

@app.post("/api/items")
def upload():
    """Encrypt the uploaded file with AES, DES and RC4 and store all three ciphertexts."""
    user = current_user()
    kind = request.form.get("kind", "")
    f = request.files.get("file")
    if kind not in ALLOWED or not f or not f.filename:
        return jsonify(error="kind atau file tidak valid"), 400
    ext = os.path.splitext(f.filename)[1].lower()
    if ext not in ALLOWED[kind]:
        return jsonify(error=f"Ekstensi {ext} tidak diizinkan untuk {kind}"), 400
    data = f.read()

    with db():  # one transaction: item + its three ciphertexts
        cur = db().execute("INSERT INTO items (user_id, kind, filename, mime, size) VALUES (?,?,?,?,?)",
                           (user["user_id"], kind, f.filename, f.mimetype or "application/octet-stream",
                            len(data)))
        for algo in ciphers.ALGOS:
            t0 = time.perf_counter()
            iv, ct = ciphers.encrypt(algo, user["keys"][algo], data)
            enc_ms = (time.perf_counter() - t0) * 1000
            db().execute("INSERT INTO ciphertexts VALUES (?,?,?,?,?)", (cur.lastrowid, algo, iv, ct, enc_ms))
    return jsonify(id=cur.lastrowid)


@app.get("/api/items")
def list_items():
    """List the user's items with per-algorithm ciphertext info (size, time, IV, first bytes)."""
    user = current_user()
    items = [dict(r) for r in db().execute(
        "SELECT id, kind, filename, mime, size, created FROM items WHERE user_id = ? ORDER BY id DESC",
        (user["user_id"],))]
    for item in items:
        rows = db().execute(
            "SELECT algo, hex(iv) AS iv, length(data) AS ct_size, hex(substr(data, 1, 24)) AS preview, enc_ms "
            "FROM ciphertexts WHERE item_id = ?", (item["id"],))
        item["ciphers"] = {r["algo"]: dict(r) for r in rows}
    return jsonify(items)


@app.get("/api/items/<int:item_id>/download")
def download(item_id):
    """Decrypt one item with the chosen algorithm; decryption time goes in X-Decrypt-Ms."""
    user = current_user()
    algo = request.args.get("algo", "aes")
    row = db().execute(
        "SELECT i.filename, i.mime, c.iv, c.data FROM items i JOIN ciphertexts c ON c.item_id = i.id "
        "WHERE i.id = ? AND i.user_id = ? AND c.algo = ?",  # user_id check: no reading other users' data
        (item_id, user["user_id"], algo)).fetchone()
    if not row:
        abort(404)
    t0 = time.perf_counter()
    plain = ciphers.decrypt(algo, user["keys"][algo], row["iv"], row["data"])
    dec_ms = (time.perf_counter() - t0) * 1000
    resp = send_file(io.BytesIO(plain), mimetype=row["mime"], download_name=row["filename"])
    resp.headers["X-Decrypt-Ms"] = f"{dec_ms:.3f}"
    resp.headers["Cache-Control"] = "no-store"  # don't let the browser cache decrypted data
    return resp


@app.get("/")
def index():
    """Serve the single-page frontend."""
    return app.send_static_file("index.html")


with app.app_context():  # create tables on startup
    db().executescript(SCHEMA)

if __name__ == "__main__":
    app.run(debug=False, port=5000)
