import os
import re
import sqlite3
import secrets
from pathlib import Path
from functools import wraps

import boto3
from flask import (
    Flask, request, redirect, url_for, session,
    render_template_string, abort, flash, send_from_directory
)
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from botocore.config import Config

app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET_KEY", secrets.token_hex(32))

APP_DIR = Path(__file__).resolve().parent
UPLOAD_DIR = APP_DIR / "uploads"
UPLOAD_DIR.mkdir(exist_ok=True)

DATABASE = APP_DIR / "chillyfile.db"
MAX_FILE_MB = int(os.environ.get("CHILLYFILE_MAX_MB", "512"))
app.config["MAX_CONTENT_LENGTH"] = MAX_FILE_MB * 1024 * 1024

# Backblaze B2 uses its S3-compatible API.
# These variables must be configured in Render before cloud uploads are enabled.
B2_KEY_ID = os.environ.get("B2_KEY_ID")
B2_APPLICATION_KEY = os.environ.get("B2_APPLICATION_KEY")
B2_BUCKET_NAME = os.environ.get("B2_BUCKET_NAME")
B2_ENDPOINT_URL = os.environ.get("B2_ENDPOINT_URL")

b2 = None
if all([B2_KEY_ID, B2_APPLICATION_KEY, B2_BUCKET_NAME, B2_ENDPOINT_URL]):
    b2 = boto3.client(
        "s3",
        endpoint_url=B2_ENDPOINT_URL,
        aws_access_key_id=B2_KEY_ID,
        aws_secret_access_key=B2_APPLICATION_KEY,
        config=Config(signature_version="s3v4"),
    )


def db():
    connection = sqlite3.connect(DATABASE)
    connection.row_factory = sqlite3.Row
    return connection


def initialize_database():
    with db() as connection:
        connection.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        connection.execute("""
            CREATE TABLE IF NOT EXISTS posts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                content TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id)
            )
        """)
        connection.execute("""
            CREATE TABLE IF NOT EXISTS files (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                token TEXT UNIQUE NOT NULL,
                filename TEXT NOT NULL,
                storage_key TEXT NOT NULL,
                size INTEGER NOT NULL,
                uploader_id INTEGER NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (uploader_id) REFERENCES users(id)
            )
        """)


initialize_database()


def login_required(function):
    @wraps(function)
    def wrapper(*args, **kwargs):
        if "user_id" not in session:
            flash("Please log in first.")
            return redirect(url_for("login"))
        return function(*args, **kwargs)
    return wrapper


PAGE = """
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>ChillyFile.io</title>
<style>
* { box-sizing: border-box; }
body {
    margin: 0;
    background: #07111f;
    color: #eaf2ff;
    font-family: Arial, sans-serif;
}
header {
    padding: 20px;
    background: #0b1d35;
    border-bottom: 1px solid #203a5b;
}
nav {
    max-width: 900px;
    margin: auto;
    display: flex;
    justify-content: space-between;
    align-items: center;
    gap: 15px;
    flex-wrap: wrap;
}
.logo { color: #60c7ff; font-size: 25px; font-weight: bold; }
a { color: #60c7ff; text-decoration: none; }
a:hover { text-decoration: underline; }
nav a { margin-left: 12px; }
main { max-width: 800px; margin: 35px auto; padding: 0 16px; }
.card {
    background: #10243d;
    border: 1px solid #234362;
    border-radius: 14px;
    padding: 22px;
    margin-bottom: 20px;
}
h1, h2 { margin-top: 0; }
input, textarea, button {
    width: 100%;
    margin-top: 10px;
    padding: 12px;
    border-radius: 8px;
    border: 1px solid #355779;
    font: inherit;
}
input, textarea { background: #08182a; color: white; }
textarea { resize: vertical; min-height: 100px; }
button {
    background: #1688d4;
    color: white;
    font-weight: bold;
    border: 0;
    cursor: pointer;
}
button:hover { background: #0875bc; }
.muted { color: #a9bdd4; font-size: 14px; }
.message {
    padding: 12px;
    margin-bottom: 12px;
    background: #173653;
    border-radius: 8px;
}
.post { white-space: pre-wrap; overflow-wrap: anywhere; }
.file-row {
    padding: 14px 0;
    border-bottom: 1px solid #29425c;
    overflow-wrap: anywhere;
}
.file-row:last-child { border-bottom: 0; }
</style>
</head>
<body>
<header>
<nav>
<div class="logo">❄ ChillyFile.io</div>
<div>
<a href="/">Home</a>
{% if user %}
<a href="/upload">Upload</a>
<a href="/logout">Log out ({{ user }})</a>
{% else %}
<a href="/login">Log in</a>
<a href="/register">Sign up</a>
{% endif %}
</div>
</nav>
</header>
<main>
{% with messages = get_flashed_messages() %}
{% for message in messages %}
<div class="message">{{ message }}</div>
{% endfor %}
{% endwith %}
{{ content|safe }}
</main>
</body>
</html>
"""


def current_user():
    user_id = session.get("user_id")
    if not user_id:
        return None
    with db() as connection:
        user = connection.execute(
            "SELECT username FROM users WHERE id = ?", (user_id,)
        ).fetchone()
    return user["username"] if user else None


def render_page(content):
    return render_template_string(
        PAGE, content=content, user=current_user()
    )


@app.route("/")
def home():
    with db() as connection:
        posts = connection.execute("""
            SELECT posts.content, posts.created_at, users.username
            FROM posts JOIN users ON users.id = posts.user_id
            ORDER BY posts.id DESC LIMIT 100
        """).fetchall()

        files = connection.execute("""
            SELECT files.token, files.filename, files.size,
                   files.created_at, users.username
            FROM files JOIN users ON users.id = files.uploader_id
            ORDER BY files.id DESC LIMIT 100
        """).fetchall()

    post_html = "".join(
        f'<div class="card"><strong>{escape_html(p["username"])}</strong>'
        f'<p class="post">{escape_html(p["content"])}</p>'
        f'<div class="muted">{escape_html(p["created_at"])}</div></div>'
        for p in posts
    ) or '<div class="card">No posts yet. Be the first to post!</div>'

    file_html = "".join(
        f'<div class="file-row"><a href="/f/{escape_html(f["token"])}">'
        f'{escape_html(f["filename"])}</a>'
        f'<div class="muted">{format_size(f["size"])} · '
        f'Uploaded by {escape_html(f["username"])}</div></div>'
        for f in files
    ) or '<p class="muted">No files uploaded yet.</p>'

    create_post = ""
    if session.get("user_id"):
        create_post = """
        <div class="card">
        <h2>Create a public post</h2>
        <form method="post" action="/post">
        <textarea name="content" maxlength="3000"
        placeholder="What's on your mind?" required></textarea>
        <button type="submit">Publish post</button>
        </form></div>
        """

    content = f"""
    <div class="card">
    <h1>Welcome to ChillyFile.io ❄</h1>
    <p>Share files and post updates with the community.</p>
    {"<a href='/upload'>Upload a file</a>" if session.get("user_id") else "<a href='/register'>Create an account</a> to get started."}
    </div>
    {create_post}
    <h2>Recent public posts</h2>
    {post_html}
    <div class="card"><h2>Public files</h2>{file_html}</div>
    """
    return render_page(content)


def escape_html(value):
    from html import escape
    return escape(str(value), quote=True)


def format_size(size):
    if size < 1024:
        return f"{size} B"
    if size < 1024 * 1024:
        return f"{size / 1024:.1f} KB"
    if size < 1024 * 1024 * 1024:
        return f"{size / (1024 * 1024):.1f} MB"
    return f"{size / (1024 * 1024 * 1024):.2f} GB"


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        if not re.fullmatch(r"[A-Za-z0-9_]{3,24}", username):
            flash("Username must be 3–24 characters using letters, numbers, or underscores.")
            return redirect(url_for("register"))

        if len(password) < 10:
            flash("Password must be at least 10 characters.")
            return redirect(url_for("register"))

        try:
            with db() as connection:
                cursor = connection.execute(
                    "INSERT INTO users (username, password_hash) VALUES (?, ?)",
                    (username, generate_password_hash(password))
                )
                session.clear()
                session["user_id"] = cursor.lastrowid
            flash("Your account has been created!")
            return redirect(url_for("home"))
        except sqlite3.IntegrityError:
            flash("That username is already taken.")
            return redirect(url_for("register"))

    return render_page("""
    <div class="card"><h1>Create account</h1>
    <form method="post">
    <label>Username</label>
    <input name="username" minlength="3" maxlength="24"
    pattern="[A-Za-z0-9_]+" autocomplete="username" required>
    <label>Password (at least 10 characters)</label>
    <input type="password" name="password" minlength="10"
    autocomplete="new-password" required>
    <button type="submit">Sign up</button>
    </form></div>
    """)


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        with db() as connection:
            user = connection.execute(
                "SELECT id, password_hash FROM users WHERE username = ?",
                (username,)
            ).fetchone()

        if user and check_password_hash(user["password_hash"], password):
            session.clear()
            session["user_id"] = user["id"]
            flash("Logged in successfully.")
            return redirect(url_for("home"))

        flash("Incorrect username or password.")
        return redirect(url_for("login"))

    return render_page("""
    <div class="card"><h1>Log in</h1>
    <form method="post">
    <label>Username</label>
    <input name="username" autocomplete="username" required>
    <label>Password</label>
    <input type="password" name="password"
    autocomplete="current-password" required>
    <button type="submit">Log in</button>
    </form></div>
    """)


@app.route("/logout")
def logout():
    session.clear()
    flash("You have been logged out.")
    return redirect(url_for("home"))


@app.route("/post", methods=["POST"])
@login_required
def create_post():
    content = request.form.get("content", "").strip()
    if not content or len(content) > 3000:
        flash("Posts must contain 1–3000 characters.")
        return redirect(url_for("home"))

    with db() as connection:
        connection.execute(
            "INSERT INTO posts (user_id, content) VALUES (?, ?)",
            (session["user_id"], content)
        )
    flash("Your post is now public.")
    return redirect(url_for("home"))


@app.route("/upload", methods=["GET", "POST"])
@login_required
def upload():
    if request.method == "POST":
        uploaded = request.files.get("file")
        if not uploaded or not uploaded.filename:
            flash("Choose a file first.")
            return redirect(url_for("upload"))

        filename = secure_filename(uploaded.filename)
        if not filename:
            flash("That filename is not allowed.")
            return redirect(url_for("upload"))

        token = secrets.token_urlsafe(18)
        storage_key = f"{token}/{filename}"
        size = 0

        try:
            if b2:
                uploaded.stream.seek(0, os.SEEK_END)
                size = uploaded.stream.tell()
                uploaded.stream.seek(0)
                b2.upload_fileobj(
                    uploaded.stream,
                    B2_BUCKET_NAME,
                    storage_key,
                    ExtraArgs={"ContentType": uploaded.mimetype or "application/octet-stream"}
                )
            else:
                local_name = f"{token}__{filename}"
                local_path = UPLOAD_DIR / local_name
                uploaded.save(local_path)
                size = local_path.stat().st_size
                storage_key = local_name

            with db() as connection:
                connection.execute("""
                    INSERT INTO files
                    (token, filename, storage_key, size, uploader_id)
                    VALUES (?, ?, ?, ?, ?)
                """, (token, filename, storage_key, size, session["user_id"]))

        except Exception:
            app.logger.exception("Upload failed")
            flash("Upload failed. Check the server configuration and try again.")
            return redirect(url_for("upload"))

        flash("Upload complete!")
        return redirect(url_for("f", token=token))

    storage_message = (
        "Backblaze B2 cloud storage is configured."
        if b2 else
        "Cloud storage is not configured yet. This upload will use temporary local storage."
    )

    return render_page(f"""
    <div class="card"><h1>Upload a file</h1>
    <p class="muted">Maximum file size: {MAX_FILE_MB} MB</p>
    <p class="muted">{escape_html(storage_message)}</p>
    <form method="post" enctype="multipart/form-data">
    <input type="file" name="file" required>
    <button type="submit">Upload file</button>
    </form></div>
    """)


@app.route("/f/<token>")
def f(token):
    with db() as connection:
        file_record = connection.execute(
            "SELECT * FROM files WHERE token = ?", (token,)
        ).fetchone()

    if not file_record:
        abort(404)

    content = f"""
    <div class="card"><h1>Your file is ready</h1>
    <p>{escape_html(file_record["filename"])}</p>
    <p class="muted">{format_size(file_record["size"])}</p>
    <a href="/download/{escape_html(token)}"><button>Download file</button></a>
    </div>
    """
    return render_page(content)


@app.route("/download/<token>")
def download(token):
    with db() as connection:
        file_record = connection.execute(
            "SELECT * FROM files WHERE token = ?", (token,)
        ).fetchone()

    if not file_record:
        abort(404)

    if b2:
        try:
            response = b2.get_object(
                Bucket=B2_BUCKET_NAME,
                Key=file_record["storage_key"]
            )
            from flask import Response
            return Response(
                response["Body"].iter_chunks(chunk_size=1024 * 1024),
                headers={
                    "Content-Disposition": f'attachment; filename="{file_record["filename"]}"',
                    "Content-Type": response.get("ContentType", "application/octet-stream")
                }
            )
        except Exception:
            app.logger.exception("Download from B2 failed")
            abort(502)

    return send_from_directory(
        UPLOAD_DIR,
        file_record["storage_key"],
        as_attachment=True,
        download_name=file_record["filename"]
    )


@app.errorhandler(413)
def too_large(error):
    return render_page(
        f"<div class='card'><h1>File too large</h1>"
        f"<p>The maximum upload size is {MAX_FILE_MB} MB.</p></div>"
    ), 413


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", "5000")))
