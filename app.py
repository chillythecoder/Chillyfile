import os
import re
import io
import sqlite3
import secrets
from pathlib import Path
from datetime import timedelta
from functools import wraps
from html import escape
from urllib.parse import quote

import boto3
from flask import (
    Flask, request, redirect, url_for, session,
    render_template_string, abort, flash, send_from_directory,
    Response
)
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from botocore.config import Config

app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET_KEY", secrets.token_hex(32))

# Optional "Keep me logged in" sessions last 30 days by default.
# Set CHILLYFILE_REMEMBER_DAYS in your hosting environment to change this.
app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(
    days=max(1, int(os.environ.get("CHILLYFILE_REMEMBER_DAYS", "30")))
)
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"

APP_DIR = Path(__file__).resolve().parent
UPLOAD_DIR = APP_DIR / "uploads"
UPLOAD_DIR.mkdir(exist_ok=True)

DATABASE = APP_DIR / "chillyfile.db"
MAX_FILE_MB = int(os.environ.get("CHILLYFILE_MAX_MB", "512"))
MAX_AVATAR_MB = 5

app.config["MAX_CONTENT_LENGTH"] = MAX_FILE_MB * 1024 * 1024

# Backblaze B2 configuration
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


# --------------------------------------------------
# DATABASE AND MIGRATIONS
# --------------------------------------------------

def db():
    connection = sqlite3.connect(DATABASE, timeout=30)
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

        connection.execute("""
            CREATE TABLE IF NOT EXISTS folders (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                token TEXT UNIQUE NOT NULL,
                name TEXT NOT NULL,
                owner_id INTEGER NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (owner_id) REFERENCES users(id)
            )
        """)

        # Follow relationships are stored separately and safely added to existing databases.
        connection.execute("""
            CREATE TABLE IF NOT EXISTS followers (
                follower_id INTEGER NOT NULL,
                followed_id INTEGER NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                PRIMARY KEY (follower_id, followed_id),
                FOREIGN KEY (follower_id) REFERENCES users(id),
                FOREIGN KEY (followed_id) REFERENCES users(id),
                CHECK (follower_id != followed_id)
            )
        """)
        connection.execute("CREATE INDEX IF NOT EXISTS idx_followers_followed ON followers(followed_id)")
        connection.execute("CREATE INDEX IF NOT EXISTS idx_followers_follower ON followers(follower_id)")

        # Add new columns without deleting existing records.
        user_columns = {
            row["name"]
            for row in connection.execute("PRAGMA table_info(users)")
        }

        if "profile_picture" not in user_columns:
            connection.execute(
                "ALTER TABLE users ADD COLUMN profile_picture TEXT"
            )

        if "role" not in user_columns:
            connection.execute(
                "ALTER TABLE users ADD COLUMN role TEXT NOT NULL DEFAULT 'member'"
            )

        if "player_id" not in user_columns:
            connection.execute("ALTER TABLE users ADD COLUMN player_id TEXT")

        # Ensure the existing @Chilly account is the site Owner.
        # This only changes roles; it never deletes users, posts, files, or folders.
        chilly_user = connection.execute(
            "SELECT id FROM users WHERE username = ? COLLATE NOCASE",
            (os.environ.get("CHILLYFILE_OWNER_USERNAME", "Chilly"),)
        ).fetchone()
        if chilly_user:
            connection.execute(
                "UPDATE users SET role = 'admin' WHERE role = 'owner' AND id != ?",
                (chilly_user["id"],)
            )
            connection.execute(
                "UPDATE users SET role = 'owner' WHERE id = ?",
                (chilly_user["id"],)
            )

        # Optional owner bootstrap/reset controlled only through Render environment
        # variables. Never place the owner's password in source code or GitHub.
        owner_username = os.environ.get("CHILLYFILE_OWNER_USERNAME", "Chilly").strip()
        owner_password = os.environ.get("CHILLYFILE_OWNER_PASSWORD", "")
        if owner_password:
            if len(owner_password) < 12:
                raise RuntimeError("CHILLYFILE_OWNER_PASSWORD must be at least 12 characters.")
            owner_record = connection.execute(
                "SELECT id FROM users WHERE username = ? COLLATE NOCASE",
                (owner_username,)
            ).fetchone()
            hashed_owner_password = generate_password_hash(owner_password)
            if owner_record:
                connection.execute(
                    "UPDATE users SET password_hash = ?, role = 'owner' WHERE id = ?",
                    (hashed_owner_password, owner_record["id"])
                )
            else:
                connection.execute(
                    "INSERT INTO users (username, password_hash, role) VALUES (?, ?, 'owner')",
                    (owner_username, hashed_owner_password)
                )

        # Assign stable public Player IDs to every existing account that lacks one.
        # The numeric database ID is already unique, so these IDs remain unique too.
        account_rows = connection.execute(
            "SELECT id FROM users WHERE player_id IS NULL OR player_id = ''"
        ).fetchall()
        for account_row in account_rows:
            connection.execute(
                "UPDATE users SET player_id = ? WHERE id = ?",
                (f"CF-{int(account_row['id']):06d}", account_row["id"])
            )
        connection.execute(
            "CREATE UNIQUE INDEX IF NOT EXISTS idx_users_player_id ON users(player_id)"
        )

        file_columns = {
            row["name"]
            for row in connection.execute("PRAGMA table_info(files)")
        }

        if "folder_id" not in file_columns:
            connection.execute(
                "ALTER TABLE files ADD COLUMN folder_id INTEGER"
            )

        # Give existing files folders while preserving their file tokens.
        existing_files = connection.execute("""
            SELECT id, token, filename, uploader_id
            FROM files
            WHERE folder_id IS NULL
        """).fetchall()

        for file_record in existing_files:
            folder_token = secrets.token_urlsafe(18)
            folder_name = Path(file_record["filename"]).stem or "My Folder"

            cursor = connection.execute("""
                INSERT INTO folders (token, name, owner_id)
                VALUES (?, ?, ?)
            """, (
                folder_token,
                folder_name,
                file_record["uploader_id"]
            ))

            connection.execute("""
                UPDATE files
                SET folder_id = ?
                WHERE id = ?
            """, (cursor.lastrowid, file_record["id"]))


initialize_database()


# --------------------------------------------------
# HELPERS
# --------------------------------------------------

def login_required(function):
    @wraps(function)
    def wrapper(*args, **kwargs):
        if not session.get("user_id"):
            flash("Please log in first.")
            return redirect(url_for("login"))
        return function(*args, **kwargs)
    return wrapper


def owner_required(function):
    @wraps(function)
    @login_required
    def wrapper(*args, **kwargs):
        user = current_user()
        if not user or user["role"] != "owner":
            abort(403)
        return function(*args, **kwargs)
    return wrapper


ROLE_INFO = {
    "owner": ("Owner", "Owner"),
    "admin": ("Admin", "Admin"),
    "community_manager": ("Moderator", "Moderator"),
    "discord_member": ("Discord Member", "Discord Member"),
    "chilly_friend": ("Chilly’s Friend", "Chilly’s Friend"),
    "member": ("Member", "Member"),
}

ASSIGNABLE_ROLES = {
    "admin": "Admin",
    "community_manager": "Community Manager",
    "discord_member": "Discord Member",
    "chilly_friend": "Chilly’s Friend",
    "member": "Member",
}


def role_badge(role):
    badge_text, label = ROLE_INFO.get(role or "member", ROLE_INFO["member"])
    css_role = re.sub(r"[^a-z_]", "", role or "member")
    return (f'<span class="role-badge role-{css_role}" '
            f'title="{escape_html(label)}">{escape_html(badge_text)}</span>')


def avatar_markup(user_id, picture, username, css_class="small-avatar"):
    if picture:
        return f'<img class="{css_class}" src="/avatar/{int(user_id)}" alt="{escape_html(username)} profile picture">'
    initial = (str(username or "?").strip()[:1] or "?").upper()
    return f'<span class="{css_class} avatar-fallback" aria-label="{escape_html(username)} avatar">{escape_html(initial)}</span>'


def user_label(username, role="member"):
    return f'{escape_html(username)} {role_badge(role)}'


def escape_html(value):
    return escape(str(value), quote=True)


def format_size(size):
    if size < 1024:
        return f"{size} B"
    if size < 1024 ** 2:
        return f"{size / 1024:.1f} KB"
    if size < 1024 ** 3:
        return f"{size / 1024 ** 2:.1f} MB"
    return f"{size / 1024 ** 3:.2f} GB"


def current_user():
    user_id = session.get("user_id")

    if not user_id:
        return None

    with db() as connection:
        return connection.execute(
            "SELECT * FROM users WHERE id = ?",
            (user_id,)
        ).fetchone()


def render_page(content, title="ChillyFile.io"):
    return render_template_string(
        PAGE,
        content=content,
        user=current_user(),
        title=title,
        role_badge=role_badge
    )


def get_file(token):
    with db() as connection:
        return connection.execute(
            "SELECT * FROM files WHERE token = ?",
            (token,)
        ).fetchone()


def get_folder(token):
    with db() as connection:
        return connection.execute(
            "SELECT * FROM folders WHERE token = ?",
            (token,)
        ).fetchone()


def store_object(key, file_object, content_type):
    if not b2:
        raise RuntimeError(
            "Backblaze B2 is not configured. Check Render environment variables."
        )

    b2.upload_fileobj(
        file_object,
        B2_BUCKET_NAME,
        key,
        ExtraArgs={
            "ContentType": content_type or "application/octet-stream"
        }
    )


def object_response(key, download_name=None):
    if not b2:
        abort(404)

    try:
        result = b2.get_object(
            Bucket=B2_BUCKET_NAME,
            Key=key
        )

        headers = {
            "Content-Type": result.get(
                "ContentType",
                "application/octet-stream"
            )
        }

        if download_name:
            safe_name = secure_filename(download_name) or "download"
            headers["Content-Disposition"] = (
                f"attachment; filename*=UTF-8''{quote(safe_name)}"
            )

        return Response(
            result["Body"].iter_chunks(chunk_size=1024 * 1024),
            headers=headers
        )

    except Exception:
        app.logger.exception("Cloud object retrieval failed")
        abort(502)


# --------------------------------------------------
# DESIGN
# --------------------------------------------------

PAGE = """
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">

<title>{{ title }}</title>

<style>
:root {
    --background: #05070b;
    --panel: #0c111b;
    --panel2: #101a2a;
    --border: #1c2e49;
    --blue: #168cff;
    --blue2: #0866d6;
    --text: #f3f7ff;
    --muted: #94a7c1;
}

* { box-sizing: border-box; }

body {
    margin: 0;
    background: var(--background);
    color: var(--text);
    font-family: Arial, sans-serif;
    min-height: 100vh;
}

header {
    background: #080c13;
    border-bottom: 1px solid var(--border);
    position: sticky;
    top: 0;
    z-index: 5;
}

nav {
    max-width: 1100px;
    margin: auto;
    padding: 15px 20px;
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 15px;
    flex-wrap: wrap;
}

.logo {
    font-size: 23px;
    font-weight: 800;
    color: white;
}

.logo span { color: var(--blue); }

nav a, a {
    color: #68b5ff;
    text-decoration: none;
}

nav a {
    margin-left: 15px;
}

a:hover { color: white; }

main {
    max-width: 1000px;
    margin: 30px auto;
    padding: 0 18px 50px;
}

.card {
    background: var(--panel);
    border: 1px solid var(--border);
    border-radius: 13px;
    padding: 22px;
    margin-bottom: 18px;
}

h1 { font-size: 27px; }
h1, h2, h3 { margin-top: 0; }

.muted {
    color: var(--muted);
    font-size: 13px;
}

button, .button {
    display: inline-block;
    background: var(--blue2);
    color: white;
    border: 0;
    border-radius: 8px;
    padding: 11px 16px;
    margin-top: 10px;
    font-size: 14px;
    font-weight: bold;
    cursor: pointer;
    text-decoration: none;
}

button:hover, .button:hover {
    background: var(--blue);
    color: white;
}

input, textarea {
    display: block;
    width: 100%;
    background: #070b12;
    color: white;
    border: 1px solid #263c5b;
    border-radius: 8px;
    padding: 12px;
    margin: 9px 0 15px;
    font: inherit;
}

textarea {
    min-height: 100px;
    resize: vertical;
}

label {
    font-size: 14px;
    color: #bdcce0;
}

.message {
    background: #102b4b;
    border: 1px solid #1d5790;
    border-radius: 9px;
    padding: 12px;
    margin-bottom: 15px;
}

.upload-box {
    text-align: center;
    padding: 38px 20px;
    border: 2px dashed #244a76;
    border-radius: 12px;
    background: #080e19;
}

.upload-box input {
    max-width: 400px;
    margin: 20px auto 10px;
}

.section-title {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 10px;
}

.file-row {
    display: flex;
    justify-content: space-between;
    align-items: center;
    gap: 15px;
    padding: 15px 0;
    border-bottom: 1px solid #1b2a40;
    overflow-wrap: anywhere;
}

.file-row:last-child { border-bottom: 0; }
.folder-mark { display:inline-block; width:19px; height:13px; margin-right:9px; position:relative; border:1px solid #5aa9ff; border-radius:3px; background:#102b49; vertical-align:middle; }
.folder-mark:before { content:""; position:absolute; top:-5px; left:1px; width:8px; height:4px; border:1px solid #5aa9ff; border-bottom:0; border-radius:3px 3px 0 0; background:#102b49; }

.file-actions {
    display: flex;
    align-items: center;
    gap: 8px;
    flex-wrap: wrap;
}

.file-actions form { margin: 0; }

.file-actions button {
    margin: 0;
}

.profile {
    display: flex;
    align-items: center;
    gap: 18px;
    flex-wrap: wrap;
}

.avatar {
    width: 76px;
    height: 76px;
    border-radius: 50%;
    object-fit: cover;
    background: #14243a;
    border: 2px solid #267fe0;
}

.small-avatar {
    width: 35px;
    height: 35px;
    border-radius: 50%;
    object-fit: cover;
    vertical-align: middle;
    background: #14243a;
}

.post {
    white-space: pre-wrap;
    overflow-wrap: anywhere;
    line-height: 1.5;
}

.role-badge {
    display: inline-flex; align-items: center; justify-content: center;
    margin-left: 5px; padding: 3px 8px; border-radius: 999px;
    border: 1px solid #275b8e; background: #102a45; color: #a9d7ff;
    font-size: 11px; font-weight: 700; vertical-align: middle; white-space: nowrap;
}
.role-owner { background: #16365c; border-color: #4ba5ff; color: #d5ecff; }
.role-admin { background: #202a3c; border-color: #6c85a9; color: #e1eaff; }
.role-community_manager { background: #173d37; border-color: #2e9c82; color: #b7ffed; }
.avatar-fallback { display: inline-flex; align-items: center; justify-content: center; font-weight: 800; color: #d8ecff; }
.post-head { display:flex; align-items:center; gap:11px; margin-bottom:12px; }
.post-head .small-avatar { flex: 0 0 auto; }
.post-card { padding:18px; }

.nav-shell { max-width:1100px; margin:auto; padding:12px 18px; display:flex; align-items:center; gap:14px; }
.menu-button { margin:0; width:42px; height:42px; padding:8px; background:#101a2a; border:1px solid #29405e; display:grid; place-items:center; }
.hamburger { width:20px; height:14px; display:flex; flex-direction:column; justify-content:space-between; }
.hamburger span { height:2px; width:100%; background:#eaf4ff; border-radius:2px; }
.logo { margin-right:auto; }
.nav-user { display:flex; align-items:center; gap:8px; color:#eaf4ff; }
.drawer-backdrop { position:fixed; inset:0; z-index:19; background:#0009; display:none; }
.drawer { position:fixed; z-index:20; top:0; left:0; height:100vh; width:min(310px,86vw); padding:22px; background:#080d16; border-right:1px solid var(--border); transform:translateX(-105%); transition:transform .2s ease; box-shadow:12px 0 40px #0008; }
.drawer.open { transform:translateX(0); }
.drawer-backdrop.open { display:block; }
.drawer-head { display:flex; align-items:center; justify-content:space-between; margin-bottom:22px; }
.drawer-links { display:flex; flex-direction:column; gap:5px; }
.drawer-links a { display:block; margin:0; padding:13px 12px; border-radius:9px; color:#d9e9ff; background:#0d1522; }
.drawer-links a:hover { background:#142640; }
.admin-table { width: 100%; border-collapse: collapse; }
.admin-table th, .admin-table td {
    padding: 12px 8px;
    border-bottom: 1px solid var(--border);
    text-align: left;
    overflow-wrap: anywhere;
}
.admin-table select {
    background: #070b12;
    color: white;
    border: 1px solid #263c5b;
    border-radius: 8px;
    padding: 9px;
    max-width: 100%;
}
.admin-table button { margin-top: 0; }

.inline-form { display: inline; }

footer {
    text-align: center;
    padding: 25px;
    color: #65758d;
    font-size: 12px;
}

@media(max-width: 600px) {
    nav { padding: 13px; }
    nav a { margin-left: 8px; }
    main { margin-top: 18px; padding: 0 12px 30px; }
    .card { padding: 17px; }
    .file-row { align-items: flex-start; flex-direction: column; }
}
</style>
</head>

<body>
<header>
<div class="nav-shell">
    <button class="menu-button" type="button" id="menuToggle" aria-label="Open navigation menu" aria-expanded="false">
        <span class="hamburger" aria-hidden="true"><span></span><span></span><span></span></span>
    </button>
    <a class="logo" href="/">Chilly<span>File</span></a>
    {% if user %}
      <a class="nav-user" href="/account">{% if user['profile_picture'] %}<img class="small-avatar" src="/avatar/{{ user['id'] }}" alt="">{% else %}<span class="small-avatar avatar-fallback">{{ user['username'][0]|upper }}</span>{% endif %}<span>{{ user['username'] }}</span>{{ role_badge(user['role'])|safe }}</a>
    {% else %}<a class="button" href="/login">Log in</a>{% endif %}
</div>
</header>
<div class="drawer-backdrop" id="drawerBackdrop"></div>
<aside class="drawer" id="siteDrawer" aria-label="Main navigation">
  <div class="drawer-head"><a class="logo" href="/">Chilly<span>File</span></a><button class="menu-button" type="button" id="menuClose" aria-label="Close navigation menu">✕</button></div>
  <div class="drawer-links">
    <a href="/">Files</a>
    <a href="/discover">Discover</a>
    <a href="/search">Search People &amp; Folders</a>
    {% if user %}
      <a href="/account">My Profile &amp; Files</a>
      <a href="/edit-profile">Edit Profile</a>
      <a href="/upload">Upload Files</a>
      {% if user['role'] == 'owner' %}<a href="/admin">Owner Console &amp; Badges</a>{% endif %}
      <a href="/logout">Log out</a>
    {% else %}
      <a href="/login">Log in</a><a href="/register">Create account</a>
    {% endif %}
  </div>
</aside>
<script>
(() => {
 const drawer=document.getElementById('siteDrawer');
 const backdrop=document.getElementById('drawerBackdrop');
 const toggle=document.getElementById('menuToggle');
 const close=document.getElementById('menuClose');
 function setOpen(open){drawer.classList.toggle('open',open);backdrop.classList.toggle('open',open);toggle.setAttribute('aria-expanded',String(open));}
 toggle.addEventListener('click',()=>setOpen(!drawer.classList.contains('open')));
 close.addEventListener('click',()=>setOpen(false));
 backdrop.addEventListener('click',()=>setOpen(false));
 document.addEventListener('keydown',e=>{if(e.key==='Escape')setOpen(false)});
})();
</script>

<main>
{% with messages = get_flashed_messages() %}
{% for message in messages %}
<div class="message">{{ message }}</div>
{% endfor %}
{% endwith %}

{{ content|safe }}
</main>

<footer>ChillyFile.io · File sharing and community</footer>
</body>
</html>
"""


# --------------------------------------------------
# HOME / PUBLIC FILES
# --------------------------------------------------

@app.route("/")
def home():
    with db() as connection:
        files = connection.execute("""
            SELECT files.*, users.username, users.role
            FROM files
            JOIN users ON users.id = files.uploader_id
            ORDER BY files.id DESC
            LIMIT 100
        """).fetchall()

    rows = ""

    for file_record in files:
        rows += f"""
        <div class="file-row">
            <div>
                <a href="/f/{escape_html(file_record['token'])}">
                    {escape_html(file_record['filename'])}
                </a>
                <div class="muted">
                    {format_size(file_record['size'])}
                    · Uploaded by <a href="/profile/{escape_html(file_record['username'])}">{user_label(file_record['username'], file_record['role'])}</a>
                </div>
            </div>
            <a class="button"
               href="/f/{escape_html(file_record['token'])}">
               Open
            </a>
        </div>
        """

    if not rows:
        rows = '<p class="muted">No public files yet.</p>'

    if session.get("user_id"):
        upload_link = '<a class="button" href="/upload">Upload files</a>'
    else:
        upload_link = '<a class="button" href="/register">Create account</a>'

    content = f"""
    <div class="card">
        <div class="upload-box">
            <h1>Share files.</h1>
            <p class="muted">
                Upload files and share them with a link.
            </p>
            {upload_link}
        </div>
    </div>

    <div class="card">
        <div class="section-title">
            <h2>Public Files</h2>
            <span class="muted">Latest uploads</span>
        </div>
        {rows}
    </div>
    """

    return render_page(content, "ChillyFile.io")


# --------------------------------------------------
# REGISTRATION / LOGIN
# --------------------------------------------------

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        if not re.fullmatch(r"[A-Za-z0-9_]{3,24}", username):
            flash("Usernames must be 3–24 letters, numbers, or underscores.")
            return redirect(url_for("register"))

        if len(password) < 10:
            flash("Your password must be at least 10 characters.")
            return redirect(url_for("register"))

        try:
            with db() as connection:
                existing = connection.execute(
                    "SELECT id FROM users WHERE username = ? COLLATE NOCASE",
                    (username,)
                ).fetchone()
                if existing:
                    flash("That username is already taken.")
                    return redirect(url_for("register"))

                cursor = connection.execute("""
                    INSERT INTO users (username, password_hash, role)
                    VALUES (?, ?, 'member')
                """, (
                    username,
                    generate_password_hash(password)
                ))

                session.clear()
                session["user_id"] = cursor.lastrowid

            flash("Account created successfully!")
            return redirect(url_for("account"))

        except sqlite3.IntegrityError:
            flash("That username is already taken.")
            return redirect(url_for("register"))

    return render_page("""
    <div class="card">
        <h1>Create account</h1>
        <form method="post">
            <label>Username</label>
            <input name="username" minlength="3" maxlength="24"
                   pattern="[A-Za-z0-9_]+" required>

            <label>Password (at least 10 characters)</label>
            <input type="password" name="password"
                   minlength="10" required>

            <button type="submit">Create account</button>
        </form>
    </div>
    """)


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        with db() as connection:
            user = connection.execute("""
                SELECT id, password_hash
                FROM users
                WHERE username = ? COLLATE NOCASE
            """, (username,)).fetchone()

        if user and check_password_hash(user["password_hash"], password):
            session.clear()
            # The checkbox makes the session cookie persistent for the configured period.
            session.permanent = request.form.get("remember_me") == "yes"
            session["user_id"] = user["id"]
            flash(
                "Logged in. You’ll stay signed in on this device."
                if session.permanent
                else "Logged in successfully."
            )
            return redirect(url_for("account"))

        flash("Incorrect username or password.")
        return redirect(url_for("login"))

    return render_page("""
    <div class="card">
        <h1>Log in</h1>
        <form method="post">
            <label>Username</label>
            <input name="username" autocomplete="username" required>

            <label>Password</label>
            <input type="password" name="password"
                   autocomplete="current-password" required>

            <label style="display:flex;align-items:center;gap:9px;margin:8px 0 14px">
                <input type="checkbox" name="remember_me" value="yes"
                       style="width:auto;margin:0">
                Keep me logged in on this device (up to 30 days)
            </label>

            <button type="submit">Log in</button>
        </form>
        <div style="border-top:1px solid var(--border, #ddd);margin-top:20px;padding-top:16px;text-align:center">
            <a class="button" href="/register" style="display:inline-block;text-decoration:none">👤 Create an Account</a>
            <p class="muted" style="margin:10px 0 0">New to ChillyFile? Create your free account.</p>
        </div>
    </div>
    """)


@app.route("/logout")
def logout():
    session.clear()
    flash("You have been logged out.")
    return redirect(url_for("home"))


# --------------------------------------------------
# ACCOUNT / PROFILE
# --------------------------------------------------

@app.route("/account")
@login_required
def account():
    user = current_user()

    with db() as connection:
        files = connection.execute("""
            SELECT files.*, folders.token AS folder_token,
                   folders.name AS folder_name
            FROM files
            LEFT JOIN folders ON folders.id = files.folder_id
            WHERE files.uploader_id = ?
            ORDER BY files.id DESC
        """, (user["id"],)).fetchall()

        posts = connection.execute("""
            SELECT *
            FROM posts
            WHERE user_id = ?
            ORDER BY id DESC
        """, (user["id"],)).fetchall()

    if user["profile_picture"]:
        picture = f'<img class="avatar" src="/avatar/{user["id"]}" alt="Profile picture">'
    else:
        picture = f'<span class="avatar avatar-fallback">{escape_html(user["username"][:1].upper())}</span>'

    file_rows = ""

    for f in files:
        file_rows += f"""
        <div class="file-row">
            <div>
                <a href="/f/{escape_html(f['token'])}">
                    {escape_html(f['filename'])}
                </a>
                <div class="muted">{format_size(f['size'])}</div>
            </div>
            <div class="file-actions">
                <a class="button"
                   href="/folder/{escape_html(f['folder_token'])}">
                   Open Folder
                </a>
                <a href="/rename-file/{escape_html(f['token'])}">Rename</a>
            </div>
        </div>
        """

    if not file_rows:
        file_rows = '<p class="muted">You have not uploaded any files yet.</p>'

    post_rows = ""

    for p in posts:
        own_avatar = avatar_markup(user['id'], user['profile_picture'], user['username'])
        post_rows += f"""
        <div class="card post-card">
            <div class="post-head">{own_avatar}<div><strong>@{escape_html(user['username'])}</strong> {role_badge(user['role'])}<div class="muted">{escape_html(p['created_at'])}</div></div></div>
            <p class="post">{escape_html(p['content'])}</p>
            <form method="post" action="/delete-post/{p['id']}"
                  onsubmit="return confirm('Delete this post?')">
                <button type="submit">Delete Post</button>
            </form>
        </div>
        """

    if not post_rows:
        post_rows = '<p class="muted">You have not published any posts yet.</p>'

    content = f"""
    <div class="card">
        <div class="profile">
            {picture}
            <div>
                <h1>{user_label(user['username'], user['role'])}</h1>
                <p class="muted">Your ChillyFile account</p>
                <p><strong>Player ID:</strong> {escape_html(user['player_id'] or f"CF-{int(user['id']):06d}")}</p>
                <a class="button" href="/edit-profile">Edit Profile</a>
                <a class="button" href="/upload">Upload Files</a>
            </div>
        </div>
    </div>

    <div class="card">
        <h2>My Files</h2>
        {file_rows}
    </div>

    <div class="card">
        <h2>My Posts</h2>
        <form method="post" action="/post">
            <textarea name="content" maxlength="3000"
                      placeholder="Share an update..." required></textarea>
            <button type="submit">Publish Post</button>
        </form>
    </div>

    {post_rows}
    """

    return render_page(content, "My Account")


@app.route("/edit-profile", methods=["GET", "POST"])
@login_required
def edit_profile():
    user = current_user()

    if request.method == "POST":
        username = request.form.get("username", "").strip()

        if not re.fullmatch(r"[A-Za-z0-9_]{3,24}", username):
            flash("Username must be 3–24 letters, numbers, or underscores.")
            return redirect(url_for("edit_profile"))

        with db() as connection:
            existing = connection.execute("""
                SELECT id FROM users
                WHERE username = ? COLLATE NOCASE AND id != ?
            """, (username, user["id"])).fetchone()

            if existing:
                flash("That username is already taken.")
                return redirect(url_for("edit_profile"))

            connection.execute("""
                UPDATE users SET username = ?
                WHERE id = ?
            """, (username, user["id"]))

        picture = request.files.get("picture")

        if picture and picture.filename:
            extension = Path(picture.filename).suffix.lower()

            allowed = {".png", ".jpg", ".jpeg", ".webp", ".gif"}

            if extension not in allowed:
                flash("Use a PNG, JPG, WEBP, or GIF profile picture.")
                return redirect(url_for("edit_profile"))

            data = picture.read(MAX_AVATAR_MB * 1024 * 1024 + 1)

            if len(data) > MAX_AVATAR_MB * 1024 * 1024:
                flash("Profile pictures must be 5 MB or smaller.")
                return redirect(url_for("edit_profile"))

            content_type = picture.mimetype or "application/octet-stream"

            if not content_type.startswith("image/"):
                flash("Please upload an image file.")
                return redirect(url_for("edit_profile"))

            key = f"avatars/{user['id']}/{secrets.token_hex(12)}{extension}"

            try:
                if b2:
                    store_object(key, io.BytesIO(data), content_type)
                else:
                    key = f"avatar_{user['id']}_{secrets.token_hex(8)}{extension}"
                    with open(UPLOAD_DIR / key, "wb") as output:
                        output.write(data)

                with db() as connection:
                    connection.execute("""
                        UPDATE users SET profile_picture = ?
                        WHERE id = ?
                    """, (key, user["id"]))

            except Exception:
                app.logger.exception("Profile picture upload failed")
                flash("Could not upload the profile picture.")
                return redirect(url_for("edit_profile"))

        flash("Profile updated!")
        return redirect(url_for("account"))

    return render_page(f"""
    <div class="card">
        <h1>Edit Profile</h1>
        <form method="post" enctype="multipart/form-data">
            <label>Username</label>
            <input name="username"
                   minlength="3" maxlength="24"
                   value="{escape_html(user['username'])}" required>

            <label>Profile picture</label>
            <input type="file" name="picture"
                   accept="image/png,image/jpeg,image/webp,image/gif">

            <p class="muted">PNG, JPG, WEBP, or animated GIF · maximum 5 MB. GIF animations are supported.</p>

            <button type="submit">Save Changes</button>
        </form>
    </div>
    """)


@app.route("/avatar/<int:user_id>")
def avatar(user_id):
    with db() as connection:
        user = connection.execute("""
            SELECT profile_picture FROM users WHERE id = ?
        """, (user_id,)).fetchone()

    if not user or not user["profile_picture"]:
        abort(404)

    key = user["profile_picture"]

    if b2 and key.startswith("avatars/"):
        return object_response(key)

    return send_from_directory(UPLOAD_DIR, key)


@app.route("/profile/<username>")
def public_profile(username):
    # Profiles are only visible to visitors who have created an account and are signed in.
    if not session.get("user_id"):
        flash("Create a ChillyFile account to view profiles.")
        return redirect(url_for("register"))

    viewer_id = session.get("user_id")
    if viewer_id is not None:
        viewer_id = int(viewer_id)
    with db() as connection:
        user = connection.execute("""
            SELECT * FROM users WHERE username = ? COLLATE NOCASE
        """, (username,)).fetchone()

        if not user:
            abort(404)

        posts = connection.execute("""
            SELECT * FROM posts
            WHERE user_id = ?
            ORDER BY id DESC
        """, (user["id"],)).fetchall()

        files = connection.execute("""
            SELECT * FROM files
            WHERE uploader_id = ?
            ORDER BY id DESC
        """, (user["id"],)).fetchall()

        follower_count = connection.execute(
            "SELECT COUNT(*) FROM followers WHERE followed_id = ?", (user["id"],)
        ).fetchone()[0]
        following_count = connection.execute(
            "SELECT COUNT(*) FROM followers WHERE follower_id = ?", (user["id"],)
        ).fetchone()[0]
        is_following = False
        if viewer_id and viewer_id != user["id"]:
            is_following = connection.execute(
                "SELECT 1 FROM followers WHERE follower_id = ? AND followed_id = ?",
                (viewer_id, user["id"])
            ).fetchone() is not None

    profile_avatar = avatar_markup(user['id'], user['profile_picture'], user['username'], 'avatar')
    follow_button = ""
    if viewer_id and viewer_id != user["id"]:
        button_text = "Unfollow" if is_following else "Follow"
        follow_button = (f'<form method="post" action="/follow/{user["id"]}" style="margin-top:10px">'
                         f'<button type="submit">{button_text}</button></form>')
    elif not viewer_id:
        follow_button = '<p class="muted"><a href="/login">Log in</a> to follow this person.</p>'

    post_rows = "".join(
        f'<div class="card"><div class="muted">{user_label(user["username"], user["role"])} · '
        f'{escape_html(p["created_at"])}</div>'
        f'<p class="post">{escape_html(p["content"])}</p></div>'
        for p in posts
    ) or '<p class="muted">No public posts yet.</p>'

    file_rows = "".join(
        f'<div class="file-row"><div><a href="/f/{escape_html(f["token"])}">'
        f'{escape_html(f["filename"])}</a>'
        f'<div class="muted">{format_size(f["size"])}</div></div></div>'
        for f in files
    ) or '<p class="muted">No public files.</p>'

    content = f"""
    <div class="card"><div class="profile">
        {profile_avatar}
        <div><h1>{user_label(user['username'], user['role'])}</h1>
        <p class="muted">Public profile</p>
        <p><strong>{follower_count}</strong> followers · <strong>{following_count}</strong> following</p>
        {follow_button}</div>
    </div></div>
    <h2>Public Posts</h2>
    {post_rows}
    <div class="card">
        <h2>Public Files</h2>
        {file_rows}
    </div>
    """

    return render_page(content, f"{user['username']} - ChillyFile")


@app.route("/follow/<int:target_id>", methods=["POST"])
@login_required
def toggle_follow(target_id):
    viewer_id = int(session["user_id"])
    if viewer_id == target_id:
        flash("You cannot follow your own account.")
        return redirect(url_for("account"))

    with db() as connection:
        target = connection.execute(
            "SELECT username FROM users WHERE id = ?", (target_id,)
        ).fetchone()
        if not target:
            abort(404)
        existing = connection.execute(
            "SELECT 1 FROM followers WHERE follower_id = ? AND followed_id = ?",
            (viewer_id, target_id)
        ).fetchone()
        if existing:
            connection.execute(
                "DELETE FROM followers WHERE follower_id = ? AND followed_id = ?",
                (viewer_id, target_id)
            )
            flash(f"You unfollowed @{target['username']}.")
        else:
            connection.execute(
                "INSERT OR IGNORE INTO followers (follower_id, followed_id) VALUES (?, ?)",
                (viewer_id, target_id)
            )
            flash(f"You are now following @{target['username']}!")

    return redirect(url_for("public_profile", username=target["username"]))


@app.route("/search")
def search():
    query = request.args.get("q", "").strip()[:100]
    people = []
    folders = []
    if query:
        pattern = f"%{query}%"
        with db() as connection:
            # Simple substring search avoids SQLite ESCAPE-string compatibility issues.
            search_pattern = f"%{query}%"
            people = connection.execute("""
                SELECT id, username, role, profile_picture
                FROM users
                WHERE username LIKE ? COLLATE NOCASE
                ORDER BY username COLLATE NOCASE
                LIMIT 50
            """, (search_pattern,)).fetchall()
            folders = connection.execute("""
                SELECT folders.token, folders.name, folders.created_at, users.username
                FROM folders JOIN users ON users.id = folders.owner_id
                WHERE folders.name LIKE ? COLLATE NOCASE
                ORDER BY folders.id DESC
                LIMIT 50
            """, (search_pattern,)).fetchall()

    people_rows = "".join(
        f'<div class="file-row"><div>{avatar_markup(person["id"], person["profile_picture"], person["username"])} '
        f'<a href="/profile/{escape_html(person["username"])}"><strong>@{escape_html(person["username"])}</strong></a>'
        f' {role_badge(person["role"])}<div class="muted">Open profile to follow</div></div></div>'
        for person in people
    ) or ('<p class="muted">No people found.</p>' if query else '<p class="muted">Enter a username to search.</p>')

    folder_rows = "".join(
        f'<div class="file-row"><div><span class="folder-mark" aria-hidden="true"></span>'
        f'<a href="/folder/{escape_html(folder["token"])}"><strong>{escape_html(folder["name"])}</strong></a>'
        f'<div class="muted">Shared by <a href="/profile/{escape_html(folder["username"])}">@{escape_html(folder["username"])}</a>'
        f' · {escape_html(folder["created_at"])}</div></div></div>'
        for folder in folders
    ) or ('<p class="muted">No folders found.</p>' if query else '<p class="muted">Enter a folder name to search.</p>')

    content = f"""
    <div class="card">
      <h1>Search ChillyFile</h1>
      <p class="muted">Find people and shared folders.</p>
      <form method="get" action="/search">
        <label for="q">Search</label>
        <input id="q" name="q" maxlength="100" value="{escape_html(query)}" placeholder="Username or folder name..." required>
        <button type="submit">Search</button>
      </form>
    </div>
    <div class="card"><h2>People</h2>{people_rows}</div>
    <div class="card"><h2>Folders</h2>{folder_rows}</div>
    """
    return render_page(content, "Search - ChillyFile")


# --------------------------------------------------
# DISCOVER / POSTS
# --------------------------------------------------

@app.route("/discover")
def discover():
    with db() as connection:
        posts = connection.execute("""
            SELECT posts.*, users.username, users.role, users.profile_picture
            FROM posts
            JOIN users ON users.id = posts.user_id
            ORDER BY posts.id DESC
            LIMIT 100
        """).fetchall()

    rows = ""

    for p in posts:
        post_avatar = avatar_markup(p['user_id'], p['profile_picture'], p['username'])
        rows += f"""
        <div class="card post-card">
            <div class="post-head">
                {post_avatar}
                <div><a href="/profile/{escape_html(p['username'])}"><strong>@{escape_html(p['username'])}</strong></a>
                {role_badge(p['role'])}<div class="muted">{escape_html(p['created_at'])}</div></div>
            </div>
            <p class="post">{escape_html(p['content'])}</p>
        </div>
        """

    if not rows:
        rows = '<div class="card">No posts yet. Be the first!</div>'

    content = f"""
    <div class="card">
        <h1>Discover</h1>
        <p class="muted">Explore public posts from the community.</p>
    </div>
    {rows}
    """

    return render_page(content, "Discover")


@app.route("/post", methods=["POST"])
@login_required
def create_post():
    content = request.form.get("content", "").strip()

    if not content or len(content) > 3000:
        flash("Posts must contain 1–3000 characters.")
        return redirect(url_for("account"))

    with db() as connection:
        connection.execute("""
            INSERT INTO posts (user_id, content)
            VALUES (?, ?)
        """, (session["user_id"], content))

    flash("Your post is now public!")
    return redirect(url_for("account"))


@app.route("/delete-post/<int:post_id>", methods=["POST"])
@login_required
def delete_post(post_id):
    with db() as connection:
        connection.execute("""
            DELETE FROM posts
            WHERE id = ? AND user_id = ?
        """, (post_id, session["user_id"]))

    flash("Post deleted.")
    return redirect(url_for("account"))


# --------------------------------------------------
# OWNER ADMIN PANEL / ROLE MANAGEMENT
# --------------------------------------------------

@app.route("/admin", methods=["GET", "POST"])
@owner_required
def admin_panel():
    if request.method == "POST":
        user_id_raw = request.form.get("user_id", "")
        new_role = request.form.get("role", "")

        if new_role not in ASSIGNABLE_ROLES:
            flash("That role is not assignable.")
            return redirect(url_for("admin_panel"))

        try:
            target_id = int(user_id_raw)
        except (TypeError, ValueError):
            flash("Invalid user.")
            return redirect(url_for("admin_panel"))

        with db() as connection:
            target = connection.execute(
                "SELECT id, username, role FROM users WHERE id = ?",
                (target_id,)
            ).fetchone()

            if not target:
                flash("User not found.")
                return redirect(url_for("admin_panel"))

            if target["role"] == "owner":
                flash("The Owner role cannot be changed from the dashboard.")
                return redirect(url_for("admin_panel"))

            connection.execute(
                "UPDATE users SET role = ? WHERE id = ?",
                (new_role, target_id)
            )

        flash(f"Updated @{target['username']}'s role to {ROLE_INFO[new_role][1]}.")
        return redirect(url_for("admin_panel"))

    with db() as connection:
        users = connection.execute("""
            SELECT id, username, role, created_at
            FROM users
            ORDER BY username COLLATE NOCASE
        """).fetchall()

    rows = []
    for account in users:
        role = account["role"] or "member"
        role_label = ROLE_INFO.get(role, ROLE_INFO["member"])[1]
        options = []
        for role_value, label in ASSIGNABLE_ROLES.items():
            selected = " selected" if role == role_value else ""
            options.append(
                f'<option value="{escape_html(role_value)}"{selected}>{escape_html(label)}</option>'
            )

        if role == "owner":
            action = '<strong>Owner — protected</strong>'
        else:
            action = f"""
                <form method="post" action="/admin" class="inline-form">
                    <input type="hidden" name="user_id" value="{account['id']}">
                    <select name="role" aria-label="Role for {escape_html(account['username'])}">
                        {''.join(options)}
                    </select>
                    <button type="submit">Save Badge</button>
                </form>
            """

        rows.append(f"""
            <tr>
                <td><a href="/profile/{escape_html(account['username'])}">@{escape_html(account['username'])}</a></td>
                <td>{role_badge(role)} {escape_html(role_label)}</td>
                <td>{escape_html(account['created_at'])}</td>
                <td>{action}</td>
            </tr>
        """)

    table_rows = "".join(rows) or '<tr><td colspan="4">No users yet.</td></tr>'
    content = f"""
        <div class="card">
            <h1>Owner Control Panel</h1>
            <p class="muted">Manage member badges and roles here. Only @Chilly (Owner) can access this page.</p>
        </div>
        <div class="card">
            <h2>Users ({len(users)})</h2>
            <div style="overflow-x:auto">
                <table class="admin-table">
                    <thead><tr><th>Username</th><th>Current Role</th><th>Joined</th><th>Assign Badge</th></tr></thead>
                    <tbody>{table_rows}</tbody>
                </table>
            </div>
        </div>
    """
    return render_page(content, "Owner Control Panel")


# --------------------------------------------------
# UPLOAD FILES
# --------------------------------------------------

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

        # Create a new folder for this upload.
        folder_token = secrets.token_urlsafe(18)
        folder_name = Path(filename).stem or "My Folder"

        file_token = secrets.token_urlsafe(18)
        storage_key = f"{file_token}/{filename}"

        try:
            uploaded.stream.seek(0, os.SEEK_END)
            size = uploaded.stream.tell()
            uploaded.stream.seek(0)

            if size > MAX_FILE_MB * 1024 * 1024:
                flash(f"Maximum file size is {MAX_FILE_MB} MB.")
                return redirect(url_for("upload"))

            if b2:
                store_object(
                    storage_key,
                    uploaded.stream,
                    uploaded.mimetype or "application/octet-stream"
                )
            else:
                # Local fallback; not persistent on most Render services.
                local_name = f"{file_token}__{filename}"
                uploaded.save(UPLOAD_DIR / local_name)
                storage_key = local_name

            with db() as connection:
                folder_cursor = connection.execute("""
                    INSERT INTO folders (token, name, owner_id)
                    VALUES (?, ?, ?)
                """, (
                    folder_token,
                    folder_name,
                    session["user_id"]
                ))

                connection.execute("""
                    INSERT INTO files
                    (token, filename, storage_key, size, uploader_id, folder_id)
                    VALUES (?, ?, ?, ?, ?, ?)
                """, (
                    file_token,
                    filename,
                    storage_key,
                    size,
                    session["user_id"],
                    folder_cursor.lastrowid
                ))

        except Exception:
            app.logger.exception("Upload failed")
            flash("Upload failed. Check the cloud storage configuration.")
            return redirect(url_for("upload"))

        return redirect(url_for("upload_complete", token=folder_token))

    storage_status = (
        "Cloud storage connected."
        if b2 else
        "Warning: Backblaze B2 is not configured. Local uploads may disappear after a restart."
    )

    return render_page(f"""
    <div class="card">
        <h1>Upload Files</h1>
        <p class="muted">{escape_html(storage_status)}</p>
        <div class="upload-box">
            <form method="post" enctype="multipart/form-data">
                <input type="file" name="file" required>
                <button type="submit">Upload File</button>
            </form>
        </div>
        <p class="muted">Maximum size: {MAX_FILE_MB} MB.</p>
    </div>
    """)


@app.route("/upload-complete/<token>")
@login_required
def upload_complete(token):
    folder = get_folder(token)

    if not folder:
        abort(404)

    if folder["owner_id"] != session["user_id"]:
        abort(403)

    content = f"""
    <div class="card" style="text-align:center">
        <h1>✓ Upload Complete!</h1>
        <p>Your file has been uploaded.</p>
        <p class="muted">Folder: {escape_html(folder['name'])}</p>

        <a class="button" href="/folder/{escape_html(token)}">
            Open Folder
        </a>

        <p style="margin-top:25px">Share this folder:</p>

        <input id="share-link"
               readonly
               value="{escape_html(request.url_root.rstrip('/') + '/folder/' + token)}">

        <button type="button"
                onclick="navigator.clipboard.writeText(
                    document.getElementById('share-link').value
                ).then(() => this.textContent = 'Copied!')">
            Copy Folder Link
        </button>
    </div>
    """

    return render_page(content, "Upload Complete")


# --------------------------------------------------
# FOLDERS / FILE SHARING
# --------------------------------------------------

@app.route("/folder/<token>")
def folder_page(token):
    folder = get_folder(token)

    if not folder:
        abort(404)

    with db() as connection:
        files = connection.execute("""
            SELECT * FROM files
            WHERE folder_id = ?
            ORDER BY id
        """, (folder["id"],)).fetchall()

    rows = ""

    for f in files:
        rows += f"""
        <div class="file-row">
            <div>
                <a href="/f/{escape_html(f['token'])}">
                    {escape_html(f['filename'])}
                </a>
                <div class="muted">{format_size(f['size'])}</div>
            </div>
            <a class="button"
               href="/download/{escape_html(f['token'])}">
               Download
            </a>
        </div>
        """

    if not rows:
        rows = '<p class="muted">This folder is empty.</p>'

    owner_controls = ""

    if session.get("user_id") == folder["owner_id"]:
        owner_controls = f"""
        <form method="post"
              action="/rename-folder/{escape_html(folder['token'])}">
            <label>Folder name</label>
            <input name="name" maxlength="120"
                   value="{escape_html(folder['name'])}" required>
            <button type="submit">Rename Folder</button>
        </form>
        """

    content = f"""
    <div class="card">
        <h1><span class="folder-mark" aria-hidden="true"></span>{escape_html(folder['name'])}</h1>
        <p class="muted">Shared folder</p>
        {owner_controls}
    </div>

    <div class="card">
        <h2>Files</h2>
        {rows}
    </div>
    """

    return render_page(content, folder["name"])


@app.route("/rename-folder/<token>", methods=["POST"])
@login_required
def rename_folder(token):
    folder = get_folder(token)

    if not folder:
        abort(404)

    if folder["owner_id"] != session["user_id"]:
        abort(403)

    name = request.form.get("name", "").strip()

    if not name or len(name) > 120:
        flash("Folder names must contain 1–120 characters.")
        return redirect(url_for("folder_page", token=token))

    with db() as connection:
        connection.execute("""
            UPDATE folders SET name = ?
            WHERE id = ? AND owner_id = ?
        """, (name, folder["id"], session["user_id"]))

    flash("Folder renamed.")
    return redirect(url_for("folder_page", token=token))


@app.route("/rename-file/<token>", methods=["GET", "POST"])
@login_required
def rename_file(token):
    file_record = get_file(token)

    if not file_record:
        abort(404)

    if file_record["uploader_id"] != session["user_id"]:
        abort(403)

    if request.method == "POST":
        filename = secure_filename(
            request.form.get("filename", "").strip()
        )

        if not filename:
            flash("Enter a valid filename.")
            return redirect(url_for("rename_file", token=token))

        with db() as connection:
            connection.execute("""
                UPDATE files SET filename = ?
                WHERE token = ? AND uploader_id = ?
            """, (filename, token, session["user_id"]))

        flash("Filename changed.")
        return redirect(url_for("account"))

    return render_page(f"""
    <div class="card">
        <h1>Rename File</h1>
        <form method="post">
            <label>Filename</label>
            <input name="filename" maxlength="255"
                   value="{escape_html(file_record['filename'])}" required>
            <button type="submit">Save Filename</button>
        </form>
    </div>
    """)


# --------------------------------------------------
# EXISTING FILE URLS / DOWNLOADS
# --------------------------------------------------

@app.route("/f/<token>")
def f(token):
    file_record = get_file(token)

    if not file_record:
        # Existing file links keep using the same /f/<token> route.
        abort(404)

    folder = None

    if file_record["folder_id"]:
        with db() as connection:
            folder = connection.execute("""
                SELECT * FROM folders WHERE id = ?
            """, (file_record["folder_id"],)).fetchone()

    folder_link = ""

    if folder:
        folder_link = f"""
        <a class="button"
           href="/folder/{escape_html(folder['token'])}">
           Open Folder
        </a>
        """

    content = f"""
    <div class="card">
        <h1>File Ready</h1>
        <p>{escape_html(file_record['filename'])}</p>
        <p class="muted">{format_size(file_record['size'])}</p>

        <a class="button"
           href="/download/{escape_html(token)}">
           Download File
        </a>

        {folder_link}
    </div>
    """

    return render_page(content, file_record["filename"])


@app.route("/download/<token>")
def download(token):
    file_record = get_file(token)

    if not file_record:
        abort(404)

    if b2:
        return object_response(
            file_record["storage_key"],
            file_record["filename"]
        )

    return send_from_directory(
        UPLOAD_DIR,
        file_record["storage_key"],
        as_attachment=True,
        download_name=file_record["filename"]
    )


# --------------------------------------------------
# ERROR HANDLERS
# --------------------------------------------------

@app.errorhandler(413)
def too_large(error):
    return render_page(f"""
    <div class="card">
        <h1>File Too Large</h1>
        <p>The maximum upload size is {MAX_FILE_MB} MB.</p>
    </div>
    """), 413


@app.errorhandler(404)
def not_found(error):
    return render_page("""
    <div class="card">
        <h1>404 — Not Found</h1>
        <p>This file, folder, or page could not be found.</p>
        <a class="button" href="/">Back Home</a>
    </div>
    """), 404


@app.errorhandler(403)
def forbidden(error):
    return render_page("""
    <div class="card">
        <h1>Access Denied</h1>
        <p>You do not have permission to change this item.</p>
        <a class="button" href="/">Back Home</a>
    </div>
    """), 403


if __name__ == "__main__":
    app.run(
        host="0.0.0.0",
        port=int(os.environ.get("PORT", "5000"))
    )
