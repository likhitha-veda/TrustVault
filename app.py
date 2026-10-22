
import os
import sqlite3
import uuid

from contextlib import contextmanager
from datetime import datetime, timezone
from functools import wraps

from flask import (
    Flask,
    render_template,
    request,
    redirect,
    url_for,
    session,
    abort,
    send_file,
)
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename


# --------------------------------------------------
# APPLICATION CONFIGURATION
# --------------------------------------------------

app = Flask(__name__)

app.secret_key = os.environ.get(
    "TRUSTVAULT_SECRET_KEY",
    "local-development-key-change-before-deployment",
)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATABASE = os.path.join(BASE_DIR, "trustvault.db")
UPLOAD_FOLDER = os.path.join(BASE_DIR, "private_documents")

os.makedirs(UPLOAD_FOLDER, exist_ok=True)

app.config["MAX_CONTENT_LENGTH"] = 5 * 1024 * 1024

ALLOWED_EXTENSIONS = {
    "pdf", "txt", "png", "jpg", "jpeg", "docx"
}


# --------------------------------------------------
# DATABASE CONNECTIONS
# --------------------------------------------------

def connect_db():
    """Open a SQLite connection with a lock-wait timeout."""
    db = sqlite3.connect(DATABASE, timeout=15)
    db.row_factory = sqlite3.Row
    db.execute("PRAGMA foreign_keys = ON")
    db.execute("PRAGMA busy_timeout = 15000")
    return db


@contextmanager
def db_session():
    """Commit successful transactions and close connections safely."""
    db = connect_db()

    try:
        yield db
        db.commit()
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()


# --------------------------------------------------
# DATABASE INITIALIZATION
# --------------------------------------------------

def init_db():
    with db_session() as db:
        db.executescript("""
            CREATE TABLE IF NOT EXISTS users (
                username TEXT PRIMARY KEY,
                password_hash TEXT NOT NULL,
                role TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS documents (
                id TEXT PRIMARY KEY,
                original_name TEXT NOT NULL,
                owner TEXT NOT NULL
                    REFERENCES users(username),
                created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS permissions (
                document_id TEXT NOT NULL
                    REFERENCES documents(id) ON DELETE CASCADE,
                username TEXT NOT NULL
                    REFERENCES users(username),
                access TEXT NOT NULL
                    CHECK(access IN ('read', 'edit')),
                PRIMARY KEY (document_id, username)
            );

            CREATE TABLE IF NOT EXISTS audit_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                username TEXT NOT NULL,
                action TEXT NOT NULL,
                document_id TEXT NOT NULL DEFAULT '',
                details TEXT NOT NULL DEFAULT ''
            );
        """)

        # Demo accounts are created only if they do not exist.
        demo_users = [
            ("admin", "Admin123", "Administrator"),
            ("owner", "Owner123", "Document Owner"),
            ("viewer", "Viewer123", "Viewer"),
        ]

        for username, password, role in demo_users:
            existing = db.execute(
                "SELECT username FROM users WHERE username = ?",
                (username,),
            ).fetchone()

            if existing is None:
                db.execute(
                    """
                    INSERT INTO users (username, password_hash, role)
                    VALUES (?, ?, ?)
                    """,
                    (
                        username,
                        generate_password_hash(password),
                        role,
                    ),
                )


# --------------------------------------------------
# AUDIT LOGGING
# --------------------------------------------------

def log_action(action, document_id="", details=""):
    """
    Store audit events using a separate, short-lived connection.
    Call this after the main operation's transaction has finished.
    """
    username = session.get("username", "Unknown")
    timestamp = datetime.now(timezone.utc).strftime(
        "%Y-%m-%d %H:%M:%S UTC"
    )

    with db_session() as db:
        db.execute(
            """
            INSERT INTO audit_logs
                (timestamp, username, action, document_id, details)
            VALUES (?, ?, ?, ?, ?)
            """,
            (
                timestamp,
                username,
                action,
                document_id or "",
                details or "",
            ),
        )


# --------------------------------------------------
# AUTHENTICATION AND AUTHORIZATION
# --------------------------------------------------

def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if "username" not in session:
            return redirect(url_for("home"))

        return view(*args, **kwargs)

    return wrapped


def roles_required(*allowed_roles):
    def decorator(view):
        @wraps(view)
        def wrapped(*args, **kwargs):
            if "username" not in session:
                return redirect(url_for("home"))

            if session.get("role") not in allowed_roles:
                log_action(
                    "ACCESS_DENIED",
                    details=f"Denied access to {request.path}",
                )
                abort(403)

            return view(*args, **kwargs)

        return wrapped

    return decorator


def get_document(document_id):
    with db_session() as db:
        return db.execute(
            "SELECT * FROM documents WHERE id = ?",
            (document_id,),
        ).fetchone()


def get_permission(document_id, username):
    with db_session() as db:
        row = db.execute(
            """
            SELECT access FROM permissions
            WHERE document_id = ? AND username = ?
            """,
            (document_id, username),
        ).fetchone()

    return row["access"] if row else None


# --------------------------------------------------
# LOGIN
# --------------------------------------------------

@app.route("/", methods=["GET", "POST"])
def home():
    message = ""

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        with db_session() as db:
            user = db.execute(
                "SELECT * FROM users WHERE username = ?",
                (username,),
            ).fetchone()

        if user and check_password_hash(
            user["password_hash"], password
        ):
            session.clear()
            session["username"] = user["username"]
            session["role"] = user["role"]

            log_action("LOGIN", details="Successful login")

            return redirect(url_for("dashboard"))

        log_action(
            "LOGIN_FAILED",
            details=f"Failed login for username: {username[:80]}",
        )
        message = "Invalid username or password."

    return render_template("login.html", message=message)


# --------------------------------------------------
# DASHBOARD
# --------------------------------------------------

@app.route("/dashboard")
@login_required
def dashboard():
    username = session["username"]

    with db_session() as db:
        documents = db.execute(
            """
            SELECT * FROM documents
            WHERE owner = ?
            ORDER BY created_at DESC
            """,
            (username,),
        ).fetchall()

        shared_documents = db.execute(
            """
            SELECT d.*
            FROM documents AS d
            JOIN permissions AS p ON p.document_id = d.id
            WHERE p.username = ?
            ORDER BY d.created_at DESC
            """,
            (username,),
        ).fetchall()

    return render_template(
        "dashboard.html",
        username=username,
        role=session["role"],
        documents=documents,
        shared_documents=shared_documents,
    )


# --------------------------------------------------
# UPLOAD DOCUMENT
# --------------------------------------------------

@app.route("/upload", methods=["GET", "POST"])
@login_required
@roles_required("Administrator", "Document Owner")
def upload_document():
    if request.method == "POST":
        uploaded_file = request.files.get("document")

        if not uploaded_file or not uploaded_file.filename:
            return "Please select a file.", 400

        original_name = secure_filename(uploaded_file.filename)

        if not original_name or "." not in original_name:
            return "Invalid filename.", 400

        extension = original_name.rsplit(".", 1)[1].lower()

        if extension not in ALLOWED_EXTENSIONS:
            return "File type not allowed.", 400

        document_id = f"{uuid.uuid4().hex}.{extension}"
        file_path = os.path.join(UPLOAD_FOLDER, document_id)

        created_at = datetime.now(timezone.utc).strftime(
            "%Y-%m-%d %H:%M:%S UTC"
        )

        uploaded_file.save(file_path)

        try:
            with db_session() as db:
                db.execute(
                    """
                    INSERT INTO documents
                        (id, original_name, owner, created_at)
                    VALUES (?, ?, ?, ?)
                    """,
                    (
                        document_id,
                        original_name,
                        session["username"],
                        created_at,
                    ),
                )
        except Exception:
            if os.path.exists(file_path):
                os.remove(file_path)
            raise

        log_action(
            "UPLOAD",
            document_id,
            f"Uploaded {original_name}",
        )

        return redirect(url_for("dashboard"))

    return render_template("upload.html")


# --------------------------------------------------
# SHARE AND REVOKE DOCUMENT ACCESS
# --------------------------------------------------

@app.route("/share/<document_id>", methods=["GET", "POST"])
@login_required
def share_document(document_id):
    doc = get_document(document_id)

    if doc is None:
        log_action(
            "DOCUMENT_NOT_FOUND",
            document_id,
            "Permission management requested for unknown document",
        )
        abort(404)

    if doc["owner"] != session["username"]:
        log_action(
            "ACCESS_DENIED",
            document_id,
            "Unauthorized attempt to manage permissions",
        )
        abort(403)

    with db_session() as db:
        available_users = db.execute(
            """
            SELECT username FROM users
            WHERE username != ?
            ORDER BY username
            """,
            (doc["owner"],),
        ).fetchall()

    # The dictionary format is compatible with the existing template.
    users = {
        row["username"]: {}
        for row in available_users
    }

    message = ""

    if request.method == "POST":
        target_user = request.form.get("target_user", "").strip()
        access = request.form.get("access", "").lower()

        if target_user not in users:
            message = "User not found."

        elif access not in ("read", "edit", "revoke"):
            message = "Please select a valid permission."

        elif target_user == session["username"]:
            message = "You cannot change your own access here."

        else:
            if access == "revoke":
                with db_session() as db:
                    result = db.execute(
                        """
                        DELETE FROM permissions
                        WHERE document_id = ? AND username = ?
                        """,
                        (document_id, target_user),
                    )
                    removed = result.rowcount > 0

                if removed:
                    log_action(
                        "ACCESS_REVOKED",
                        document_id,
                        f"Revoked access for {target_user}",
                    )
                    message = "Access revoked successfully."
                else:
                    message = "This user did not have access."

            else:
                with db_session() as db:
                    db.execute(
                        """
                        INSERT INTO permissions
                            (document_id, username, access)
                        VALUES (?, ?, ?)
                        ON CONFLICT(document_id, username)
                        DO UPDATE SET access = excluded.access
                        """,
                        (document_id, target_user, access),
                    )

                log_action(
                    "ACCESS_GRANTED",
                    document_id,
                    f"Granted {access} access to {target_user}",
                )
                message = f"{access.title()} access granted."

    with db_session() as db:
        current_rows = db.execute(
            """
            SELECT username, access FROM permissions
            WHERE document_id = ?
            """,
            (document_id,),
        ).fetchall()

    current_permissions = {
        row["username"]: row["access"]
        for row in current_rows
    }

    return render_template(
        "share.html",
        doc=doc,
        users=users,
        current_permissions=current_permissions,
        message=message,
    )


# --------------------------------------------------
# DOWNLOAD DOCUMENT
# --------------------------------------------------

@app.route("/document/<document_id>")
@login_required
def view_document(document_id):
    username = session["username"]
    doc = get_document(document_id)

    if doc is None:
        log_action(
            "DOCUMENT_NOT_FOUND",
            document_id,
            "Download requested for unknown document",
        )
        abort(404)

    permission = get_permission(document_id, username)

    # Owners and users with explicit read/edit access may download.
    if (
        doc["owner"] != username
        and permission not in ("read", "edit")
    ):
        log_action(
            "ACCESS_DENIED",
            document_id,
            "Unauthorized document download attempt",
        )
        abort(403)

    file_path = os.path.join(UPLOAD_FOLDER, document_id)

    if not os.path.isfile(file_path):
        log_action(
            "FILE_MISSING",
            document_id,
            "Document record exists but file is missing",
        )
        abort(404)

    log_action(
        "DOWNLOAD",
        document_id,
        f"Downloaded {doc['original_name']}",
    )

    return send_file(
        file_path,
        as_attachment=True,
        download_name=doc["original_name"],
    )


# --------------------------------------------------
# ADMIN AUDIT LOGS
# --------------------------------------------------

@app.route("/audit")
@login_required
@roles_required("Administrator")
def audit():
    with db_session() as db:
        audit_logs = db.execute(
            """
            SELECT timestamp, username, action, document_id, details
            FROM audit_logs
            ORDER BY id DESC
            """
        ).fetchall()

    return render_template(
        "audit.html",
        audit_logs=audit_logs,
    )


# --------------------------------------------------
# LOGOUT
# --------------------------------------------------

@app.route("/logout")
def logout():
    if "username" in session:
        log_action(
            "LOGOUT",
            details="User logged out",
        )

    session.clear()
    return redirect(url_for("home"))


# --------------------------------------------------
# ERROR HANDLERS
# --------------------------------------------------

@app.errorhandler(403)
def forbidden(error):
    return (
        "Access denied. You do not have permission to do this.",
        403,
    )


@app.errorhandler(404)
def not_found(error):
    return "Document or page not found.", 404


@app.errorhandler(413)
def file_too_large(error):
    return "File too large. Maximum allowed size is 5 MB.", 413


# --------------------------------------------------
# START APPLICATION
# --------------------------------------------------

init_db()

if __name__ == "__main__":
    app.run(debug=True)
