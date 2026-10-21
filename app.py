
from flask import (
    Flask, render_template, request, redirect,
    url_for, session, send_from_directory, abort
)
from werkzeug.utils import secure_filename
from functools import wraps
from datetime import datetime
import os
import json

app = Flask(__name__)
app.secret_key = "replace-this-with-a-long-random-secret"

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
UPLOAD_FOLDER = os.path.join(BASE_DIR, "uploads")
AUDIT_FILE = os.path.join(BASE_DIR, "audit_log.json")
PERMISSIONS_FILE = os.path.join(BASE_DIR, "document_permissions.json")

os.makedirs(UPLOAD_FOLDER, exist_ok=True)

USERS = {
    "admin@trustvault.com": "TrustVault@123",
    "user@trustvault.com": "UserVault@123"
}


def read_json(path, default):
    if not os.path.exists(path):
        return default

    try:
        with open(path, "r", encoding="utf-8") as file:
            return json.load(file)
    except (json.JSONDecodeError, OSError):
        return default


def write_json(path, data):
    with open(path, "w", encoding="utf-8") as file:
        json.dump(data, file, indent=4)


def add_audit_log(activity, actor=None):
    logs = read_json(AUDIT_FILE, [])

    logs.insert(0, {
        "time": datetime.now().strftime("%d-%m-%Y %H:%M:%S"),
        "user": actor or session.get("email", "Unauthenticated"),
        "activity": activity
    })

    write_json(AUDIT_FILE, logs[:500])


def read_permissions():
    return read_json(PERMISSIONS_FILE, {})


def get_document_records():
    permissions = read_permissions()
    changed = False
    records = []

    for filename in sorted(os.listdir(UPLOAD_FOLDER)):
        path = os.path.join(UPLOAD_FOLDER, filename)

        if not os.path.isfile(path):
            continue

        if filename not in permissions:
            permissions[filename] = {
                "owner": "admin@trustvault.com",
                "allowed_users": ["admin@trustvault.com"]
            }
            changed = True

        details = permissions[filename]

        if "owner" not in details:
            details["owner"] = "admin@trustvault.com"
            changed = True

        if "allowed_users" not in details:
            details["allowed_users"] = [details["owner"]]
            changed = True

        if details["owner"] not in details["allowed_users"]:
            details["allowed_users"].append(details["owner"])
            changed = True

        records.append({
            "filename": filename,
            "owner": details["owner"],
            "allowed_users": details["allowed_users"]
        })

    if changed:
        write_json(PERMISSIONS_FILE, permissions)

    return records


def login_required(route_function):
    @wraps(route_function)
    def wrapper(*args, **kwargs):
        if "email" not in session:
            add_audit_log(
                f"Unauthorized access attempt: {request.path}",
                actor="Unauthenticated"
            )
            return redirect(url_for("home"))

        return route_function(*args, **kwargs)

    return wrapper


def show_dashboard(message="", error=""):
    email = session["email"]
    records = get_document_records()

    visible_documents = [
        record for record in records
        if email in record["allowed_users"]
    ]

    for record in visible_documents:
        record["can_manage"] = record["owner"] == email

    other_users = [
        user_email for user_email in USERS
        if user_email != email
    ]

    return render_template(
        "dashboard.html",
        documents=visible_documents,
        audit_logs=read_json(AUDIT_FILE, []),
        message=message,
        error=error,
        current_user=email,
        other_users=other_users
    )


@app.route("/")
def home():
    if "email" in session:
        return redirect(url_for("dashboard"))

    return render_template("login.html", error="")


@app.route("/login", methods=["POST"])
def login():
    email = request.form.get("email", "").strip().lower()
    password = request.form.get("password", "")

    if USERS.get(email) == password:
        session.clear()
        session["email"] = email
        add_audit_log("Login successful")
        return redirect(url_for("dashboard"))

    add_audit_log(
        f"Failed login attempt for: {email or 'empty email'}",
        actor="Unauthenticated"
    )

    return render_template(
        "login.html",
        error="Invalid email or password. Please try again."
    ), 401


@app.route("/dashboard")
@login_required
def dashboard():
    return show_dashboard()


@app.route("/upload", methods=["POST"])
@login_required
def upload():
    if "document" not in request.files:
        return show_dashboard(error="No file selected.")

    file = request.files["document"]

    if not file.filename:
        return show_dashboard(error="Please select a file.")

    filename = secure_filename(file.filename)

    if not filename:
        return show_dashboard(error="Invalid filename.")

    file_path = os.path.join(UPLOAD_FOLDER, filename)

    if os.path.exists(file_path):
        name, extension = os.path.splitext(filename)
        counter = 1

        while os.path.exists(file_path):
            filename = f"{name}_{counter}{extension}"
            file_path = os.path.join(UPLOAD_FOLDER, filename)
            counter += 1

    file.save(file_path)

    permissions = read_permissions()
    permissions[filename] = {
        "owner": session["email"],
        "allowed_users": [session["email"]]
    }
    write_json(PERMISSIONS_FILE, permissions)

    add_audit_log(f"Document uploaded: {filename}")

    return show_dashboard(message=f"{filename} uploaded successfully!")


@app.route("/share/<filename>", methods=["POST"])
@login_required
def share_document(filename):
    safe_filename = secure_filename(filename)

    if not safe_filename or safe_filename != filename:
        add_audit_log("Blocked invalid share request")
        abort(400)

    permissions = read_permissions()
    details = permissions.get(safe_filename)

    if not details or not os.path.isfile(
        os.path.join(UPLOAD_FOLDER, safe_filename)
    ):
        return show_dashboard(error="Document not found.")

    if details["owner"] != session["email"]:
        add_audit_log(
            f"Blocked share attempt for document: {safe_filename}"
        )
        abort(403)

    target_user = request.form.get("share_with", "").strip().lower()

    if target_user not in USERS:
        return show_dashboard(error="Invalid user selected.")

    if target_user == session["email"]:
        return show_dashboard(error="You already own this document.")

    if target_user not in details["allowed_users"]:
        details["allowed_users"].append(target_user)
        write_json(PERMISSIONS_FILE, permissions)
        add_audit_log(
            f"Document shared with {target_user}: {safe_filename}"
        )
        return show_dashboard(
            message=f"{safe_filename} shared with {target_user}."
        )

    return show_dashboard(
        message=f"{target_user} already has access to {safe_filename}."
    )


@app.route("/revoke/<filename>", methods=["POST"])
@login_required
def revoke_access(filename):
    safe_filename = secure_filename(filename)

    if not safe_filename or safe_filename != filename:
        add_audit_log("Blocked invalid revoke request")
        abort(400)

    permissions = read_permissions()
    details = permissions.get(safe_filename)

    if not details or not os.path.isfile(
        os.path.join(UPLOAD_FOLDER, safe_filename)
    ):
        return show_dashboard(error="Document not found.")

    if details["owner"] != session["email"]:
        add_audit_log(
            f"Blocked revoke attempt for document: {safe_filename}"
        )
        abort(403)

    target_user = request.form.get("revoke_user", "").strip().lower()

    if target_user not in USERS:
        return show_dashboard(error="Invalid user selected.")

    if target_user == details["owner"]:
        return show_dashboard(
            error="Document owner access cannot be revoked."
        )

    if target_user not in details["allowed_users"]:
        return show_dashboard(
            error=f"{target_user} does not have access to this document."
        )

    details["allowed_users"].remove(target_user)
    write_json(PERMISSIONS_FILE, permissions)

    add_audit_log(
        f"Access revoked for {target_user}: {safe_filename}"
    )

    return show_dashboard(
        message=f"Access revoked for {target_user} on {safe_filename}."
    )


@app.route("/download/<filename>")
@login_required
def download(filename):
    safe_filename = secure_filename(filename)

    if not safe_filename or safe_filename != filename:
        add_audit_log("Blocked invalid download request")
        abort(400)

    file_path = os.path.join(UPLOAD_FOLDER, safe_filename)
    permissions = read_permissions()
    details = permissions.get(safe_filename)

    if not os.path.isfile(file_path) or not details:
        add_audit_log(f"Document not found: {safe_filename}")
        abort(404)

    if session["email"] not in details["allowed_users"]:
        add_audit_log(
            f"Blocked unauthorized download: {safe_filename}"
        )
        abort(403)

    add_audit_log(f"Document downloaded: {safe_filename}")

    return send_from_directory(
        UPLOAD_FOLDER,
        safe_filename,
        as_attachment=True
    )


@app.route("/logout")
@login_required
def logout():
    email = session["email"]
    add_audit_log("Logout", actor=email)
    session.clear()
    return redirect(url_for("home"))


if __name__ == "__main__":
    app.run(debug=True)
