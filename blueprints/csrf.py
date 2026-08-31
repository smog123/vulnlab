from flask import Blueprint, render_template, request, flash, session, redirect, url_for, make_response
from flask_login import login_required, current_user
from models import db, User
import secrets
import hashlib
import time

csrf_bp = Blueprint("csrf", __name__)

def generate_csrf_token():
    level = session.get("security_level", "LOW")
    if level == "LOW":
        return ""
    elif level == "MEDIUM":
        predictable = hashlib.md5(str(current_user.id).encode()).hexdigest()[:16]
        session["csrf_token"] = predictable
        return predictable
    else:
        token = secrets.token_hex(32)
        session["csrf_token"] = token
        return token

def validate_csrf_token():
    level = session.get("security_level", "LOW")
    if level == "LOW":
        return True
    token = request.form.get("csrf_token", "")
    return token == session.get("csrf_token", "")

@csrf_bp.route("/csrf", methods=["GET", "POST"])
def csrf_demo():
    level = session.get("security_level", "LOW")
    message = ""
    message_type = "info"

    if request.method == "POST":
        if not validate_csrf_token():
            message = "CSRF token missing or invalid! Attack blocked."
            message_type = "danger"
        else:
            action = request.form.get("action", "")

            if action == "change_email":
                new_email = request.form.get("email", "")
                if current_user.is_authenticated:
                    current_user.email = new_email
                    db.session.commit()
                    message = f"Email changed to: {new_email}"
                    message_type = "success"
                else:
                    message = "You must be logged in."
                    message_type = "warning"

            elif action == "change_password":
                new_password = request.form.get("new_password", "")
                if current_user.is_authenticated:
                    current_user.password = new_password
                    db.session.commit()
                    message = "Password changed successfully!"
                    message_type = "success"
                else:
                    message = "You must be logged in."
                    message_type = "warning"

            elif action == "delete_account":
                if current_user.is_authenticated:
                    db.session.delete(current_user)
                    db.session.commit()
                    message = "Account deleted!"
                    message_type = "success"

            elif action == "transfer_money":
                amount = request.form.get("amount", "0")
                to_user = request.form.get("to_user", "")
                message = f"Transferred ${amount} to {to_user} (simulated)"
                message_type = "success"

    csrf_token = generate_csrf_token()
    return render_template("vulns/csrf.html", message=message, message_type=message_type, csrf_token=csrf_token, level=level)

@csrf_bp.route("/csrf/attacker")
def csrf_attacker_page():
    return render_template("vulns/csrf_attacker.html")
