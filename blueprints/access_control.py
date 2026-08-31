from flask import Blueprint, render_template, request, flash, session, redirect, url_for, jsonify
from flask_login import login_required, current_user
from models import db, User, Note, Post

access_control_bp = Blueprint("access_control", __name__)

@access_control_bp.route("/idor", methods=["GET", "POST"])
def idor():
    level = session.get("security_level", "LOW")
    notes = []
    target_user_id = None

    if request.method == "POST":
        target_user_id = request.form.get("user_id", "")

        if level == "LOW":
            notes = Note.query.filter_by(user_id=target_user_id).all()
        elif level == "MEDIUM":
            if current_user.is_authenticated and str(current_user.id) == str(target_user_id):
                notes = Note.query.filter_by(user_id=target_user_id).all()
            else:
                notes = Note.query.filter_by(user_id=target_user_id, is_private=False).all()
                if not notes:
                    flash("Access denied.", "danger")
        else:
            if current_user.is_authenticated and str(current_user.id) == str(target_user_id):
                notes = Note.query.filter_by(user_id=target_user_id).all()
            else:
                flash("Access denied: You can only view your own notes.", "danger")

    all_users = User.query.all()
    return render_template("vulns/idor.html", notes=notes, users=all_users, target_user_id=target_user_id, level=level)

@access_control_bp.route("/privilege_escalation", methods=["GET", "POST"])
def privilege_escalation():
    level = session.get("security_level", "LOW")
    message = ""

    if request.method == "POST":
        action = request.form.get("action", "")

        if level == "LOW":
            if action == "make_admin":
                user_id = request.form.get("user_id", "")
                user = db.session.get(User, int(user_id))
                if user:
                    user.role = "admin"
                    user.is_admin = True
                    db.session.commit()
                    message = f"User {user.username} is now admin!"
            elif action == "view_secrets":
                message = "Admin Secret: database_password=P@ssw0rd123, api_key=sk-1234567890abcdef"

        elif level == "MEDIUM":
            if action == "make_admin":
                role = request.form.get("role", "user")
                user_id = request.form.get("user_id", "")
                user = db.session.get(User, int(user_id))
                if user:
                    user.role = role
                    user.is_admin = (role == "admin")
                    db.session.commit()
                    message = f"User {user.username} role changed to {role}!"

        else:
            if current_user.is_authenticated and current_user.is_admin:
                if action == "make_admin":
                    user_id = request.form.get("user_id", "")
                    user = db.session.get(User, int(user_id))
                    if user:
                        user.role = "admin"
                        user.is_admin = True
                        db.session.commit()
                        message = f"User {user.username} is now admin!"
                elif action == "view_secrets":
                    message = "Admin Secret: database_password=P@ssw0rd123, api_key=sk-1234567890abcdef"
            else:
                flash("Access denied: Admin only.", "danger")

    users = User.query.all()
    return render_template("vulns/privilege_escalation.html", users=users, message=message, level=level)

@access_control_bp.route("/cors_misconfig")
def cors_misconfig():
    level = session.get("security_level", "LOW")
    return render_template("vulns/cors_misconfig.html", level=level)
