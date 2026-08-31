from flask import Blueprint, render_template, request, redirect, url_for, flash, session, current_app
from flask_login import login_user, logout_user, login_required, current_user
import bcrypt
import jwt
import datetime
import time
from models import db, User

auth_bp = Blueprint("auth", __name__)

login_attempts = {}

@auth_bp.route("/login", methods=["GET", "POST"])
def login():
    level = session.get("security_level", "LOW")

    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        user = User.query.filter_by(username=username).first()

        if level == "LOW":
            if user and bcrypt.checkpw(password.encode(), user.password.encode()):
                login_user(user)
                flash("Login successful!", "success")
                return redirect(url_for("index"))
            flash("Invalid credentials.", "danger")

        elif level == "MEDIUM":
            ip = request.remote_addr
            if ip in login_attempts and login_attempts[ip]["count"] >= 10:
                if time.time() - login_attempts[ip]["start"] < 300:
                    flash("Too many attempts. Try again later.", "danger")
                    return render_template("auth/login.html")
                else:
                    login_attempts[ip] = {"count": 0, "start": time.time()}

            if user and bcrypt.checkpw(password.encode(), user.password.encode()):
                login_attempts.pop(ip, None)
                login_user(user)
                flash("Login successful!", "success")
                return redirect(url_for("index"))

            if ip not in login_attempts:
                login_attempts[ip] = {"count": 0, "start": time.time()}
            login_attempts[ip]["count"] += 1
            flash(f"Invalid credentials. Attempts: {login_attempts[ip]['count']}/10", "danger")

        elif level == "HIGH":
            ip = request.remote_addr
            if ip in login_attempts and login_attempts[ip]["count"] >= 5:
                elapsed = time.time() - login_attempts[ip]["start"]
                if elapsed < 900:
                    remaining = int(900 - elapsed)
                    flash(f"Account locked. Try again in {remaining} seconds.", "danger")
                    return render_template("auth/login.html")
                else:
                    login_attempts.pop(ip, None)

            if user and bcrypt.checkpw(password.encode(), user.password.encode()):
                login_attempts.pop(ip, None)
                login_user(user)
                db.session.commit()
                flash("Login successful!", "success")
                return redirect(url_for("index"))

            if ip not in login_attempts:
                login_attempts[ip] = {"count": 0, "start": time.time()}
            login_attempts[ip]["count"] += 1
            remaining_attempts = 5 - login_attempts[ip]["count"]
            if remaining_attempts <= 0:
                flash("Account locked for 15 minutes.", "danger")
            else:
                flash(f"Invalid credentials. {remaining_attempts} attempts remaining.", "danger")

    return render_template("auth/login.html")

@auth_bp.route("/register", methods=["GET", "POST"])
def register():
    level = session.get("security_level", "LOW")

    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        email = request.form.get("email", "")

        if level == "LOW":
            if User.query.filter_by(username=username).first():
                flash("Username already exists.", "danger")
                return render_template("auth/register.html")
            hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
            new_user = User(username=username, password=hashed, email=email)
            db.session.add(new_user)
            db.session.commit()
            flash("Registration successful! Please login.", "success")
            return redirect(url_for("auth.login"))

        elif level == "MEDIUM":
            if len(password) < 6:
                flash("Password must be at least 6 characters.", "danger")
                return render_template("auth/register.html")
            if User.query.filter_by(username=username).first():
                flash("Username already exists.", "danger")
                return render_template("auth/register.html")
            hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
            new_user = User(username=username, password=hashed, email=email)
            db.session.add(new_user)
            db.session.commit()
            flash("Registration successful! Please login.", "success")
            return redirect(url_for("auth.login"))

        elif level == "HIGH":
            if len(password) < 12:
                flash("Password must be at least 12 characters.", "danger")
                return render_template("auth/register.html")
            if not any(c.isupper() for c in password):
                flash("Password must contain an uppercase letter.", "danger")
                return render_template("auth/register.html")
            if not any(c.isdigit() for c in password):
                flash("Password must contain a digit.", "danger")
                return render_template("auth/register.html")
            if not any(c in "!@#$%^&*()_+-=[]{}|;:,.<>?" for c in password):
                flash("Password must contain a special character.", "danger")
                return render_template("auth/register.html")
            if User.query.filter_by(username=username).first():
                flash("Username already exists.", "danger")
                return render_template("auth/register.html")
            hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
            new_user = User(username=username, password=hashed, email=email)
            db.session.add(new_user)
            db.session.commit()
            flash("Registration successful! Please login.", "success")
            return redirect(url_for("auth.login"))

    return render_template("auth/register.html")

@auth_bp.route("/logout")
@login_required
def logout():
    logout_user()
    flash("Logged out.", "info")
    return redirect(url_for("index"))

@auth_bp.route("/jwt-demo")
def jwt_demo():
    level = session.get("security_level", "LOW")

    if level == "LOW":
        secret = "jwt-secret"
        token = jwt.encode({"user": "admin", "role": "admin", "exp": datetime.datetime.utcnow() + datetime.timedelta(hours=24)}, secret, algorithm="HS256")
    elif level == "MEDIUM":
        secret = current_app.config.get("A04_WEAK_JWT_SECRET", "jwt-secret")
        token = jwt.encode({"user": "admin", "role": "user", "exp": datetime.datetime.utcnow() + datetime.timedelta(hours=24)}, secret, algorithm="HS256")
    else:
        secret = current_app.config["SECRET_KEY"]
        token = jwt.encode({"user": "guest", "role": "user", "exp": datetime.datetime.utcnow() + datetime.timedelta(minutes=15)}, secret, algorithm="HS256")

    decoded = jwt.decode(token, options={"verify_signature": False})

    return render_template("auth/jwt_demo.html", token=token, decoded=decoded, level=level)
