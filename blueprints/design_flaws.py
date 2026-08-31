from flask import Blueprint, render_template, request, flash, session
from models import db, User, Transaction
import json
import pickle
import base64

design_flaws_bp = Blueprint("design_flaws", __name__)

@design_flaws_bp.route("/insecure_design")
def insecure_design():
    return render_template("vulns/insecure_design.html", level=session.get("security_level", "LOW"))

@design_flaws_bp.route("/insecure_design/purchase", methods=["GET", "POST"])
def purchase():
    level = session.get("security_level", "LOW")
    message = ""
    final_price = 0

    if request.method == "POST":
        price = float(request.form.get("price", 0))
        coupon = request.form.get("coupon", "")

        if level == "LOW":
            discount = 0
            if coupon == "SAVE10":
                discount = 0.10
            elif coupon == "SAVE50":
                discount = 0.50
            elif coupon == "FREE":
                discount = 1.0
            elif coupon == "NEGATIVE":
                discount = 2.0

            final_price = price * (1 - discount)
            message = f"Final price: ${final_price:.2f} (coupon: {coupon}, discount: {discount*100}%)"

        elif level == "MEDIUM":
            if coupon in ["SAVE10", "SAVE20", "SAVE30"]:
                discount_map = {"SAVE10": 0.10, "SAVE20": 0.20, "SAVE30": 0.30}
                discount = discount_map.get(coupon, 0)
                final_price = max(0, price * (1 - discount))
                message = f"Final price: ${final_price:.2f}"
            else:
                final_price = price
                message = f"Invalid coupon. Price: ${final_price:.2f}"

        else:
            if coupon in ["SAVE10", "SAVE20", "SAVE30"]:
                discount_map = {"SAVE10": 0.10, "SAVE20": 0.20, "SAVE30": 0.30}
                discount = discount_map.get(coupon, 0)
                final_price = max(0, price * (1 - discount))
            else:
                final_price = price
            message = f"Final price: ${final_price:.2f}"

    return render_template("vulns/purchase.html", message=message, final_price=final_price, level=level)

@design_flaws_bp.route("/insecure_design/profile", methods=["GET", "POST"])
def mass_assignment():
    level = session.get("security_level", "LOW")
    message = ""

    if request.method == "POST":
        username = request.form.get("username", "")
        email = request.form.get("email", "")

        if level == "LOW":
            is_admin = request.form.get("is_admin", "false") == "true"
            role = request.form.get("role", "user")
            new_user = User(username=username, email=email, is_admin=is_admin, role=role, password="password123")
            db.session.add(new_user)
            db.session.commit()
            message = f"User created: {username}, admin={is_admin}, role={role}"

        elif level == "MEDIUM":
            new_user = User(username=username, email=email, role="user", password="password123")
            db.session.add(new_user)
            db.session.commit()
            message = f"User created: {username}"

        else:
            new_user = User(username=username, email=email, role="user", password="password123")
            db.session.add(new_user)
            db.session.commit()
            message = f"User created: {username} (secure: only whitelisted fields accepted)"

    return render_template("vulns/mass_assignment.html", message=message, level=level)

@design_flaws_bp.route("/insecure_design/reset-password", methods=["GET", "POST"])
def reset_password():
    level = session.get("security_level", "LOW")
    message = ""

    if request.method == "POST":
        email = request.form.get("email", "")

        if level == "LOW":
            message = f"Password reset link sent to {email} (no rate limiting, unlimited requests)"
        elif level == "MEDIUM":
            message = f"Password reset link sent to {email} (basic rate limit: 5/hour)"
        else:
            message = f"Password reset link sent to {email} (rate limited + CAPTCHA required)"

    return render_template("vulns/reset_password.html", message=message, level=level)
