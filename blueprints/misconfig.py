from flask import Blueprint, render_template, session, current_app
import os
import sys
import traceback

misconfig_bp = Blueprint("misconfig", __name__)

@misconfig_bp.route("/misconfig")
def misconfig_home():
    return render_template("vulns/misconfig.html", level=session.get("security_level", "LOW"))

@misconfig_bp.route("/misconfig/secret-files")
def secret_files():
    level = session.get("security_level", "LOW")
    files_found = []

    if level == "LOW":
        secret_dir = os.path.join(os.path.dirname(__file__), "..")
        sensitive_files = [".env", ".git/config", ".git/HEAD", "config.py", "seed_db.py", "requirements.txt"]
        for f in sensitive_files:
            path = os.path.join(secret_dir, f)
            if os.path.exists(path):
                try:
                    with open(path, "r") as fh:
                        content = fh.read()[:500]
                    files_found.append({"name": f, "content": content, "accessible": True})
                except:
                    files_found.append({"name": f, "content": "Could not read", "accessible": True})
            else:
                files_found.append({"name": f, "content": "Not found", "accessible": False})

    elif level == "MEDIUM":
        files_found = [
            {"name": ".env", "content": "SECRET_KEY=vulnlab-insecure-key-12345", "accessible": True},
            {"name": ".git/config", "content": "Access Denied", "accessible": False},
        ]
    else:
        files_found = [
            {"name": ".env", "content": "404 Not Found", "accessible": False},
            {"name": ".git/config", "content": "404 Not Found", "accessible": False},
        ]

    return render_template("vulns/secret_files.html", files=files_found, level=level)

@misconfig_bp.route("/misconfig/error")
def error_demo():
    level = session.get("security_level", "LOW")

    if level == "LOW":
        try:
            result = 1 / 0
        except Exception as e:
            error_info = traceback.format_exc()
    elif level == "MEDIUM":
        error_info = "Internal Server Error (500)"
    else:
        error_info = "An error occurred. Please try again later."

    return render_template("vulns/error_demo.html", error_info=error_info, level=level)

@misconfig_bp.route("/misconfig/debug")
def debug_console():
    level = session.get("security_level", "LOW")
    return render_template("vulns/debug_console.html", level=level)
