from flask import Blueprint, render_template, request, flash, session
import sqlite3
import os
import subprocess
import bleach
from models import db, Post, User

injection_bp = Blueprint("injection", __name__)

DB_PATH = "instance/vulnlab.db"

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

@injection_bp.route("/sqli", methods=["GET", "POST"])
def sqli():
    level = session.get("security_level", "LOW")
    results = []
    query_used = ""

    if request.method == "POST":
        search = request.form.get("search", "")

        if level == "LOW":
            query = f"SELECT id, username, email FROM users WHERE username LIKE '%{search}%'"
            query_used = query
            try:
                conn = get_db()
                results = conn.execute(query).fetchall()
                conn.close()
            except Exception as e:
                flash(f"SQL Error: {str(e)}", "danger")

        elif level == "MEDIUM":
            search = search.replace("'", "").replace('"', "")
            query = f"SELECT id, username, email FROM users WHERE username LIKE '%{search}%'"
            query_used = query
            try:
                conn = get_db()
                results = conn.execute(query).fetchall()
                conn.close()
            except Exception as e:
                flash(f"SQL Error: {str(e)}", "danger")

        elif level == "HIGH":
            query_used = "SELECT id, username, email FROM users WHERE username LIKE ?"
            try:
                conn = get_db()
                results = conn.execute(query_used, (f"%{search}%",)).fetchall()
                conn.close()
            except Exception as e:
                flash(f"Error: An error occurred.", "danger")

    return render_template("vulns/sqli.html", results=results, query_used=query_used, level=level)

@injection_bp.route("/xss", methods=["GET", "POST"])
def xss():
    level = session.get("security_level", "LOW")
    comments = Post.query.filter_by(user_id=1).all()

    if request.method == "POST":
        comment = request.form.get("comment", "")
        title = request.form.get("title", "XSS Comment")

        if level == "LOW":
            new_post = Post(title=title, content=comment, user_id=1)
            db.session.add(new_post)
            db.session.commit()
            flash("Comment posted!", "success")

        elif level == "MEDIUM":
            safe_comment = bleach.clean(comment, tags=["b", "i", "u", "em", "strong"], attributes={})
            new_post = Post(title=title, content=safe_comment, user_id=1)
            db.session.add(new_post)
            db.session.commit()
            flash("Comment posted (sanitized)!", "success")

        elif level == "HIGH":
            safe_comment = bleach.clean(comment, tags=[], attributes={})
            new_post = Post(title=title, content=safe_comment, user_id=1)
            db.session.add(new_post)
            db.session.commit()
            flash("Comment posted (all HTML stripped)!", "success")

        comments = Post.query.filter_by(user_id=1).all()

    return render_template("vulns/xss.html", comments=comments, level=level)

@injection_bp.route("/xss/reflected")
def xss_reflected():
    level = session.get("security_level", "LOW")
    name = request.args.get("name", "")
    return render_template("vulns/xss_reflected.html", name=name, level=level)

@injection_bp.route("/xss/dom")
def xss_dom():
    return render_template("vulns/xss_dom.html", level=session.get("security_level", "LOW"))

@injection_bp.route("/command_injection", methods=["GET", "POST"])
def command_injection():
    level = session.get("security_level", "LOW")
    output = ""

    if request.method == "POST":
        ip = request.form.get("ip", "")

        if level == "LOW":
            cmd = f"ping -c 2 {ip}"
            output = f"$ {cmd}\n"
            try:
                result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=5)
                output += result.stdout
                if result.stderr:
                    output += result.stderr
            except subprocess.TimeoutExpired:
                output += "Command timed out."
            except Exception as e:
                output += f"Error: {str(e)}"

        elif level == "MEDIUM":
            if ";" in ip or "|" in ip or "&" in ip or "$" in ip or "`" in ip:
                output = "Blocked: Dangerous characters detected."
            else:
                cmd = f"ping -c 2 {ip}"
                output = f"$ {cmd}\n"
                try:
                    result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=5)
                    output += result.stdout
                    if result.stderr:
                        output += result.stderr
                except subprocess.TimeoutExpired:
                    output += "Command timed out."
                except Exception as e:
                    output += f"Error: {str(e)}"

        elif level == "HIGH":
            import re
            if not re.match(r'^(\d{1,3}\.){3}\d{1,3}$', ip):
                output = "Invalid: Please enter a valid IP address (e.g., 127.0.0.1)"
            else:
                cmd = ["ping", "-c", "2", ip]
                output = f"$ {' '.join(cmd)}\n"
                try:
                    result = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
                    output += result.stdout
                    if result.stderr:
                        output += result.stderr
                except subprocess.TimeoutExpired:
                    output += "Command timed out."
                except Exception as e:
                    output += f"Error: An error occurred."

    return render_template("vulns/command_injection.html", output=output, level=level)
