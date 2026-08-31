from flask import Blueprint, render_template, request, session

logging_bp = Blueprint("logging", __name__)

failed_logins = []

@logging_bp.route("/logging")
def logging_demo():
    level = session.get("security_level", "LOW")
    return render_template("vulns/logging.html", failed_logins=failed_logins, level=level)

@logging_bp.route("/logging/test-login", methods=["POST"])
def test_login():
    level = session.get("security_level", "LOW")
    username = request.form.get("username", "")
    password = request.form.get("password", "")

    success = (username == "admin" and password == "admin123")

    if level == "LOW":
        pass

    elif level == "MEDIUM":
        if not success:
            print(f"FAILED LOGIN: user={username} ip={request.remote_addr}")

    else:
        import datetime
        from models import AuditLog, db
        log = AuditLog(
            event="login_attempt",
            user_id=None,
            details=f"user={username} success={success}",
            ip_address=request.remote_addr
        )
        db.session.add(log)
        db.session.commit()

    if success:
        return "Login successful!"
    else:
        if level == "LOW":
            failed_logins.append({"username": username, "ip": request.remote_addr, "time": "not logged"})
        elif level == "MEDIUM":
            failed_logins.append({"username": username, "ip": request.remote_addr, "time": "logged to console"})
        else:
            failed_logins.append({"username": username, "ip": request.remote_addr, "time": "logged to DB"})
        return "Invalid credentials."

@logging_bp.route("/logging/audit-trail")
def audit_trail():
    level = session.get("security_level", "LOW")
    logs = []
    if level == "HIGH":
        from models import AuditLog
        logs = AuditLog.query.order_by(AuditLog.created_at.desc()).limit(50).all()
    return render_template("vulns/audit_trail.html", logs=logs, level=level)
