from flask import Blueprint, render_template, request, session
import traceback

exceptions_bp = Blueprint("exceptions", __name__)

@exceptions_bp.route("/exceptions")
def exceptions_home():
    level = session.get("security_level", "LOW")
    return render_template("vulns/exceptions.html", level=level)

@exceptions_bp.route("/exceptions/error")
def trigger_error():
    level = session.get("security_level", "LOW")

    if level == "LOW":
        try:
            result = 1 / 0
        except Exception as e:
            error_detail = {
                "type": type(e).__name__,
                "message": str(e),
                "traceback": traceback.format_exc(),
                "frame_locals": {"divisor": 0},
                "environment": {
                    "python_version": "3.13.12",
                    "database": "sqlite:///vulnlab.db",
                    "secret_key": "vulnlab-insecure-key-12345",
                    "debug": True,
                }
            }

    elif level == "MEDIUM":
        error_detail = {
            "type": "ZeroDivisionError",
            "message": "An arithmetic error occurred",
            "traceback": None,
            "environment": None
        }

    else:
        error_detail = {
            "type": None,
            "message": "An unexpected error occurred. Please try again later.",
            "traceback": None,
            "environment": None
        }

    return render_template("vulns/error_detail.html", error=error_detail, level=level)

@exceptions_bp.route("/exceptions/api-error")
def api_error():
    level = session.get("security_level", "LOW")

    if level == "LOW":
        return {
            "error": True,
            "message": "DatabaseError: relation 'users' does not exist at character 42",
            "stack": "File \"/app/models.py\", line 42, in query\n    return db.session.execute(text(query)).fetchall()\nsqlalchemy.exc.OperationalError: (sqlite3.OperationalError)",
            "query": "SELECT * FROM nonexistent_table WHERE id=1",
            "config": {
                "DATABASE_URL": "sqlite:///vulnlab.db",
                "SECRET_KEY": "vulnlab-insecure-key-12345",
                "DEBUG": True
            }
        }, 500

    elif level == "MEDIUM":
        return {
            "error": True,
            "message": "Internal Server Error",
            "query": None
        }, 500

    else:
        return {
            "error": True,
            "message": "An error occurred. Please contact support."
        }, 500
