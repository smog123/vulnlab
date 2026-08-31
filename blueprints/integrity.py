from flask import Blueprint, render_template, request, flash, session
import pickle
import base64
import json

integrity_bp = Blueprint("integrity", __name__)

@integrity_bp.route("/integrity")
def integrity():
    return render_template("vulns/integrity.html", level=session.get("security_level", "LOW"))

@integrity_bp.route("/integrity/deserialize", methods=["GET", "POST"])
def deserialize():
    level = session.get("security_level", "LOW")
    result = ""

    if request.method == "POST":
        data = request.form.get("data", "")

        if level == "LOW":
            try:
                decoded = base64.b64decode(data)
                obj = pickle.loads(decoded)
                result = f"Deserialized object: {obj}"
            except Exception as e:
                result = f"Error: {str(e)}"

        elif level == "MEDIUM":
            try:
                obj = json.loads(data)
                result = f"Parsed JSON: {obj}"
            except:
                result = "Invalid JSON"

        else:
            try:
                obj = json.loads(data)
                if isinstance(obj, dict) and "username" in obj and "email" in obj:
                    allowed_keys = {"username", "email"}
                    sanitized = {k: v for k, v in obj.items() if k in allowed_keys}
                    result = f"Validated and parsed: {sanitized}"
                else:
                    result = "Invalid: Expected object with 'username' and 'email' fields"
            except:
                result = "Invalid JSON"

    return render_template("vulns/deserialize.html", result=result, level=level)

@integrity_bp.route("/integrity/cookies")
def cookie_tampering():
    level = session.get("security_level", "LOW")
    return render_template("vulns/cookie_tampering.html", level=level)
