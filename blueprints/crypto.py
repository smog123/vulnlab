from flask import Blueprint, render_template, request, flash, session
from models import db, User
import hashlib
import bcrypt

crypto_bp = Blueprint("crypto", __name__)

@crypto_bp.route("/weak_crypto")
def weak_crypto():
    level = session.get("security_level", "LOW")

    demo_password = "MySecretPassword123"

    if level == "LOW":
        md5_hash = hashlib.md5(demo_password.encode()).hexdigest()
        sha1_hash = hashlib.sha1(demo_password.encode()).hexdigest()
        method = "MD5 + SHA1 (unsalted)"
        strength = "Trivially reversible with rainbow tables"
    elif level == "MEDIUM":
        sha256_hash = hashlib.sha256(demo_password.encode()).hexdigest()
        method = "SHA-256 (unsalted)"
        strength = "Vulnerable to rainbow tables, fast to brute force"
        md5_hash = sha256_hash
        sha1_hash = sha256_hash
    else:
        bcrypt_hash = bcrypt.hashpw(demo_password.encode(), bcrypt.gensalt(12)).decode()
        method = "bcrypt (cost=12, salted)"
        strength = "Resistant to rainbow tables and brute force"
        md5_hash = bcrypt_hash
        sha1_hash = bcrypt_hash

    hardcoded_key = "super-secret-key-do-not-share"

    return render_template("vulns/weak_crypto.html",
        method=method, strength=strength,
        demo_password=demo_password,
        hash_result=md5_hash,
        hardcoded_key=hardcoded_key,
        level=level)
