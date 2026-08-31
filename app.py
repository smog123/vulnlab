import os
import pickle
import base64
from flask import Flask, session, redirect, url_for, render_template, request
from flask_login import LoginManager, current_user
from flask_cors import CORS
from models import db, User
from config import Config

login_manager = LoginManager()

def create_app():
    app = Flask(__name__)
    app.config.from_object(Config)

    db.init_app(app)
    login_manager.init_app(app)
    login_manager.login_view = "auth.login"

    CORS(app, resources={r"/api/*": {"origins": "*"}})

    @login_manager.user_loader
    def load_user(user_id):
        return db.session.get(User, int(user_id))

    @app.before_request
    def set_security_level():
        g_level = request.args.get("level")
        if g_level in ("LOW", "MEDIUM", "HIGH"):
            session["security_level"] = g_level
        if "security_level" not in session:
            session["security_level"] = "LOW"

    @app.context_processor
    def inject_security_level():
        return dict(security_level=session.get("security_level", "LOW"))

    @app.route("/")
    def index():
        return render_template("index.html")

    from blueprints.auth import auth_bp
    from blueprints.injection import injection_bp
    from blueprints.access_control import access_control_bp
    from blueprints.crypto import crypto_bp
    from blueprints.misconfig import misconfig_bp
    from blueprints.design_flaws import design_flaws_bp
    from blueprints.integrity import integrity_bp
    from blueprints.logging_failures import logging_bp
    from blueprints.exceptions import exceptions_bp
    from blueprints.csrf import csrf_bp
    from api.api_v1 import api_bp

    app.register_blueprint(auth_bp, url_prefix="/auth")
    app.register_blueprint(injection_bp, url_prefix="/vulns")
    app.register_blueprint(access_control_bp, url_prefix="/vulns")
    app.register_blueprint(crypto_bp, url_prefix="/vulns")
    app.register_blueprint(misconfig_bp, url_prefix="/vulns")
    app.register_blueprint(design_flaws_bp, url_prefix="/vulns")
    app.register_blueprint(integrity_bp, url_prefix="/vulns")
    app.register_blueprint(logging_bp, url_prefix="/vulns")
    app.register_blueprint(exceptions_bp, url_prefix="/vulns")
    app.register_blueprint(csrf_bp, url_prefix="/vulns")
    app.register_blueprint(api_bp, url_prefix="/api/v1")

    with app.app_context():
        db.create_all()

    return app

if __name__ == "__main__":
    app = create_app()
    app.run(host="0.0.0.0", port=5000, debug=True)
