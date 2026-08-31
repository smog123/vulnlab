from flask import Blueprint, request, jsonify, session
from flask_restful import Api, Resource
from flask_login import login_required, current_user
import sqlite3
import os
import bcrypt
import jwt
import datetime
import pickle
import base64
from models import db, User, Note, Post, ApiKey, Transaction

api_bp = Blueprint("api", __name__)
api = Api(api_bp)

DB_PATH = "instance/vulnlab.db"

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

class UserListResource(Resource):
    def get(self):
        level = request.args.get("level", session.get("security_level", "LOW"))
        users = User.query.all()
        return jsonify([{
            "id": u.id, "username": u.username, "email": u.email,
            "role": u.role, "is_admin": u.is_admin
        } for u in users])

class UserNotesResource(Resource):
    def get(self, user_id):
        level = session.get("security_level", "LOW")
        if level == "LOW":
            notes = Note.query.filter_by(user_id=user_id).all()
        else:
            if current_user.is_authenticated and current_user.id == user_id:
                notes = Note.query.filter_by(user_id=user_id).all()
            else:
                return {"error": "Access denied"}, 403
        return jsonify([{
            "id": n.id, "title": n.title, "content": n.content, "is_private": n.is_private
        } for n in notes])

class CreateNoteResource(Resource):
    def post(self):
        level = session.get("security_level", "LOW")
        data = request.get_json(force=True)

        if level == "LOW":
            note = Note(
                title=data.get("title", ""),
                content=data.get("content", ""),
                user_id=data.get("user_id", 1),
                is_private=data.get("is_private", True)
            )
        else:
            note = Note(
                title=data.get("title", ""),
                content=data.get("content", ""),
                user_id=current_user.id if current_user.is_authenticated else 1,
                is_private=True
            )
        db.session.add(note)
        db.session.commit()
        return {"message": "Note created", "id": note.id}, 201

class SearchResource(Resource):
    def get(self):
        level = session.get("security_level", "LOW")
        q = request.args.get("q", "")
        if level == "LOW":
            conn = get_db()
            results = conn.execute(f"SELECT id, username, email FROM users WHERE username LIKE '%{q}%'").fetchall()
            conn.close()
        else:
            conn = get_db()
            results = conn.execute("SELECT id, username, email FROM users WHERE username LIKE ?", (f"%{q}%",)).fetchall()
            conn.close()
        return jsonify([dict(r) for r in results])

class TransferResource(Resource):
    def post(self):
        level = session.get("security_level", "LOW")
        data = request.get_json(force=True)
        amount = data.get("amount", 0)
        to_user = data.get("to_user_id", 1)

        if level == "LOW":
            tx = Transaction(user_id=1, amount=amount, description="API Transfer")
        else:
            if amount <= 0:
                return {"error": "Invalid amount"}, 400
            tx = Transaction(user_id=1, amount=-amount, description="API Transfer")
            credit = Transaction(user_id=to_user, amount=amount, description="API Transfer")
            db.session.add(credit)

        db.session.add(tx)
        db.session.commit()
        return {"message": "Transfer complete", "amount": amount}

class UploadResource(Resource):
    def post(self):
        level = session.get("security_level", "LOW")
        if "file" not in request.files:
            return {"error": "No file"}, 400
        file = request.files["file"]
        if level == "LOW":
            filename = file.filename
            file.save(f"/tmp/{filename}")
            return {"message": f"File saved as {filename}"}
        else:
            import re
            if not re.match(r'^[\w\-. ]+\.(jpg|jpeg|png|gif|pdf|txt)$', file.filename):
                return {"error": "Invalid file type"}, 400
            filename = file.filename
            file.save(f"/tmp/{filename}")
            return {"message": f"File saved as {filename}"}

class ConfigResource(Resource):
    def get(self):
        level = session.get("security_level", "LOW")
        if level == "LOW":
            return {
                "database": "sqlite:///vulnlab.db",
                "secret_key": "vulnlab-insecure-key-12345",
                "debug": True,
                "admin_password": "admin123",
                "jwt_secret": "jwt-secret"
            }
        elif level == "MEDIUM":
            return {
                "database": "configured",
                "debug": False
            }
        else:
            return {"status": "ok"}

class LoginResource(Resource):
    def post(self):
        data = request.get_json(force=True)
        username = data.get("username", "")
        password = data.get("password", "")
        user = User.query.filter_by(username=username).first()

        if user and bcrypt.checkpw(password.encode(), user.password.encode()):
            level = session.get("security_level", "LOW")
            if level == "LOW":
                token = jwt.encode(
                    {"user": user.username, "role": user.role, "admin": user.is_admin,
                     "exp": datetime.datetime.utcnow() + datetime.timedelta(hours=24)},
                    "jwt-secret", algorithm="HS256"
                )
            elif level == "MEDIUM":
                token = jwt.encode(
                    {"user": user.username, "role": user.role,
                     "exp": datetime.datetime.utcnow() + datetime.timedelta(hours=24)},
                    "jwt-secret", algorithm="HS256"
                )
            else:
                token = jwt.encode(
                    {"user": user.username, "role": user.role,
                     "exp": datetime.datetime.utcnow() + datetime.timedelta(minutes=15)},
                    "jwt-secret", algorithm="HS256"
                )
            return {"token": token, "user": user.username, "role": user.role}
        return {"error": "Invalid credentials"}, 401

api.add_resource(UserListResource, "/users")
api.add_resource(UserNotesResource, "/users/<int:user_id>/notes")
api.add_resource(CreateNoteResource, "/notes")
api.add_resource(SearchResource, "/search")
api.add_resource(TransferResource, "/transfer")
api.add_resource(UploadResource, "/upload")
api.add_resource(ConfigResource, "/config")
api.add_resource(LoginResource, "/auth/login")
