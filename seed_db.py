import bcrypt
from app import create_app
from models import db, User, Post, Note, ApiKey, Transaction

def seed():
    app = create_app()
    with app.app_context():
        db.drop_all()
        db.create_all()

        admin_pw = bcrypt.hashpw(b"admin123", bcrypt.gensalt()).decode()
        user_pw = bcrypt.hashpw(b"user123", bcrypt.gensalt()).decode()
        weak_pw = bcrypt.hashpw(b"password", bcrypt.gensalt()).decode()

        admin = User(username="admin", password=admin_pw, role="admin", is_admin=True, email="admin@vulnlab.local")
        user1 = User(username="alice", password=user_pw, role="user", email="alice@vulnlab.local")
        user2 = User(username="bob", password=user_pw, role="user", email="bob@vulnlab.local")
        user3 = User(username="charlie", password=weak_pw, role="user", email="charlie@vulnlab.local")

        db.session.add_all([admin, user1, user2, user3])
        db.session.flush()

        posts = [
            Post(title="Welcome to VulnLab", content="This is an intentionally vulnerable application for security training.", user_id=admin.id),
            Post(title="Alice's Post", content="Hello world, this is alice's first post.", user_id=user1.id),
            Post(title="Bob's Secret Post", content="This post contains sensitive information about the project.", user_id=user2.id),
        ]

        notes = [
            Note(title="Admin Secrets", content="Database password: P@ssw0rd123\nAPI Key: sk-1234567890abcdef", user_id=admin.id, is_private=True),
            Note(title="Alice's Note", content="Remember to fix the SQL injection bug.", user_id=user1.id, is_private=True),
            Note(title="Public Draft", content="This is a public note from bob.", user_id=user2.id, is_private=False),
        ]

        api_keys = [
            ApiKey(key="ak-admin-1234567890abcdef", user_id=admin.id),
            ApiKey(key="ak-alice-abcdef1234567890", user_id=user1.id),
        ]

        transactions = [
            Transaction(user_id=user1.id, amount=100.00, description="Initial deposit"),
            Transaction(user_id=user2.id, amount=250.50, description="Monthly salary"),
            Transaction(user_id=admin.id, amount=1000.00, description="Admin transfer"),
        ]

        db.session.add_all(posts + notes + api_keys + transactions)
        db.session.commit()
        print("Database seeded successfully!")
        print("  Users: admin/admin123, alice/user123, bob/user123, charlie/password")

if __name__ == "__main__":
    seed()
