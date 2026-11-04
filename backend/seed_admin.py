# backend/seed_admin.py
import os
from sqlalchemy import text
from app.core.database import SessionLocal, engine, Base
from app import models
from app.api.auth import get_password_hash

# 1. Drop existing legacy 'admins' table with the old schema
with engine.connect() as conn:
    conn.execute(text("DROP TABLE IF EXISTS admins;"))
    conn.commit()

# 2. Recreate tables according to current SQLAlchemy models
Base.metadata.create_all(bind=engine)

db = SessionLocal()

admin_email = os.getenv("SEED_ADMIN_EMAIL", "admin@cyberscribe.local")
admin_pass = os.getenv("SEED_ADMIN_PASSWORD", "Admin@123")

# 3. Create Super Admin with email + password_hash only
new_admin = models.Admin(
    email=admin_email,
    password_hash=get_password_hash(admin_pass),
    role="super_admin"
)
db.add(new_admin)
db.commit()

print("\n==========================================")
print("✅ Admins table recreated & Admin seeded successfully!")
print(f"📧 Super Admin Email:    {admin_email}")
print(f"🔑 Super Admin Password: {admin_pass}")
print("==========================================\n")

db.close()
