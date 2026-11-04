import sys
import os
backend_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if backend_dir not in sys.path:
    sys.path.insert(0, backend_dir)

from app.core.database import engine
from sqlalchemy import text, inspect

def run_migration():
    insp = inspect(engine)
    cols = [c["name"] for c in insp.get_columns("tenants")]
    if "remediation_policy" not in cols:
        with engine.connect() as conn:
            conn.execute(text("ALTER TABLE tenants ADD COLUMN remediation_policy VARCHAR(50) DEFAULT 'NOTIFY';"))
            conn.commit()
            print("[SUCCESS] Added column 'remediation_policy' to table 'tenants'.")
    else:
        print("[INFO] Column 'remediation_policy' already exists in table 'tenants'.")

if __name__ == "__main__":
    run_migration()
