import sys
import os
backend_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if backend_dir not in sys.path:
    sys.path.insert(0, backend_dir)

from app.core.database import engine, Base
from app.models import TenantNotification
from sqlalchemy import inspect

def run_migration():
    insp = inspect(engine)
    tables = insp.get_table_names()
    if "_tenant_notifications" not in tables:
        TenantNotification.__table__.create(bind=engine)
        print("[SUCCESS] Created table '_tenant_notifications'.")
    else:
        print("[INFO] Table '_tenant_notifications' already exists.")

if __name__ == "__main__":
    run_migration()
