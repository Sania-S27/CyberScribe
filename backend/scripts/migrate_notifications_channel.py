"""
Database Migration: Add `channel` column to `_tenant_notifications`
------------------------------------------------------------------
Safely adds `channel VARCHAR(50) NOT NULL DEFAULT 'WEBHOOK'` to the existing
`_tenant_notifications` table if it does not already exist.
Preserves all existing records and schema.
"""

import sys
import os
from pathlib import Path

# Add backend directory to sys.path
backend_dir = Path(__file__).resolve().parent.parent
if str(backend_dir) not in sys.path:
    sys.path.insert(0, str(backend_dir))

from sqlalchemy import text, inspect
from app.core.database import engine

def migrate():
    print("[*] Checking _tenant_notifications table schema...")
    inspector = inspect(engine)
    columns = [col['name'] for col in inspector.get_columns('_tenant_notifications')]

    if 'channel' in columns:
        print("[+] Column 'channel' already exists in _tenant_notifications. No migration needed.")
        return

    print("[*] Adding 'channel' column to _tenant_notifications...")
    with engine.begin() as conn:
        conn.execute(text(
            "ALTER TABLE _tenant_notifications "
            "ADD COLUMN channel VARCHAR(50) NOT NULL DEFAULT 'WEBHOOK' AFTER event_type"
        ))
        conn.execute(text(
            "ALTER TABLE _tenant_notifications "
            "ADD INDEX idx_notifications_channel (channel)"
        ))
    print("[+] Successfully added 'channel' column and index to _tenant_notifications.")

if __name__ == "__main__":
    migrate()
