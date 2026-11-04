"""
Migration Script: Autonomous Containment Actions & Audit Logs
--------------------------------------------------------------
Creates persistent tables `_containment_actions` and `_containment_audit_logs`
to support deterministic autonomous response policy decisions and simulated
firewall state lifecycle tracking in Phase 1.

Preserves all existing data non-destructively.
"""

import os
import sys
import argparse
from sqlalchemy import text, inspect

# Ensure backend path is in sys.path
backend_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if backend_dir not in sys.path:
    sys.path.insert(0, backend_dir)

from app.core.database import SessionLocal, engine, Base
from app.models import ContainmentAction, ContainmentAuditLog


def run_migration(dry_run: bool = True):
    print("=" * 80)
    print("MIGRATION: Autonomous Containment Actions & Audit Tables")
    print(f"Mode: {'[DRY RUN - Read Only]' if dry_run else '[EXECUTE - Live Changes]'}")
    print("=" * 80)

    inspector = inspect(engine)
    existing_tables = inspector.get_table_names()

    target_tables = ["_containment_actions", "_containment_audit_logs"]

    print(f"[*] Checking target tables: {target_tables}")
    for table_name in target_tables:
        exists = table_name in existing_tables
        print(f"    - {table_name}: {'EXISTS' if exists else 'NOT CREATED YET'}")

    if dry_run:
        print("\n[DRY RUN] Actions planned:")
        for table_name in target_tables:
            if table_name in existing_tables:
                print(f"    - Table '{table_name}' already exists. No structural alteration needed.")
            else:
                print(f"    - Table '{table_name}' will be created via Base.metadata.create_all.")
        print("\nRun with --execute to apply live changes.")
        return

    print("\n[*] Applying non-destructive schema migration...")
    # Base.metadata.create_all with explicit tables creates only missing target tables
    tables_to_create = [
        ContainmentAction.__table__,
        ContainmentAuditLog.__table__
    ]
    Base.metadata.create_all(bind=engine, tables=tables_to_create, checkfirst=True)
    print("[OK] Target tables verified / created successfully.")

    # Ensure partial index exists
    with engine.connect() as conn:
        try:
            conn.execute(text(
                "CREATE UNIQUE INDEX IF NOT EXISTS uq_active_tenant_indicator "
                "ON _containment_actions (tenant_id, indicator_value) "
                "WHERE status IN ('PENDING', 'SIMULATED', 'DISPATCHED', 'RECEIVED', 'APPLIED', 'VERIFIED')"
            ))
            conn.commit()
            print("[OK] Partial unique index uq_active_tenant_indicator verified / created.")
        except Exception as idx_err:
            print(f"[!] Partial index notice: {idx_err}")

    # Re-inspect to confirm
    inspector = inspect(engine)
    updated_tables = inspector.get_table_names()
    for table_name in target_tables:
        if table_name in updated_tables:
            print(f"    - Verified '{table_name}' is active in schema.")
        else:
            raise RuntimeError(f"Failed to create table '{table_name}'.")

    print("\n[+] Migration completed non-destructively. Zero existing records modified.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Migrate Containment Action Tables")
    parser.add_argument("--execute", action="store_true", help="Apply schema changes live")
    args = parser.parse_args()

    run_migration(dry_run=not args.execute)
