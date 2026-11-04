"""
Migration Script: Standardize Threat Remediation Statuses
---------------------------------------------------------
Simplifies CyberScribe's status taxonomy from legacy ('unmitigated', 'triaged', 'patched', 'mitigated', 'active')
to standardized enterprise statuses:
  - 'OPEN'
  - 'IN_PROGRESS'
  - 'RESOLVED'

Mapping rules:
  - 'unmitigated' -> 'OPEN'
  - 'triaged'     -> 'OPEN'
  - 'active'      -> 'OPEN'
  - 'patched'     -> 'RESOLVED'
  - 'mitigated'   -> 'RESOLVED'
"""

import os
import sys
import argparse
from sqlalchemy import text

# Ensure backend path is in sys.path
backend_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if backend_dir not in sys.path:
    sys.path.insert(0, backend_dir)

from app.core.database import SessionLocal, engine
from app.models import ThreatMatch


def run_migration(dry_run: bool = True):
    print("=" * 80)
    print("MIGRATION: Standardize ThreatMatch Remediation Statuses")
    print(f"Mode: {'[DRY RUN - Read Only]' if dry_run else '[EXECUTE - Live Changes]'}")
    print("=" * 80)

    db = SessionLocal()
    try:
        # 1. Inspect current status counts
        with engine.connect() as conn:
            counts = conn.execute(
                text("SELECT status, count(*) FROM _threat_matches GROUP BY status")
            ).fetchall()
            print("\n[+] Current status distribution in `_threat_matches`:")
            for s, c in counts:
                print(f"    - {s}: {c} records")

        if dry_run:
            print("\n[DRY RUN] Proposed Changes:")
            print("  1. Alter table column `_threat_matches.status` enum to include 'OPEN', 'IN_PROGRESS', 'RESOLVED'")
            print("  2. Update all 'unmitigated', 'triaged', 'active' records -> 'OPEN'")
            print("  3. Update all 'patched', 'mitigated' records -> 'RESOLVED'")
            print("\nTo apply these changes live, rerun with --execute")
            return

        print("\n[*] Applying database schema alteration (if not already applied)...")
        with engine.connect() as conn:
            conn.execute(
                text(
                    "ALTER TABLE _threat_matches MODIFY COLUMN status "
                    "ENUM('OPEN', 'IN_PROGRESS', 'RESOLVED', 'unmitigated', 'triaged', 'patched', 'mitigated', 'active') "
                    "DEFAULT 'OPEN'"
                )
            )
            conn.commit()
            print("[OK] Schema updated: ENUM expanded with 'OPEN', 'IN_PROGRESS', 'RESOLVED'.")

            print("\n[*] Migrating existing rows...")
            res_open = conn.execute(
                text("UPDATE _threat_matches SET status = 'OPEN' WHERE status IN ('unmitigated', 'triaged', 'active')")
            )
            res_resolved = conn.execute(
                text("UPDATE _threat_matches SET status = 'RESOLVED' WHERE status IN ('patched', 'mitigated')")
            )
            conn.commit()

            print(f"[OK] Migrated {res_open.rowcount} rows to 'OPEN'")
            print(f"[OK] Migrated {res_resolved.rowcount} rows to 'RESOLVED'")

            # Verify post-migration state
            new_counts = conn.execute(
                text("SELECT status, count(*) FROM _threat_matches GROUP BY status")
            ).fetchall()
            print("\n[+] Verified post-migration status distribution:")
            for s, c in new_counts:
                print(f"    - {s}: {c} records")

        print("\n" + "=" * 80)
        print("[SUCCESS] Status remediation migration completed cleanly!")
        print("=" * 80)

    except Exception as e:
        db.rollback()
        print(f"\n[ERROR] Migration failed: {e}")
        raise
    finally:
        db.close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Migrate threat match statuses to OPEN/IN_PROGRESS/RESOLVED")
    parser.add_argument("--execute", action="store_true", help="Execute live changes against the database")
    args = parser.parse_args()

    run_migration(dry_run=not args.execute)
