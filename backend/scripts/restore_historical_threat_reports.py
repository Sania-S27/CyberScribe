"""
CyberScribe Historical Threat Reports Recovery Script.

Non-destructive selective restoration tool.
Restores only verified missing threat reports from a pre-migration JSON backup.
Does NOT overwrite existing records, drop tables, or alter foreign keys.
"""

import os
import sys
import json
import argparse
from datetime import datetime
from sqlalchemy import text

# Ensure backend root is on sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from app.core.database import SessionLocal, engine
from app import models


def audit_and_restore(backup_path: str, dry_run: bool = True):
    print(f"[*] Reading backup file: {backup_path}")
    if not os.path.exists(backup_path):
        print(f"[!] Error: Backup file not found at {backup_path}")
        return

    with open(backup_path, "r", encoding="utf-8") as f:
        backup_data = json.load(f)

    if "tables" not in backup_data or "threat_reports" not in backup_data["tables"]:
        print("[!] Error: Invalid backup structure. 'threat_reports' table not found.")
        return

    backup_threat_table = backup_data["tables"]["threat_reports"]
    backup_rows = backup_threat_table.get("rows", [])
    backup_count = len(backup_rows)
    print(f"[*] Backup contains {backup_count} threat reports.")

    db = SessionLocal()
    try:
        # Fetch existing live records
        live_records = db.query(models.ThreatReport).all()
        live_count = len(live_records)
        live_ids = set(r.id for r in live_records)
        live_urls = set(r.source_url for r in live_records if r.source_url)
        live_cves = set(r.cve_id for r in live_records if r.cve_id)

        print(f"[*] Live database contains {live_count} threat reports.")

        # Identify missing records
        missing_records = []
        skipped_records = []

        for row in backup_rows:
            report_id = row.get("id")
            source_url = row.get("source_url")
            cve_id = row.get("cve_id")

            # Check if record already exists by ID
            if report_id in live_ids:
                skipped_records.append({"id": report_id, "reason": "ID already exists in live database"})
                continue

            # Check if source_url exists
            if source_url and source_url in live_urls:
                skipped_records.append({"id": report_id, "source_url": source_url, "reason": "source_url already exists in live database"})
                continue

            # Check if cve_id exists (for targeted CVE entries)
            if cve_id and cve_id in live_cves:
                skipped_records.append({"id": report_id, "cve_id": cve_id, "reason": "cve_id already exists in live database"})
                continue

            missing_records.append(row)

        print("\n================ AUDIT SUMMARY ================")
        print(f"Total backup records:            {backup_count}")
        print(f"Total live records:              {live_count}")
        print(f"Existing records in both:        {len(skipped_records)}")
        print(f"Missing records to restore:      {len(missing_records)}")
        print(f"Expected post-recovery total:    {live_count + len(missing_records)}")
        print("===============================================\n")

        if dry_run:
            print("[*] [DRY RUN] No records were modified or inserted. Run with --execute to perform recovery.")
            return

        print(f"[*] [EXECUTION] Inserting {len(missing_records)} missing historical records...")
        inserted_count = 0
        for item in missing_records:
            # Parse created_at / updated_at
            created_at = None
            if item.get("created_at"):
                try:
                    created_at = datetime.fromisoformat(item["created_at"])
                except Exception:
                    created_at = None

            updated_at = None
            if item.get("updated_at"):
                try:
                    updated_at = datetime.fromisoformat(item["updated_at"])
                except Exception:
                    updated_at = None

            published_at = None
            if item.get("published_at"):
                try:
                    published_at = datetime.fromisoformat(item["published_at"])
                except Exception:
                    published_at = None

            report = models.ThreatReport(
                id=item["id"],
                source_url=item.get("source_url"),
                title=item.get("title") or "Untitled Threat",
                summary=item.get("summary"),
                severity=item.get("severity") or "unknown",
                stix_bundle=item.get("stix_bundle"),
                cve_id=item.get("cve_id"),
                created_at=created_at,
                updated_at=updated_at,
                published_at=published_at
            )
            db.add(report)
            inserted_count += 1

        db.commit()
        print(f"[+] Successfully inserted {inserted_count} historical records!")

        # Verify final live count
        final_count = db.query(models.ThreatReport).count()
        print(f"[+] Verified new live database count: {final_count} threat reports.")

    except Exception as e:
        db.rollback()
        print(f"[!] Error during recovery: {e}")
        raise
    finally:
        db.close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Selective historical threat recovery")
    parser.add_argument(
        "--backup",
        type=str,
        default=os.path.join(os.path.dirname(__file__), "..", "backups", "cyberscribe_backup_20261010_123328.json"),
        help="Path to JSON backup file"
    )
    parser.add_argument(
        "--execute",
        action="store_true",
        help="Perform actual database insertions (default is dry-run)"
    )
    args = parser.parse_args()

    audit_and_restore(backup_path=args.backup, dry_run=not args.execute)
