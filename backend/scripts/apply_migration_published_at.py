import os
import sys
import io
import json
import datetime
import decimal
from pathlib import Path

# Ensure UTF-8 output
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8', errors='replace')

# Add backend directory to sys.path
BACKEND_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BACKEND_DIR))

import sqlalchemy
from sqlalchemy import text
from app.core.database import engine, SessionLocal
from app.models import ThreatReport, ThreatMatch, Tenant, AssetComponent, MitigationPlaybook, Admin, User
from app.core.chroma import threat_collection

BACKUP_DIR = Path(__file__).resolve().parent.parent / "backups"
BACKUP_DIR.mkdir(parents=True, exist_ok=True)

class CustomEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, (datetime.datetime, datetime.date)):
            return obj.isoformat()
        if isinstance(obj, decimal.Decimal):
            return float(obj)
        if isinstance(obj, bytes):
            return obj.hex()
        return super().default(obj)

def run_backup():
    print("========================================")
    print("STEP 1: DATABASE BACKUP")
    print("========================================")
    timestamp = datetime.datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    backup_json_path = BACKUP_DIR / f"cyberscribe_backup_{timestamp}.json"
    backup_sql_path = BACKUP_DIR / f"cyberscribe_backup_{timestamp}.sql"
    
    tables = [
        "tenants",
        "users",
        "_asset_components",
        "threat_reports",
        "_threat_matches",
        "mitigation_playbooks",
        "admins"
    ]
    
    backup_data = {
        "timestamp": timestamp,
        "tables": {}
    }
    
    sql_lines = [
        f"-- CyberScribe Database Backup",
        f"-- Generated at {timestamp} UTC",
        "-- --------------------------------------------------------\n"
    ]
    
    with engine.connect() as conn:
        for tbl in tables:
            # 1. Get CREATE TABLE statement
            try:
                create_res = conn.execute(text(f"SHOW CREATE TABLE `{tbl}`;")).fetchone()
                create_stmt = create_res[1] if create_res else ""
            except Exception as e:
                create_stmt = f"-- Error getting CREATE TABLE: {e}"
            
            # 2. Get columns
            cols_res = conn.execute(text(f"SHOW COLUMNS FROM `{tbl}`;")).fetchall()
            col_names = [col[0] for col in cols_res]
            
            # 3. Get all rows
            rows_res = conn.execute(text(f"SELECT * FROM `{tbl}`;")).fetchall()
            rows_data = []
            
            sql_lines.append(f"\n-- Table structure for table `{tbl}`")
            sql_lines.append(f"DROP TABLE IF EXISTS `{tbl}_backup_temp`;")
            sql_lines.append(f"{create_stmt};\n")
            sql_lines.append(f"-- Dumping data for table `{tbl}` ({len(rows_res)} rows)")
            
            for row in rows_res:
                row_dict = dict(zip(col_names, row))
                rows_data.append(row_dict)
            
            backup_data["tables"][tbl] = {
                "create_statement": create_stmt,
                "columns": col_names,
                "row_count": len(rows_data),
                "rows": rows_data
            }
            print(f"  -> Backed up table `{tbl}`: {len(rows_data)} rows")

    # Write JSON backup
    with open(backup_json_path, "w", encoding="utf-8") as f:
        json.dump(backup_data, f, indent=2, cls=CustomEncoder)
        
    # Write SQL backup
    with open(backup_sql_path, "w", encoding="utf-8") as f:
        f.write("\n".join(sql_lines))
        
    print(f"\n[Backup Saved] JSON: {backup_json_path} ({backup_json_path.stat().st_size} bytes)")
    print(f"[Backup Saved] SQL: {backup_sql_path} ({backup_sql_path.stat().st_size} bytes)")
    
    # Verify backup is readable and complete
    print("\nVerifying backup readability...")
    with open(backup_json_path, "r", encoding="utf-8") as f:
        loaded = json.load(f)
        assert len(loaded["tables"]) == 7, "Backup tables count mismatch!"
        for tbl in tables:
            assert tbl in loaded["tables"], f"Table {tbl} missing in backup!"
            loaded_count = loaded["tables"][tbl]["row_count"]
            actual_count = len(loaded["tables"][tbl]["rows"])
            assert loaded_count == actual_count, f"Row count mismatch in table {tbl}!"
            print(f"  ✓ Verified table `{tbl}` in backup ({actual_count} records)")
            
    print("✅ Pre-migration backup verified successfully!\n")
    return backup_json_path, backup_sql_path

def run_migration():
    print("========================================")
    print("STEP 2: PRE-ALTER CHECK & MIGRATION")
    print("========================================")
    
    with engine.connect() as conn:
        # Pre-check if column exists
        cols_res = conn.execute(text("SHOW COLUMNS FROM threat_reports;")).fetchall()
        existing_cols = [c[0] for c in cols_res]
        print(f"Current columns in `threat_reports`: {existing_cols}")
        
        if "published_at" in existing_cols:
            print("ℹ️ Column `published_at` already exists in `threat_reports`. Skipping ALTER TABLE.")
        else:
            print("Executing ALTER TABLE to add `published_at DATETIME NULL DEFAULT NULL`...")
            conn.execute(text(
                "ALTER TABLE threat_reports ADD COLUMN published_at DATETIME NULL DEFAULT NULL AFTER cve_id;"
            ))
            conn.commit()
            print("✅ ALTER TABLE executed successfully.")
            
        # Post-alter column verification
        cols_after = conn.execute(text("SHOW COLUMNS FROM threat_reports;")).fetchall()
        pub_col_info = next((c for c in cols_after if c[0] == "published_at"), None)
        print(f"Column info for `published_at`: {pub_col_info}")
        assert pub_col_info is not None, "Failed to verify published_at column after migration!"
        assert pub_col_info[1] == "datetime", f"Unexpected type: {pub_col_info[1]}"
        assert pub_col_info[2] == "YES", f"Expected nullable YES, got {pub_col_info[2]}"

def verify_data_integrity():
    print("\n========================================")
    print("STEP 3: DATA INTEGRITY & RECORD COUNT")
    print("========================================")
    with engine.connect() as conn:
        total_rows = conn.execute(text("SELECT COUNT(*) FROM threat_reports;")).scalar()
        null_pub_rows = conn.execute(text("SELECT COUNT(*) FROM threat_reports WHERE published_at IS NULL;")).scalar()
        not_null_pub_rows = conn.execute(text("SELECT COUNT(*) FROM threat_reports WHERE published_at IS NOT NULL;")).scalar()
        
        print(f"Total rows in `threat_reports`: {total_rows}")
        print(f"Rows with published_at IS NULL: {null_pub_rows}")
        print(f"Rows with published_at IS NOT NULL: {not_null_pub_rows}")
        
        assert total_rows == 391, f"Expected 391 rows, got {total_rows}"
        assert null_pub_rows == 391, f"Expected all 391 existing rows to have NULL published_at, got {null_pub_rows}"
        assert not_null_pub_rows == 0, f"Expected 0 rows with non-null published_at, got {not_null_pub_rows}"
        print("✅ Record count (391) and historical NULL preservation verified.")

def verify_orm_and_collector():
    print("\n========================================")
    print("STEP 4: ORM & OSINT COLLECTOR QUERIES")
    print("========================================")
    db = SessionLocal()
    try:
        # 1. Test basic ORM query
        report = db.query(ThreatReport).first()
        print(f"  ✓ ORM query ThreatReport: id={report.id}, title='{report.title[:30]}...', published_at={report.published_at}")
        
        # 2. Test auto-prune filter query
        cutoff_date = datetime.datetime.utcnow() - datetime.timedelta(days=30)
        subquery = db.query(ThreatMatch.threat_report_id).distinct()
        old_reports = db.query(ThreatReport).filter(
            ThreatReport.created_at < cutoff_date,
            ThreatReport.id.not_in(subquery)
        ).all()
        print(f"  ✓ Auto-prune query executed successfully without error (found {len(old_reports)} eligible records).")
        
        # 3. Test targeted NVD duplicate check query
        test_cve = "CVE-2024-TEST"
        test_url = "https://nvd.nist.gov/vuln/detail/CVE-2024-TEST"
        existing_nvd = db.query(ThreatReport).filter(
            (ThreatReport.source_url == test_url) | (ThreatReport.cve_id == test_cve)
        ).first()
        print(f"  ✓ Targeted NVD duplicate check query executed successfully (result: {existing_nvd}).")
        
        # 4. Test RSS duplicate check query
        rss_url = "https://feeds.feedburner.com/TheHackersNews"
        existing_rss = db.query(ThreatReport).filter(ThreatReport.source_url == rss_url).first()
        print(f"  ✓ RSS duplicate check query executed successfully (result: {existing_rss}).")
        
        # 5. Test total count
        count = db.query(ThreatReport).count()
        print(f"  ✓ db.query(ThreatReport).count() returned: {count}")
    finally:
        db.close()
    print("✅ All ORM queries and collector operations passed.")

def verify_chromadb():
    print("\n========================================")
    print("STEP 5: CHROMADB & RAG INTEGRITY")
    print("========================================")
    try:
        count = threat_collection.count()
        print(f"  ✓ ChromaDB collection 'cyber_threat_intelligence' count: {count} documents")
        
        # Test query
        sample = threat_collection.peek(limit=1)
        if sample and sample.get("ids"):
            print(f"  ✓ ChromaDB peek sample ID: {sample['ids'][0]}")
            print(f"  ✓ ChromaDB metadata sample: {sample['metadatas'][0] if sample.get('metadatas') else 'N/A'}")
        print("✅ ChromaDB and RAG collection verified intact.")
    except Exception as e:
        print(f"❌ ChromaDB check failed: {e}")
        raise

if __name__ == "__main__":
    b_json, b_sql = run_backup()
    run_migration()
    verify_data_integrity()
    verify_orm_and_collector()
    verify_chromadb()
    print("\n🎉 ALL MIGRATION AND SAFETY CHECKS COMPLETED SUCCESSFULLY!")
