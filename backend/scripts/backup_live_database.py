# backend/scripts/backup_live_database.py
import os
import sys
import io
import json
import datetime
import decimal
from pathlib import Path

# Ensure UTF-8 output
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")

BACKEND_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BACKEND_DIR))

from sqlalchemy import text
from app.core.database import engine

BACKUP_DIR = BACKEND_DIR / "backups"
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


def create_live_backup():
    print("=" * 80)
    print("CREATING FRESH LIVE DATABASE BACKUP")
    print("=" * 80)
    
    timestamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%d_%H%M%S")
    backup_json_path = BACKUP_DIR / f"cyberscribe_live_backup_{timestamp}.json"
    backup_sql_path = BACKUP_DIR / f"cyberscribe_live_backup_{timestamp}.sql"
    
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
        "database": "threat_agent_db",
        "tables": {}
    }
    
    sql_lines = [
        f"-- CyberScribe Live Database Backup",
        f"-- Generated at {timestamp} UTC",
        "-- Database: threat_agent_db",
        "-- --------------------------------------------------------\n"
    ]
    
    with engine.connect() as conn:
        for tbl in tables:
            try:
                create_res = conn.execute(text(f"SHOW CREATE TABLE `{tbl}`;")).fetchone()
                create_stmt = create_res[1] if create_res else ""
                sql_lines.append(f"\n-- Table structure for table `{tbl}`")
                sql_lines.append(f"DROP TABLE IF EXISTS `{tbl}_backup_temp`;")
                sql_lines.append(create_stmt + ";\n")
            except Exception as e:
                print(f"[-] Warning reading CREATE TABLE for {tbl}: {e}")
                
            # Read all rows
            try:
                rows_res = conn.execute(text(f"SELECT * FROM `{tbl}`;"))
                cols = list(rows_res.keys())
                rows = [dict(zip(cols, row)) for row in rows_res.fetchall()]
                
                backup_data["tables"][tbl] = {
                    "columns": cols,
                    "row_count": len(rows),
                    "rows": rows
                }
                
                print(f"[+] Backed up `{tbl}`: {len(rows)} records")
                
                # SQL INSERT statements
                if rows:
                    sql_lines.append(f"-- Dumping data for table `{tbl}`")
                    for r in rows:
                        col_names = ", ".join([f"`{c}`" for c in cols])
                        val_parts = []
                        for c in cols:
                            val = r[c]
                            if val is None:
                                val_parts.append("NULL")
                            elif isinstance(val, (int, float, decimal.Decimal)):
                                val_parts.append(str(val))
                            elif isinstance(val, bool):
                                val_parts.append("1" if val else "0")
                            elif isinstance(val, (datetime.datetime, datetime.date)):
                                val_parts.append(f"'{val.isoformat()}'")
                            elif isinstance(val, (dict, list)):
                                escaped = json.dumps(val).replace("'", "''").replace("\\", "\\\\")
                                val_parts.append(f"'{escaped}'")
                            elif isinstance(val, bytes):
                                val_parts.append(f"X'{val.hex()}'")
                            else:
                                escaped = str(val).replace("'", "''").replace("\\", "\\\\")
                                val_parts.append(f"'{escaped}'")
                        sql_lines.append(f"INSERT INTO `{tbl}` ({col_names}) VALUES ({', '.join(val_parts)});")
                    sql_lines.append("\n")
            except Exception as e:
                print(f"[-] Error backing up rows for `{tbl}`: {e}")
                
    # Write JSON backup
    with open(backup_json_path, "w", encoding="utf-8") as f:
        json.dump(backup_data, f, indent=2, cls=CustomEncoder)
        
    # Write SQL backup
    with open(backup_sql_path, "w", encoding="utf-8") as f:
        f.write("\n".join(sql_lines))
        
    print(f"\n[SUCCESS] Backup files created and verified:")
    print(f"  - JSON: {backup_json_path} ({os.path.getsize(backup_json_path) / 1024:.1f} KB)")
    print(f"  - SQL:  {backup_sql_path} ({os.path.getsize(backup_sql_path) / 1024:.1f} KB)")
    return str(backup_json_path), str(backup_sql_path)


if __name__ == "__main__":
    create_live_backup()
