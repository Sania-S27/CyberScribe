import json
import os
import sys
from datetime import datetime, timezone
from sqlalchemy import inspect, text

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from app.core.database import engine

def backup_database():
    inspector = inspect(engine)
    tables = inspector.get_table_names()
    backup = {
        'timestamp': datetime.now(timezone.utc).isoformat(),
        'tables': {}
    }

    with engine.connect() as conn:
        for table in tables:
            rows = conn.execute(text(f"SELECT * FROM `{table}`")).mappings().all()
            backup['tables'][table] = []
            for r in rows:
                row_dict = dict(r)
                for k, v in row_dict.items():
                    if hasattr(v, 'isoformat'):
                        row_dict[k] = v.isoformat()
                    elif v is not None and not isinstance(v, (str, int, float, bool, list, dict)):
                        row_dict[k] = str(v)
                backup['tables'][table].append(row_dict)

    now_str = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    backup_path = os.path.join(os.path.dirname(__file__), "..", "backups", f"cyberscribe_live_backup_{now_str}.json")
    os.makedirs(os.path.dirname(backup_path), exist_ok=True)
    with open(backup_path, 'w', encoding='utf-8') as f:
        json.dump(backup, f, indent=2)

    print(f"[BACKUP SUCCESS] Backup written to {backup_path}")
    print("Table row counts:")
    for t in tables:
        print(f"  - {t}: {len(backup['tables'][t])} rows")
    return backup_path

if __name__ == "__main__":
    backup_database()
