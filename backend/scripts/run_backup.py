import json
import os
import datetime
from app.core.database import SessionLocal, engine
from sqlalchemy import inspect, text

def make_backup():
    db = SessionLocal()
    insp = inspect(engine)
    tables = insp.get_table_names()
    backup = {"timestamp": datetime.datetime.now().isoformat(), "tables": {}}

    for table in tables:
        rows = db.execute(text(f"SELECT * FROM `{table}`")).mappings().all()
        backup["tables"][table] = [dict(r) for r in rows]

    os.makedirs("backups", exist_ok=True)
    ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"backups/cyberscribe_db_backup_{ts}.json"
    with open(filename, "w", encoding="utf-8") as f:
        json.dump(backup, f, default=str, indent=2)

    print(f"BACKUP_SAVED: {filename} with {len(tables)} tables.")

if __name__ == "__main__":
    make_backup()
