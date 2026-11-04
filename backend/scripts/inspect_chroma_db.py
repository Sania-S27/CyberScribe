import sqlite3
import os

paths = [
    './chroma_storage/chroma.sqlite3',
    './chroma_data/chroma.sqlite3',
    '../chroma_data/chroma.sqlite3'
]

for p in paths:
    if os.path.exists(p):
        print(f"\n=================== PATH: {p} ({os.path.getsize(p)} bytes) ===================")
        conn = sqlite3.connect(p)
        cur = conn.cursor()
        tables = [r[0] for r in cur.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()]
        print("Tables:", tables)
        for t in tables:
            try:
                cnt = cur.execute(f"SELECT count(*) FROM [{t}]").fetchone()[0]
                print(f"  [{t}]: {cnt} rows")
            except Exception as e:
                print(f"  [{t}]: error {e}")
        
        # Check migrations table if present
        for mig_table in ['migrations', 'schema_migrations', '_migrations']:
            if mig_table in tables:
                print(f"\n  --- Content of {mig_table} ---")
                rows = cur.execute(f"SELECT * FROM [{mig_table}]").fetchall()
                for row in rows:
                    print("   ", row)

        # Check collections table if present
        for col_table in ['collections']:
            if col_table in tables:
                print(f"\n  --- Content of {col_table} ---")
                rows = cur.execute(f"SELECT * FROM [{col_table}]").fetchall()
                for row in rows:
                    print("   ", row)

        # Check tenants / databases tables if present
        for t_table in ['tenants', 'databases']:
            if t_table in tables:
                print(f"\n  --- Content of {t_table} ---")
                rows = cur.execute(f"SELECT * FROM [{t_table}]").fetchall()
                for row in rows:
                    print("   ", row)

        conn.close()
