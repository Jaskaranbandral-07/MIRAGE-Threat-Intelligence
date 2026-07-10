import sqlite3
import os

db_path = os.environ.get("MIRAGE_DB_PATH", "/data/mirage.db")
print(f"Diagnosing DB at {db_path}...")

conn = sqlite3.connect(db_path)
conn.row_factory = sqlite3.Row

# 1. Check if tables exist
tables = conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()
print("Tables:", [t['name'] for t in tables])

# 2. Check credentials table count
if 'credentials' in [t['name'] for t in tables]:
    count = conn.execute("SELECT COUNT(*) as c FROM credentials").fetchone()['c']
    print(f"Credentials count: {count}")
    
    rows = conn.execute("SELECT * FROM credentials ORDER BY timestamp DESC LIMIT 5").fetchall()
    print("Latest credentials:")
    for r in rows:
        print(dict(r))
else:
    print("WARNING: credentials table DOES NOT EXIST!")

# 3. Check sessions for wordpress
rows = conn.execute("SELECT * FROM sessions WHERE protocol='wordpress'").fetchall()
print(f"\nWordpress sessions count: {len(rows)}")
for r in rows:
    print(dict(r))

# 4. Check commands for these sessions
if rows:
    sids = ",".join(str(r['session_id']) for r in rows)
    cmds = conn.execute(f"SELECT * FROM commands WHERE session_id IN ({sids})").fetchall()
    print(f"\nCommands for wordpress sessions: {len(cmds)}")
    for c in cmds:
        print(dict(c))
