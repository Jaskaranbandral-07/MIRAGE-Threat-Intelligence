import sqlite3
import os

def migrate():
    db_path = os.environ.get("MIRAGE_DB_PATH", "/data/mirage.db")
    if not os.path.exists(db_path):
        print(f"Database not found at {db_path}")
        return

    print(f"Migrating database at {db_path}...")
    conn = sqlite3.connect(db_path)
    
    # Disable foreign keys during migration
    conn.execute("PRAGMA foreign_keys = OFF")
    
    cursor = conn.cursor()
    
    # 1. Rename old table
    print("Renaming old sessions table...")
    cursor.execute("ALTER TABLE sessions RENAME TO sessions_old")
    
    # 2. Create new table with updated CHECK constraint
    print("Creating new sessions table...")
    cursor.execute("""
    CREATE TABLE sessions (
        session_id        INTEGER PRIMARY KEY AUTOINCREMENT,
        source_ip         TEXT NOT NULL,
        protocol          TEXT NOT NULL CHECK (protocol IN ('ssh', 'http', 'ftp', 'telnet', 'smtp', 'vnc', 'wordpress', 'elasticsearch', 'adb')),
        start_time        DATETIME NOT NULL,
        end_time          DATETIME,
        duration_seconds  INTEGER,
        cluster_id        INTEGER,
        FOREIGN KEY (source_ip) REFERENCES sources(ip_address),
        FOREIGN KEY (cluster_id) REFERENCES clusters(cluster_id)
    )
    """)
    
    # 3. Copy data
    print("Copying data to new table...")
    cursor.execute("""
    INSERT INTO sessions (session_id, source_ip, protocol, start_time, end_time, duration_seconds, cluster_id)
    SELECT session_id, source_ip, protocol, start_time, end_time, duration_seconds, cluster_id
    FROM sessions_old
    """)
    
    # 4. Drop old table
    print("Dropping old table...")
    cursor.execute("DROP TABLE sessions_old")
    
    # Re-enable foreign keys
    conn.execute("PRAGMA foreign_keys = ON")
    
    # Also recreate indexes for the new table
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_sessions_source_ip ON sessions(source_ip)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_sessions_cluster_id ON sessions(cluster_id)")
    
    conn.commit()
    conn.close()
    
    print("Migration complete! The database now accepts all 6 honeypot protocols.")

if __name__ == "__main__":
    migrate()
