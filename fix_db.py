import sqlite3
import os

def fix():
    db_path = os.environ.get("MIRAGE_DB_PATH", "/data/mirage.db")
    if not os.path.exists(db_path):
        print("DB not found")
        return
        
    print(f"Fixing broken foreign keys in {db_path}...")
    conn = sqlite3.connect(db_path)
    # MUST turn off foreign keys to allow dropping tables that are referenced (or contain broken references)
    conn.isolation_level = None # auto-commit mode so PRAGMA works
    conn.execute("PRAGMA foreign_keys = OFF")
    conn.execute("BEGIN TRANSACTION")
    
    cursor = conn.cursor()

    # 1. Recreate commands
    print("Fixing commands table...")
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS new_commands (
        command_id          INTEGER PRIMARY KEY AUTOINCREMENT,
        session_id          INTEGER NOT NULL,
        sequence_number      INTEGER NOT NULL,
        raw_input            TEXT NOT NULL,
        timestamp            DATETIME NOT NULL,
        time_since_prev_ms   INTEGER,
        FOREIGN KEY (session_id) REFERENCES sessions(session_id)
    )
    """)
    cursor.execute("INSERT INTO new_commands SELECT * FROM commands")
    cursor.execute("DROP TABLE commands")
    cursor.execute("ALTER TABLE new_commands RENAME TO commands")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_commands_session_id ON commands(session_id)")

    # 2. Recreate credentials
    print("Fixing credentials table...")
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS new_credentials (
        credential_id    INTEGER PRIMARY KEY AUTOINCREMENT,
        session_id       INTEGER,
        source_ip        TEXT NOT NULL,
        protocol         TEXT NOT NULL,
        username         TEXT,
        password         TEXT,
        timestamp        DATETIME NOT NULL,
        success          BOOLEAN DEFAULT 0,
        FOREIGN KEY (session_id) REFERENCES sessions(session_id)
    )
    """)
    # credentials table was just created yesterday, might be empty, but copy just in case
    cursor.execute("INSERT INTO new_credentials SELECT * FROM credentials")
    cursor.execute("DROP TABLE credentials")
    cursor.execute("ALTER TABLE new_credentials RENAME TO credentials")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_credentials_source_ip ON credentials(source_ip)")

    # 3. Recreate session_techniques
    print("Fixing session_techniques table...")
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS new_session_techniques (
        session_id          INTEGER NOT NULL,
        signature_id        INTEGER NOT NULL,
        matched_command_id  INTEGER,
        PRIMARY KEY (session_id, signature_id),
        FOREIGN KEY (session_id) REFERENCES sessions(session_id),
        FOREIGN KEY (signature_id) REFERENCES technique_signatures(signature_id),
        FOREIGN KEY (matched_command_id) REFERENCES commands(command_id)
    )
    """)
    cursor.execute("INSERT INTO new_session_techniques SELECT * FROM session_techniques")
    cursor.execute("DROP TABLE session_techniques")
    cursor.execute("ALTER TABLE new_session_techniques RENAME TO session_techniques")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_session_techniques_session ON session_techniques(session_id)")

    conn.execute("COMMIT")
    conn.execute("PRAGMA foreign_keys = ON")
    conn.close()
    
    print("Foreign keys fixed! The database is now fully repaired.")

if __name__ == "__main__":
    fix()
