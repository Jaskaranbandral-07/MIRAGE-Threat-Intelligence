import sqlite3

try:
    print("Connecting to database...")
    db = sqlite3.connect('/data/mirage.db')
    
    # Add the HTTP Web Scanning signature
    db.execute(
        "INSERT INTO technique_signatures (pattern, attack_technique_id, technique_name) "
        "VALUES ('(?:GET|POST)\\s+/(?:login|admin|wp-|boaform|license|\\.env).*', 'T1595', 'Active Scanning: Web Vulnerabilities')"
    )
    
    db.commit()
    print("SUCCESS: HTTP Signature added! You can now run the analytics pipeline.")
except Exception as e:
    print(f"Error: {e}")
