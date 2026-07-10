#!/usr/bin/env python3
"""
MIRAGE — Clear all demo/seed data from the database.
Leaves the schema and ATT&CK signatures intact so real
captured data can flow in cleanly.
"""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from database.db import init_db, get_db

def clear_all_session_data():
    init_db()
    db = get_db()
    cursor = db.cursor()

    # Order matters due to foreign keys
    tables = [
        'session_techniques',
        'commands',
        'sessions',
        'clusters',
        'sources',
    ]

    for table in tables:
        cursor.execute(f'DELETE FROM {table}')
        print(f'  Cleared: {table} ({cursor.rowcount} rows deleted)')

    db.commit()
    print('\nAll demo data has been wiped.')
    print('The ATT&CK technique signatures are still intact.')
    print('Real attacker data will now flow in cleanly.\n')

if __name__ == '__main__':
    print('\n=== MIRAGE — Clearing Demo Data ===\n')
    clear_all_session_data()
