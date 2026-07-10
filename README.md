<h1 align="center">🪞 MIRAGE</h1>
<p align="center">
  <strong>A live deception system — SSH honeypot + HTTP decoy with real-time analytics</strong>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/python-3.11+-blue?logo=python" alt="Python 3.11+">
  <img src="https://img.shields.io/badge/license-MIT-green" alt="MIT License">
  <img src="https://img.shields.io/badge/AI--free-rule%20based-orange" alt="No AI/LLM">
</p>

---

## Overview

**MIRAGE** captures, classifies, and clusters attacker behaviour observed
through an SSH honeypot (Cowrie) and an HTTP decoy server. All
classification is **rule-based or statistical** — zero LLM/generative-AI
calls anywhere in the stack.

Key capabilities:

| Capability | Description |
|---|---|
| 🐝 **SSH Honeypot** | Cowrie captures SSH sessions and shell commands |
| 🕸️ **HTTP Decoy** | Fake login pages, APIs, and admin panels attract scanners |
| 📊 **Analytics Dashboard** | Real-time Flask dashboard with clustering and ATT&CK mapping |
| 🔍 **Technique Detection** | 30 MITRE ATT&CK regex signatures auto-match commands |
| 🤖 **Bot Detection** | Statistical heuristics distinguish bots from human operators |
| 📡 **Live Feed** | Real-time session feed via the dashboard |

---

## Architecture

```
                          ┌──────────────────────────────────────────────┐
                          │              Docker: mirage-net              │
   Attacker               │                                              │
   ───────►  :2222  ──────┤──►  Cowrie (SSH)  ──► cowrie-logs volume     │
   ───────►  :8080  ──────┤──►  Decoy (HTTP)  ──┐                       │
                          │                      │                       │
                          │   Ingestion ◄────────┤──► mirage-data vol.   │
                          │       │              │       (SQLite DB)     │
                          │       ▼              │          │            │
                          │   Enrichment         │          │            │
                          │   + ATT&CK Match     │          │            │
                          │   + Clustering        │          ▼            │
                          │                      │     Dashboard :5000   │
                          │                      │     (Flask + Charts)  │
                          └──────────────────────┴──────────────────────┘
                                                          │
                                           Analyst  ◄─────┘
```

---

## Tech Stack

| Layer | Technology |
|---|---|
| SSH Honeypot | [Cowrie](https://github.com/cowrie/cowrie) |
| HTTP Decoy | Python / Flask |
| Database | SQLite 3 (WAL mode) |
| Dashboard | Flask, vanilla HTML/CSS/JS |
| Clustering | scikit-learn (DBSCAN) |
| Log Watching | watchdog |
| Containerisation | Docker / Docker Compose |

---

## Quick Start

### 1. Clone & configure

```bash
git clone <repo-url> && cd mirage-project
cp .env.example .env        # edit as needed
```

### 2. Run with Docker Compose

```bash
docker-compose up -d
```

### 3. Seed demo data (optional, for development)

```bash
pip install -r requirements.txt
python seed_demo_data.py --clean
```

### 4. Access the dashboard

Open **http://localhost:5000** in your browser.

---

## Directory Structure

```
MIRAGE Project/
├── config.py                 # Central configuration (env-var overrides)
├── requirements.txt          # Python dependencies
├── .env.example              # Environment variable template
├── docker-compose.yml        # Docker orchestration
├── seed_demo_data.py         # Demo data generator (6 attacker personas)
├── README.md                 # ← you are here
│
├── database/
│   ├── __init__.py
│   ├── db.py                 # Connection manager (thread-safe, WAL)
│   ├── schema.sql            # PRD §6 schema (6 tables + indexes)
│   └── seed_signatures.sql   # 30 ATT&CK technique regex patterns
│
├── dashboard/                # Flask analytics dashboard (coming next)
│   └── Dockerfile
│
├── decoy/                    # HTTP decoy server (coming next)
│   └── Dockerfile
│
└── ingestion/                # Cowrie log ingestion pipeline (coming next)
    └── Dockerfile
```

---

## Database Schema (PRD §6)

Six tables with foreign-key constraints and performance indexes:

```
sources ──1:N──► sessions ──1:N──► commands
                    │
                    ├──N:1──► clusters
                    │
                    └──M:N──► technique_signatures
                              (via session_techniques)
```

| Table | Purpose |
|---|---|
| `sources` | Unique attacker IPs with geo metadata |
| `clusters` | DBSCAN cluster centroids |
| `sessions` | SSH/HTTP sessions linked to source & cluster |
| `commands` | Individual commands with inter-keystroke timing |
| `technique_signatures` | MITRE ATT&CK regex patterns |
| `session_techniques` | Junction: which session matched which technique |

---

## Environment Variables

See [`.env.example`](.env.example) for the full list. Key variables:

| Variable | Default | Description |
|---|---|---|
| `MIRAGE_DB_PATH` | `./mirage.db` | SQLite database path |
| `COWRIE_LOG_PATH` | `/var/log/cowrie/cowrie.json` | Cowrie JSON log |
| `DASHBOARD_PORT` | `5000` | Dashboard listen port |
| `DECOY_PORT` | `8080` | HTTP decoy listen port |
| `CLUSTER_EPS` | `0.5` | DBSCAN epsilon |
| `CLUSTER_MIN_SAMPLES` | `3` | DBSCAN min samples |

---

## Demo Data

`seed_demo_data.py` generates **~90 sessions** across 6 attacker personas:

| Persona | Sessions | Protocol | Origin | Behavior |
|---|---|---|---|---|
| Botnet Deployer | 20 | SSH | CN, RU | Bot-like timing |
| Credential Harvester | 15 | SSH | BR, VN | Bot-like timing |
| Recon Scanner | 15 | SSH | US, DE | Human-like timing |
| Cryptominer Deployer | 15 | SSH | RO, UA | Bot-like timing |
| Manual Hacker | 10 | SSH | NL, US | Clearly human timing |
| HTTP Scanner | 15 | HTTP | Various | Rapid scanner timing |

---

## PRD Reference

This project implements the MIRAGE Product Requirements Document (PRD).
The database schema follows **PRD §6** verbatim. Technique signatures
are mapped to [MITRE ATT&CK Enterprise](https://attack.mitre.org/techniques/enterprise/).

---

## License

```
MIT License

Copyright (c) 2026 MIRAGE Project

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```
