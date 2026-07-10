<h1 align="center">🪞 MIRAGE</h1>
<p align="center">
  <strong>A Live Deception Network — Multi-protocol honeypot architecture with real-time analytics</strong>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/python-3.11+-blue?logo=python" alt="Python 3.11+">
  <img src="https://img.shields.io/badge/docker-compose-2496ED?logo=docker" alt="Docker">
  <img src="https://img.shields.io/badge/license-MIT-green" alt="MIT License">
  <img src="https://img.shields.io/badge/AI--free-rule%20based-orange" alt="No AI/LLM">
</p>

---

## Overview

**MIRAGE** is a comprehensive, multi-protocol Live Deception Network. It captures, classifies, and clusters attacker behaviour observed across a wide array of vulnerable services. All classification is **rule-based or statistical** — zero LLM/generative-AI calls anywhere in the stack.

The platform is designed to capture everything from automated botnet scanning to human-driven APT campaigns, funneling all intelligence into a unified, real-time dashboard.

### 🪤 The Traps (Honeypots)

| Honeypot | Protocol | Port | Purpose |
|---|---|---|---|
| **Cowrie** | SSH | 2222 | Captures SSH brute-forcing and interactive shell sessions |
| **Credential Trap** | FTP, Telnet, SMTP, VNC | 21, 23, 25, 5900 | High-fidelity credential capture across legacy protocols (Custom built) |
| **Wordpot** | HTTP (WordPress) | 8081 | Emulates a vulnerable WP site to trap scanners and brute-forcers |
| **Elasticpot** | HTTP (Elasticsearch) | 9200 | Fake DB cluster to catch data thieves and ransomware droppers |
| **ADBHoney** | ADB | 5555 | Fake Android debug bridge to catch IoT botnets (Mirai/Ares) |
| **Decoy** | HTTP (Generic) | 8080 | Fake login pages, APIs, and admin panels |

### 🧠 Intelligence Capabilities

| Capability | Description |
|---|---|
| 📊 **Unified Dashboard** | Real-time Flask dashboard visualizing data from all 6 honeypots |
| 🔍 **MITRE ATT&CK Mapping** | 100+ regex signatures automatically map shell, HTTP, & legacy commands to ATT&CK |
| 🔑 **Credential Tracking** | Aggregates and ranks the top passwords attempted by hackers |
| 🤖 **Bot Detection** | Statistical heuristics (inter-keystroke timing) distinguish bots from humans |
| 📡 **Live Feed** | Real-time event feed of all attacks hitting the network |

---

## Architecture

```text
                           ┌────────────────────────────────────────────────────────┐
                           │                  Docker: mirage-net                    │
    Internet               │                                                        │
    ────────►  :2222  ─────┤──► Cowrie (SSH)                                        │
    ────────►  :8080  ─────┤──► Decoy (HTTP)               ┌────────────────────┐   │
    ────────►  :21,23 ─────┤──► Credential Trap            │                    │   │
    ────────►  :8081  ─────┤──► Wordpot (WordPress)  ──────►  honeypot-logs vol │   │
    ────────►  :9200  ─────┤──► Elasticpot (DB)            │                    │   │
    ────────►  :5555  ─────┤──► ADBHoney (IoT)             └─────────┬──────────┘   │
                           │                                         │              │
                           │                                         ▼              │
                           │                          ┌─────────────────────────┐   │
                           │                          │ Ingestion & Enrichment  │   │
                           │                          └──────────────┬──────────┘   │
                           │                                         ▼              │
                           │                          ┌─────────────────────────┐   │
                           │                          │  mirage-data (SQLite)   │   │
                           │                          └──────────────┬──────────┘   │
                           │                                         ▼              │
                           │                          ┌─────────────────────────┐   │
                           │                          │   Dashboard (:5000)     │   │
                           └──────────────────────────┴─────────────────────────┴───┘
                                                                     │
                                                      Analyst  ◄─────┘
```

---

## Quick Start

### 1. Clone & Configure
```bash
git clone https://github.com/yourusername/mirage.git
cd mirage
cp .env.example .env
```

### 2. Deploy
```bash
docker-compose up -d --build
```

### 3. Open Firewall Ports
Ensure the following inbound ports are open on your server:
`21, 23, 25, 2222, 5000, 5555, 5900, 8080, 8081, 9200`

### 4. Access Dashboard
Open **http://your-server-ip:5000** in your browser.

---

## Database Schema

Seven highly-indexed tables with strict foreign-key constraints (PRD §6):

| Table | Purpose |
|---|---|
| `sources` | Unique attacker IPs with geolocation metadata |
| `clusters` | DBSCAN cluster centroids (behavioral profiling) |
| `sessions` | Individual connections linked to source & cluster |
| `commands` | Individual commands/requests with execution timing |
| `credentials` | Captured usernames and passwords |
| `technique_signatures`| MITRE ATT&CK regex patterns |
| `session_techniques` | Junction: which session matched which technique |

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
