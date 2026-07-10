# MIRAGE — Product Requirements Document

**Version:** 1.0
**Date:** July 7, 2026
**Owner:** Ace

---

## 1. Overview

MIRAGE is a live deception system: an SSH honeypot plus a deliberately vulnerable Flask decoy, exposed on an isolated cloud VM. It doesn't stop at logging what attackers do. It stores every session in a normalized relational database, statistically groups sessions into distinct attacker "campaigns," and tags each session with the MITRE ATT&CK techniques it exhibited — using rule-based signature matching, not a language model.

The Flask decoy deliberately reintroduces three real bugs found during a prior security audit: an exposed JWT secret, an authentication bypass, and a permissive CORS configuration. Real bait, built from a real audit.

## 2. Goals

- Capture real attacker sessions against both an SSH surface and an HTTP surface.
- Store every session in a properly normalized relational schema (sessions, commands, sources, clusters, technique signatures).
- Statistically cluster sessions into distinct "campaigns" using command-sequence similarity and timing features.
- Automatically tag sessions with MITRE ATT&CK technique IDs via a rule-based signature lookup — no generative model involved.
- Present all of this in a live dashboard.
- Produce a clean, defensible write-up suitable for an internship or college submission.

## 3. Non-goals

- **No LLM or generative-AI text calls anywhere in the running system.** Classification, clustering, and technique-tagging are all rule-based or statistical. This is a hard constraint — if an AI coding tool suggests adding an LLM call anywhere in this pipeline, reject it and keep the rule-based approach.
- No active counter-hacking or engagement with attackers beyond passive observation.
- No production hardening, uptime guarantees, or customer-facing polish — this is a research/portfolio build, not a commercial product.

## 4. Target audience

Personal portfolio piece and internship deliverable. The intended reader of the final report is a college evaluator or internship supervisor assessing DBMS design, applied statistics, and security engineering — not an end-user of a commercial product.

## 5. System architecture

Five stages, in order:

1. **Decoy layer** — Cowrie (SSH honeypot) and a custom Flask decoy (HTTP), both facing the internet on an isolated VM.
2. **Session logger** — normalizes Cowrie's JSON output and the Flask decoy's request logs into a common event format.
3. **Relational database** — the normalized schema in Section 6.
4. **Analytics engine** — feature extraction, similarity/clustering (Section 7), and rule-based ATT&CK tagging (Section 8).
5. **Dashboard** — Flask + a charting library, showing live sessions, campaign clusters, and a technique heatmap.

## 6. Data model

```sql
-- Attacker source fingerprint (one row per unique IP seen)
CREATE TABLE sources (
    ip_address      TEXT PRIMARY KEY,
    first_seen      DATETIME NOT NULL,
    last_seen       DATETIME NOT NULL,
    asn             TEXT,
    country         TEXT,
    session_count   INTEGER DEFAULT 0
);

-- One row per attacker session (one SSH login, or one HTTP visit)
CREATE TABLE sessions (
    session_id        INTEGER PRIMARY KEY AUTOINCREMENT,
    source_ip         TEXT NOT NULL,
    protocol          TEXT NOT NULL CHECK (protocol IN ('ssh', 'http')),
    start_time        DATETIME NOT NULL,
    end_time          DATETIME,
    duration_seconds  INTEGER,
    cluster_id        INTEGER,
    FOREIGN KEY (source_ip) REFERENCES sources(ip_address),
    FOREIGN KEY (cluster_id) REFERENCES clusters(cluster_id)
);

-- One row per command/request within a session
CREATE TABLE commands (
    command_id          INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id          INTEGER NOT NULL,
    sequence_number      INTEGER NOT NULL,
    raw_input            TEXT NOT NULL,
    timestamp            DATETIME NOT NULL,
    time_since_prev_ms   INTEGER,
    FOREIGN KEY (session_id) REFERENCES sessions(session_id)
);

-- Discovered attacker "campaigns" (output of the clustering step)
CREATE TABLE clusters (
    cluster_id         INTEGER PRIMARY KEY AUTOINCREMENT,
    label              TEXT,
    first_seen         DATETIME,
    last_seen          DATETIME,
    session_count      INTEGER DEFAULT 0,
    centroid_features  TEXT  -- JSON blob of the feature-vector centroid
);

-- Lookup table: command pattern -> MITRE ATT&CK technique (rule-based, no LLM)
CREATE TABLE technique_signatures (
    signature_id         INTEGER PRIMARY KEY AUTOINCREMENT,
    pattern              TEXT NOT NULL,   -- regex/substring matched against commands.raw_input
    attack_technique_id  TEXT NOT NULL,   -- e.g. 'T1082'
    technique_name       TEXT NOT NULL
);

-- Junction table: which sessions triggered which techniques
CREATE TABLE session_techniques (
    session_id          INTEGER NOT NULL,
    signature_id        INTEGER NOT NULL,
    matched_command_id  INTEGER,
    PRIMARY KEY (session_id, signature_id),
    FOREIGN KEY (session_id) REFERENCES sessions(session_id),
    FOREIGN KEY (signature_id) REFERENCES technique_signatures(signature_id),
    FOREIGN KEY (matched_command_id) REFERENCES commands(command_id)
);
```

Notes: `sources` is split out from `sessions` to avoid repeating IP metadata across every session from the same attacker (a 3NF call). `session_techniques` is a junction table handling the many-to-many relationship between sessions and the techniques they exhibited.

## 7. Analytics & clustering approach

- **Feature extraction per session:** command count, unique-command ratio, average inter-command time, total duration, and a set of binary flags for high-signal substrings (`wget`, `curl`, `chmod +x`, `/etc/passwd`, etc.).
- **Similarity metric:** Jaccard similarity over command sets, or cosine similarity over TF-IDF vectors of commands, between every pair of sessions.
- **Clustering algorithm:** DBSCAN or hierarchical clustering (`scipy.cluster.hierarchy`) rather than k-means — real attacker traffic won't split into a known number of clean groups upfront, and DBSCAN naturally handles noise/outlier sessions.
- **Feature selection via correlation:** before clustering, check Spearman correlation between candidate features (e.g. session duration vs. unique-command count) to drop redundant ones — the same logic as Spearman's Rank Correlation from COM-402's stats coverage, just pointed at attacker behavior instead of exam data.
- **Validation:** since real honeypot data has no ground truth, validate with silhouette score plus manual spot-checks — pull a few sessions from each cluster and confirm they look behaviorally coherent.

## 8. TTP mapping (rule-based, no LLM)

- Populate `technique_signatures` with pattern-to-ATT&CK-ID mappings. Use Atomic Red Team's publicly documented technique-to-command references as a starting point for which commands map to which technique IDs — don't copy code, just use the technique mappings as a reference.
- A simple regex/substring matching script scans every row in `commands` against every row in `technique_signatures` and inserts matches into `session_techniques`.
- The dashboard aggregates per-cluster technique frequency into a heatmap — which campaign favors which techniques.

## 9. Tech stack

- **Honeypot:** Cowrie (SSH), custom Flask decoy (HTTP) reintroducing the Bartigo bugs.
- **Analysis:** Python, pandas, scikit-learn/scipy.
- **Database:** SQLite to start (matches existing Bartigo experience); migrate to PostgreSQL if session volume grows large.
- **Dashboard:** Flask + Chart.js.
- **Hosting:** a small isolated cloud VM (Oracle Cloud Free Tier or AWS free tier are both sufficient).

## 10. Deployment & safety

- Run on an isolated VM — not a home network, not anything with real credentials or personal data nearby.
- Keep a clean snapshot to rebuild from if the box gets fully compromised.
- Strictly passive: log and observe only, never engage or counter-hack.
- Basic outbound firewall rules on the honeypot host, so it can't be used to reach or attack anything else even if an attacker goes further than intended.

## 11. Phased build plan (8 weeks)

| Week | Focus | Deliverable |
|---|---|---|
| 1 | Infra + decoy | Cowrie and the Flask decoy live on an isolated VM, logging raw sessions |
| 2 | Schema | Section 6's schema built; a script parsing raw logs into it |
| 3–4 | Data collection + features | Sessions accumulating; feature-extraction pipeline written and tested |
| 5 | Clustering | Similarity/clustering pipeline running; first campaign groupings; silhouette check |
| 6 | TTP mapping | `technique_signatures` populated; matching engine tagging sessions |
| 7 | Dashboard | Live dashboard: sessions, clusters, technique heatmap |
| 8 | Report | Write-up covering methodology and findings, demo polish |

## 12. Success criteria

- At least a few dozen real attacker sessions captured across both surfaces.
- Clustering produces visually and statistically distinct campaign groups (silhouette score meaningfully above zero).
- `technique_signatures` covers at least 15–20 distinct ATT&CK techniques.
- Working dashboard demo.
- Report that documents methodology, schema design rationale, and findings.

## 13. Risks & mitigations

| Risk | Mitigation |
|---|---|
| Real attacker traffic is sparse early on | Start the VM running in week 1 so traffic accumulates in parallel with schema/pipeline work; don't wait to deploy |
| Cloud costs | Use free-tier VMs; monitor usage |
| Legal/ethical exposure | Passive-only, isolated VM, no engagement with attackers, no scope creep |
| Unsupervised clustering is hard to validate | Silhouette score plus manual spot-checks; see stretch goal below for a stronger validation option |

## 14. Stretch goals

- Use a small, separately-generated batch of labeled sessions (attacker "personas" you script yourself, with known ground truth) as a calibration set to sanity-check whether MIRAGE's unsupervised clustering approach is actually working before trusting it on real, unlabeled data.
- A simple classifier distinguishing "likely automated/bot" from "likely human" sessions based on timing regularity, without any model — just statistical thresholds on inter-command timing variance.

## 15. Using this PRD with AI coding tools

Paste this whole document at the start of a new session in whichever tool you're using (Claude Code, Antigravity, Gemini Pro), then work phase by phase rather than asking for everything at once. A few starter prompts for week 1:

- "Using section 9's stack, write a `docker-compose.yml` that runs Cowrie and a Flask app on the same isolated network."
- "Scaffold the Flask decoy app with routes that intentionally reproduce the JWT secret exposure and auth bypass described in section 1 — for a controlled honeypot only, not a real login system."
- "Write a script that tails Cowrie's JSON log output and normalizes each event into the format needed for section 6's `sessions` and `commands` tables."

Keep this file as the reference you return to when a tool starts making assumptions that drift from it — schema names, the no-LLM constraint, and the clustering approach in particular are worth re-pasting if a session starts drifting.
