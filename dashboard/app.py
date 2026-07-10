import sys
import os
import time
import json
from flask import Flask, render_template, request, jsonify, Response
from flask_cors import CORS

# Add project root to sys.path so we can import shared modules
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from config import Config
from database.db import get_db, init_db

# Try importing analytics for bot detection if available
try:
    from analytics.bot_detector import classify_all_sessions
    HAS_BOT_DETECTION = True
except ImportError:
    HAS_BOT_DETECTION = False

app = Flask(__name__)
app.secret_key = Config.SECRET_KEY
CORS(app)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/stats')
def api_stats():
    db = get_db()
    cursor = db.cursor()
    
    # Total sessions, ssh, http
    cursor.execute("SELECT COUNT(*) AS total, SUM(CASE WHEN protocol='ssh' THEN 1 ELSE 0 END) AS ssh, SUM(CASE WHEN protocol='http' THEN 1 ELSE 0 END) AS http FROM sessions")
    row = cursor.fetchone()
    total_sessions = row['total'] or 0
    ssh_sessions = row['ssh'] or 0
    http_sessions = row['http'] or 0
    
    # Active clusters
    cursor.execute("SELECT COUNT(DISTINCT cluster_id) AS active_clusters FROM sessions WHERE cluster_id IS NOT NULL")
    active_clusters = cursor.fetchone()['active_clusters'] or 0
    
    # Techniques matched
    cursor.execute("SELECT COUNT(DISTINCT signature_id) AS techniques_matched FROM session_techniques")
    techniques_matched = cursor.fetchone()['techniques_matched'] or 0
    
    # Unique IPs
    cursor.execute("SELECT COUNT(*) AS unique_ips FROM sources")
    unique_ips = cursor.fetchone()['unique_ips'] or 0
    
    # Total commands
    cursor.execute("SELECT COUNT(*) AS total_commands FROM commands")
    total_commands = cursor.fetchone()['total_commands'] or 0
    
    # Avg duration
    cursor.execute("SELECT AVG(duration_seconds) AS avg_duration FROM sessions WHERE duration_seconds IS NOT NULL")
    avg_session_duration = cursor.fetchone()['avg_duration'] or 0
    
    # Credential count (may not exist yet)
    try:
        credential_count = cursor.execute('SELECT COUNT(*) FROM credentials').fetchone()[0]
    except Exception:
        credential_count = 0
    
    return jsonify({
        "total_sessions": total_sessions,
        "ssh_sessions": ssh_sessions,
        "http_sessions": http_sessions,
        "active_clusters": active_clusters,
        "techniques_matched": techniques_matched,
        "unique_ips": unique_ips,
        "total_commands": total_commands,
        "avg_session_duration": round(avg_session_duration, 1),
        "credentials_captured": credential_count
    })

@app.route('/api/sessions')
def api_sessions():
    page = int(request.args.get('page', 1))
    per_page = int(request.args.get('per_page', 20))
    protocol = request.args.get('protocol')
    cluster_id = request.args.get('cluster_id')
    
    offset = (page - 1) * per_page
    
    db = get_db()
    cursor = db.cursor()
    
    query = """
        SELECT s.session_id, s.source_ip, s.protocol, s.start_time, s.duration_seconds, 
               c.label AS cluster_label,
               (SELECT COUNT(*) FROM commands cmd WHERE cmd.session_id = s.session_id) as command_count,
               (SELECT COUNT(*) FROM session_techniques st WHERE st.session_id = s.session_id) as technique_count
        FROM sessions s
        LEFT JOIN clusters c ON s.cluster_id = c.cluster_id
        WHERE 1=1
    """
    params = []
    
    if protocol:
        query += " AND s.protocol = ?"
        params.append(protocol)
    if cluster_id:
        query += " AND s.cluster_id = ?"
        params.append(cluster_id)
        
    # Get total
    count_query = f"SELECT COUNT(*) as total FROM ({query})"
    cursor.execute(count_query, params)
    total = cursor.fetchone()['total']
    
    query += " ORDER BY s.start_time DESC LIMIT ? OFFSET ?"
    params.extend([per_page, offset])
    
    cursor.execute(query, params)
    rows = cursor.fetchall()
    
    sessions = []
    for row in rows:
        session_dict = dict(row)
        if HAS_BOT_DETECTION and Config.ENABLE_BOT_DETECTION:
            try:
                from analytics.bot_detector import classify_session
                session_dict['is_bot'] = classify_session(session_dict['session_id'])
            except Exception:
                session_dict['is_bot'] = 'unknown'
        else:
            session_dict['is_bot'] = 'unknown'
        sessions.append(session_dict)
        
    return jsonify({
        "sessions": sessions,
        "total": total,
        "page": page,
        "pages": (total + per_page - 1) // per_page
    })

@app.route('/api/sessions/<int:session_id>')
def api_session_detail(session_id):
    db = get_db()
    cursor = db.cursor()
    
    # Session metadata
    cursor.execute("""
        SELECT s.*, c.label AS cluster_label 
        FROM sessions s 
        LEFT JOIN clusters c ON s.cluster_id = c.cluster_id
        WHERE s.session_id = ?
    """, (session_id,))
    session = cursor.fetchone()
    
    if not session:
        return jsonify({"error": "Session not found"}), 404
        
    session_dict = dict(session)
    
    # Commands
    cursor.execute("""
        SELECT command_id, sequence_number, raw_input, timestamp, time_since_prev_ms 
        FROM commands 
        WHERE session_id = ? 
        ORDER BY sequence_number ASC
    """, (session_id,))
    commands = [dict(row) for row in cursor.fetchall()]
    
    # Techniques
    cursor.execute("""
        SELECT st.matched_command_id, ts.attack_technique_id, ts.technique_name
        FROM session_techniques st
        JOIN technique_signatures ts ON st.signature_id = ts.signature_id
        WHERE st.session_id = ?
    """, (session_id,))
    techniques = [dict(row) for row in cursor.fetchall()]
    
    # Map techniques to commands
    tech_map = {}
    for t in techniques:
        cmd_id = t['matched_command_id']
        if cmd_id not in tech_map:
            tech_map[cmd_id] = []
        tech_map[cmd_id].append({
            "id": t['attack_technique_id'],
            "name": t['technique_name']
        })
        
    for cmd in commands:
        cmd['techniques'] = tech_map.get(cmd['command_id'], [])
        
    session_dict['commands'] = commands
    
    # Credentials
    cursor.execute("""
        SELECT username, password 
        FROM credentials 
        WHERE session_id = ?
    """, (session_id,))
    session_dict['credentials'] = [dict(row) for row in cursor.fetchall()]

    
    # Try bot detection
    if HAS_BOT_DETECTION and Config.ENABLE_BOT_DETECTION:
        try:
            from analytics.bot_detector import classify_session
            session_dict['is_bot'] = classify_session(session_id)
        except Exception:
            pass
            
    return jsonify(session_dict)

@app.route('/api/clusters')
def api_clusters():
    db = get_db()
    cursor = db.cursor()
    
    cursor.execute("""
        SELECT cluster_id, label, first_seen, last_seen, centroid_features,
               (SELECT COUNT(*) FROM sessions s WHERE s.cluster_id = clusters.cluster_id) as actual_count
        FROM clusters
        WHERE label IS NOT NULL
        ORDER BY actual_count DESC
    """)
    clusters = []
    for row in cursor.fetchall():
        if row['actual_count'] == 0:
            continue
            
        cluster_dict = dict(row)
        cluster_dict['session_count'] = row['actual_count']
        if cluster_dict['centroid_features']:
            try:
                cluster_dict['centroid_features'] = json.loads(cluster_dict['centroid_features'])
            except:
                pass
                
        # Get top techniques for this cluster
        cursor.execute("""
            SELECT ts.attack_technique_id AS id, ts.technique_name AS name, COUNT(*) as count
            FROM session_techniques st
            JOIN sessions s ON st.session_id = s.session_id
            JOIN technique_signatures ts ON st.signature_id = ts.signature_id
            WHERE s.cluster_id = ?
            GROUP BY ts.attack_technique_id
            ORDER BY count DESC
            LIMIT 3
        """, (row['cluster_id'],))
        
        cluster_dict['top_techniques'] = [dict(t) for t in cursor.fetchall()]
        
        # Get protocol breakdown
        cursor.execute("""
            SELECT protocol, COUNT(*) as count
            FROM sessions
            WHERE cluster_id = ?
            GROUP BY protocol
        """, (row['cluster_id'],))
        
        cluster_dict['protocols'] = {p['protocol']: p['count'] for p in cursor.fetchall()}
        
        clusters.append(cluster_dict)
        
    return jsonify(clusters)

@app.route('/api/techniques/heatmap')
def api_techniques_heatmap():
    db = get_db()
    cursor = db.cursor()
    
    # Get all valid clusters
    cursor.execute("SELECT cluster_id, label FROM clusters WHERE label IS NOT NULL ORDER BY cluster_id")
    cluster_rows = cursor.fetchall()
    clusters_labels = [row['label'] for row in cluster_rows]
    cluster_ids = [row['cluster_id'] for row in cluster_rows]
    
    # Get top techniques
    cursor.execute("""
        SELECT ts.attack_technique_id, ts.technique_name, COUNT(*) as total_count
        FROM session_techniques st
        JOIN technique_signatures ts ON st.signature_id = ts.signature_id
        GROUP BY ts.attack_technique_id
        ORDER BY total_count DESC
        LIMIT 20
    """)
    tech_rows = cursor.fetchall()
    technique_ids = [row['attack_technique_id'] for row in tech_rows]
    technique_names = {row['attack_technique_id']: row['technique_name'] for row in tech_rows}
    
    # Build matrix
    matrix = []
    for cid in cluster_ids:
        row_data = []
        for tid in technique_ids:
            cursor.execute("""
                SELECT COUNT(*) as cnt
                FROM session_techniques st
                JOIN sessions s ON st.session_id = s.session_id
                JOIN technique_signatures ts ON st.signature_id = ts.signature_id
                WHERE s.cluster_id = ? AND ts.attack_technique_id = ?
            """, (cid, tid))
            cnt = cursor.fetchone()['cnt']
            row_data.append(cnt)
        matrix.append(row_data)
        
    return jsonify({
        "clusters": clusters_labels,
        "techniques": technique_ids,
        "technique_names": technique_names,
        "matrix": matrix
    })

@app.route('/api/timeline')
def api_timeline():
    db = get_db()
    cursor = db.cursor()
    
    # Group by day
    cursor.execute("""
        SELECT DATE(start_time) as date, protocol, COUNT(*) as count
        FROM sessions
        GROUP BY DATE(start_time), protocol
        ORDER BY date ASC
    """)
    rows = cursor.fetchall()
    
    timeline_data = {}
    protocols_seen = set()
    for row in rows:
        date = row['date']
        proto = row['protocol']
        protocols_seen.add(proto)
        if date not in timeline_data:
            timeline_data[date] = {}
        timeline_data[date][proto] = row['count']
        
    labels = sorted(list(timeline_data.keys()))
    datasets = {}
    for p in protocols_seen:
        datasets[p] = [timeline_data[label].get(p, 0) for label in labels]
    
    return jsonify({
        "labels": labels,
        "datasets": datasets
    })

@app.route('/api/geo')
def api_geo():
    db = get_db()
    cursor = db.cursor()
    
    cursor.execute("""
        SELECT source_ip AS country, COUNT(*) as count
        FROM sessions
        WHERE source_ip IS NOT NULL
        GROUP BY source_ip
        ORDER BY count DESC
        LIMIT 10
    """)
    rows = cursor.fetchall()
    
    return jsonify([dict(row) for row in rows])

@app.route('/api/techniques/top')
def api_techniques_top():
    db = get_db()
    cursor = db.cursor()
    
    cursor.execute("""
        SELECT ts.attack_technique_id AS id, ts.technique_name AS name, COUNT(*) as count
        FROM session_techniques st
        JOIN technique_signatures ts ON st.signature_id = ts.signature_id
        GROUP BY ts.attack_technique_id
        ORDER BY count DESC
        LIMIT 10
    """)
    rows = cursor.fetchall()
    
    return jsonify([dict(row) for row in rows])

@app.route('/api/commands/recent')
def api_commands_recent():
    limit = int(request.args.get('limit', 50))
    db = get_db()
    cursor = db.cursor()
    
    cursor.execute("""
        SELECT c.command_id, c.session_id, c.raw_input, c.timestamp, 
               s.source_ip, s.protocol,
               (SELECT ts.attack_technique_id 
                FROM session_techniques st 
                JOIN technique_signatures ts ON st.signature_id = ts.signature_id 
                WHERE st.matched_command_id = c.command_id LIMIT 1) as technique_id
        FROM commands c
        JOIN sessions s ON c.session_id = s.session_id
        ORDER BY c.timestamp DESC
        LIMIT ?
    """, (limit,))
    
    rows = cursor.fetchall()
    return jsonify([dict(row) for row in rows])

@app.route('/api/live')
def api_live():
    if not Config.ENABLE_LIVE_FEED:
        return jsonify({"error": "Live feed disabled"}), 403
        
    def generate():
        while True:
            # Send an update event
            # In a real app this would use a message queue or pub/sub
            # Here we just send a ping that triggers the client to fetch /api/commands/recent
            yield f"data: {json.dumps({'event': 'update'})}\n\n"
            time.sleep(Config.DASHBOARD_REFRESH_INTERVAL)
            
    return Response(generate(), mimetype="text/event-stream")

@app.route('/api/credentials')
def api_credentials():
    db = get_db()
    cursor = db.cursor()
    try:
        cursor.execute("""
            SELECT credential_id, source_ip, protocol, username, password, timestamp, success
            FROM credentials
            ORDER BY timestamp DESC
            LIMIT 100
        """)
        rows = cursor.fetchall()
        return jsonify([dict(r) for r in rows])
    except Exception:
        return jsonify([])

@app.route('/api/credentials/top')
def api_credentials_top():
    db = get_db()
    cursor = db.cursor()
    try:
        # Top 10 most attempted username/password combos
        cursor.execute("""
            SELECT username, password, COUNT(*) as attempts
            FROM credentials
            WHERE username IS NOT NULL
            GROUP BY username, password
            ORDER BY attempts DESC
            LIMIT 10
        """)
        rows = cursor.fetchall()
        return jsonify([dict(r) for r in rows])
    except Exception:
        return jsonify([])

@app.route('/api/protocols/breakdown')
def api_protocol_breakdown():
    db = get_db()
    cursor = db.cursor()
    cursor.execute("""
        SELECT protocol, COUNT(*) as count
        FROM sessions
        GROUP BY protocol
        ORDER BY count DESC
    """)
    rows = cursor.fetchall()
    return jsonify([dict(r) for r in rows])

if __name__ == '__main__':
    # Ensure DB is initialized
    init_db()
    app.run(host=Config.DASHBOARD_HOST, port=Config.DASHBOARD_PORT, debug=True)
