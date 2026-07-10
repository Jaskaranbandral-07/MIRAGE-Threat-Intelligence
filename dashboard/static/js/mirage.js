// Global State
let currentPage = 1;
let currentProtocolFilter = '';

document.addEventListener('DOMContentLoaded', () => {
    // Elements
    const clockEl = document.getElementById('clock');
    
    // Initialize
    updateClock();
    setInterval(updateClock, 1000);
    
    // Set global Chart.js defaults
    Chart.defaults.color = '#94a3b8';
    Chart.defaults.font.family = "'Inter', sans-serif";
    Chart.defaults.plugins.legend.labels.usePointStyle = true;
    Chart.defaults.plugins.legend.labels.padding = 20;
    Chart.defaults.elements.line.tension = 0.4;
    Chart.defaults.scale.grid.color = 'rgba(255,255,255,0.04)';
    
    // Load data
    loadAllData();
    
    // Setup Event Listeners
    document.getElementById('modal-close').addEventListener('click', closeModal);
    document.getElementById('session-modal').addEventListener('click', (e) => {
        if (e.target.id === 'session-modal') closeModal();
    });
    document.addEventListener('keydown', (e) => {
        if (e.key === 'Escape') closeModal();
    });
    
    document.getElementById('btn-prev-page').addEventListener('click', () => {
        if (currentPage > 1) {
            currentPage--;
            loadSessionsTable();
        }
    });
    
    document.getElementById('btn-next-page').addEventListener('click', () => {
        currentPage++;
        loadSessionsTable();
    });
    
    document.getElementById('filter-protocol').addEventListener('change', (e) => {
        currentProtocolFilter = e.target.value;
        currentPage = 1;
        loadSessionsTable();
    });
    
    // Setup SSE for live feed if enabled, otherwise poll
    setupLiveFeed();
});

// --- Utility Functions ---

function updateClock() {
    const now = new Date();
    document.getElementById('clock').textContent = now.toISOString().replace('T', ' ').substring(0, 19) + ' UTC';
}

function formatDuration(seconds) {
    if (!seconds) return '0s';
    if (seconds < 60) return `${Math.round(seconds)}s`;
    const m = Math.floor(seconds / 60);
    const s = Math.round(seconds % 60);
    return m > 60 ? `${Math.floor(m/60)}h ${m%60}m` : `${m}m ${s}s`;
}

function formatTime(isoStr) {
    if (!isoStr) return '';
    return isoStr.replace('T', ' ').substring(0, 19);
}

function createBadge(text, type) {
    return `<span class="badge badge-${type}">${text}</span>`;
}

function animateValue(obj, start, end, duration) {
    let startTimestamp = null;
    const step = (timestamp) => {
        if (!startTimestamp) startTimestamp = timestamp;
        const progress = Math.min((timestamp - startTimestamp) / duration, 1);
        const easedProgress = 1 - Math.pow(1 - progress, 3); // easeOutCubic
        obj.innerHTML = Math.floor(easedProgress * (end - start) + start);
        if (progress < 1) {
            window.requestAnimationFrame(step);
        } else {
            obj.innerHTML = end; // Ensure exact final value
        }
    };
    window.requestAnimationFrame(step);
}

// --- Data Loading ---

async function loadAllData() {
    await Promise.all([
        loadStats(),
        loadTimeline(),
        loadTopTechniques(),
        loadTopSources(),
        loadClusters(),
        loadSessionsTable(),
        loadLiveFeedInit(),
        loadHeatmapData()
    ]);
}

async function loadStats() {
    try {
        const res = await fetch('/api/stats');
        const data = await res.json();
        
        animateValue(document.getElementById('kpi-total-sessions'), 0, data.total_sessions, 1500);
        document.getElementById('kpi-ssh-count').textContent = data.ssh_sessions;
        document.getElementById('kpi-http-count').textContent = data.http_sessions;
        
        animateValue(document.getElementById('kpi-active-campaigns'), 0, data.active_clusters, 1500);
        animateValue(document.getElementById('kpi-techniques'), 0, data.techniques_matched, 1500);
        animateValue(document.getElementById('kpi-unique-ips'), 0, data.unique_ips, 1500);
        
        document.getElementById('kpi-avg-duration').textContent = data.avg_session_duration.toFixed(1);
        
        renderProtocolChart(data.ssh_sessions, data.http_sessions);
    } catch (e) { console.error('Error loading stats:', e); }
}

async function loadTimeline() {
    try {
        const res = await fetch('/api/timeline');
        const data = await res.json();
        
        const ctx = document.getElementById('timelineChart').getContext('2d');
        
        const gradientSSH = ctx.createLinearGradient(0, 0, 0, 300);
        gradientSSH.addColorStop(0, 'rgba(0, 240, 255, 0.4)');
        gradientSSH.addColorStop(1, 'rgba(0, 240, 255, 0.0)');
        
        const gradientHTTP = ctx.createLinearGradient(0, 0, 0, 300);
        gradientHTTP.addColorStop(0, 'rgba(255, 159, 28, 0.4)');
        gradientHTTP.addColorStop(1, 'rgba(255, 159, 28, 0.0)');
        
        new Chart(ctx, {
            type: 'line',
            data: {
                labels: data.labels,
                datasets: [
                    {
                        label: 'SSH Sessions',
                        data: data.ssh,
                        borderColor: '#00f0ff',
                        backgroundColor: gradientSSH,
                        fill: true,
                        tension: 0.4
                    },
                    {
                        label: 'HTTP Sessions',
                        data: data.http,
                        borderColor: '#ff9f1c',
                        backgroundColor: gradientHTTP,
                        fill: true,
                        tension: 0.4
                    }
                ]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                interaction: { mode: 'index', intersect: false },
                plugins: { legend: { position: 'top' } }
            }
        });
    } catch (e) { console.error('Error loading timeline:', e); }
}

function renderProtocolChart(ssh, http) {
    const ctx = document.getElementById('protocolChart').getContext('2d');
    new Chart(ctx, {
        type: 'doughnut',
        data: {
            labels: ['SSH', 'HTTP'],
            datasets: [{
                data: [ssh, http],
                backgroundColor: ['#00f0ff', '#ff9f1c'],
                borderWidth: 0,
                hoverOffset: 4
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            cutout: '75%',
            plugins: { legend: { position: 'bottom' } }
        }
    });
}

async function loadTopTechniques() {
    try {
        const res = await fetch('/api/techniques/top');
        const data = await res.json();
        
        const ctx = document.getElementById('topTechniquesChart').getContext('2d');
        new Chart(ctx, {
            type: 'bar',
            data: {
                labels: data.map(d => d.name.length > 25 ? d.name.substring(0, 25) + '...' : d.name),
                datasets: [{
                    label: 'Session Matches',
                    data: data.map(d => d.count),
                    backgroundColor: '#7c3aed',
                    borderRadius: 4
                }]
            },
            options: {
                indexAxis: 'y',
                responsive: true,
                maintainAspectRatio: false,
                plugins: { legend: { display: false } }
            }
        });
    } catch (e) { console.error('Error:', e); }
}

async function loadTopSources() {
    try {
        const res = await fetch('/api/geo');
        const data = await res.json();
        
        const ctx = document.getElementById('topSourcesChart').getContext('2d');
        new Chart(ctx, {
            type: 'bar',
            data: {
                labels: data.map(d => d.country || 'Unknown'),
                datasets: [{
                    label: 'Source IPs',
                    data: data.map(d => d.count),
                    backgroundColor: '#ff9f1c',
                    borderRadius: 4
                }]
            },
            options: {
                indexAxis: 'y',
                responsive: true,
                maintainAspectRatio: false,
                plugins: { legend: { display: false } }
            }
        });
    } catch (e) { console.error('Error:', e); }
}

async function loadClusters() {
    try {
        const res = await fetch('/api/clusters');
        const data = await res.json();
        
        const container = document.getElementById('campaigns-container');
        container.innerHTML = '';
        
        if (data.length === 0) {
            container.innerHTML = '<div style="color:var(--text-muted)">No campaigns discovered yet. Run the analytics pipeline.</div>';
            return;
        }
        
        data.forEach(c => {
            let techHtml = c.top_techniques.map(t => `<span class="badge badge-technique" title="${t.name}">${t.id}</span>`).join('');
            
            const html = `
                <div class="card campaign-card">
                    <div class="campaign-header">
                        <div class="campaign-title">${c.label}</div>
                        <div class="badge badge-ssh" style="border-color:var(--text-muted); color:var(--text-primary)">${c.session_count} sessions</div>
                    </div>
                    <div class="campaign-meta">First seen: ${formatTime(c.first_seen)}</div>
                    <div>${techHtml || '<span class="text-muted">No specific techniques identified</span>'}</div>
                </div>
            `;
            container.innerHTML += html;
        });
    } catch (e) { console.error('Error:', e); }
}

async function loadSessionsTable() {
    try {
        const query = new URLSearchParams({ page: currentPage, per_page: 20 });
        if (currentProtocolFilter) query.append('protocol', currentProtocolFilter);
        
        const res = await fetch(`/api/sessions?${query}`);
        const data = await res.json();
        
        const tbody = document.getElementById('sessions-table-body');
        tbody.innerHTML = '';
        
        data.sessions.forEach(s => {
            const tr = document.createElement('tr');
            tr.innerHTML = `
                <td>${s.session_id}</td>
                <td class="code-cell">${s.source_ip}</td>
                <td>${createBadge(s.protocol.toUpperCase(), s.protocol)}</td>
                <td>${formatTime(s.start_time)}</td>
                <td>${formatDuration(s.duration_seconds)}</td>
                <td>${s.command_count}</td>
                <td>${s.cluster_label || '-'}</td>
                <td><button class="glass-btn" onclick="openSessionDetail(${s.session_id})">View</button></td>
            `;
            tbody.appendChild(tr);
        });
        
        document.getElementById('page-indicator').textContent = `Page ${data.page} of ${data.pages || 1}`;
        document.getElementById('btn-prev-page').disabled = data.page <= 1;
        document.getElementById('btn-next-page').disabled = data.page >= data.pages;
        
    } catch (e) { console.error('Error:', e); }
}

// --- Live Feed ---

let lastFeedCommandId = 0;

async function loadLiveFeedInit() {
    try {
        const res = await fetch('/api/commands/recent?limit=20');
        const data = await res.json();
        
        const tbody = document.getElementById('live-feed-body');
        tbody.innerHTML = '';
        
        if (data.length > 0) {
            lastFeedCommandId = data[0].command_id;
            data.forEach(cmd => addLiveFeedRow(cmd, false));
        }
    } catch (e) { console.error('Error:', e); }
}

function addLiveFeedRow(cmd, animate = true) {
    const tbody = document.getElementById('live-feed-body');
    const tr = document.createElement('tr');
    tr.className = `row-${cmd.protocol} ${animate ? 'new-row' : ''}`;
    
    // Truncate long commands
    const displayCmd = cmd.raw_input.length > 80 ? cmd.raw_input.substring(0, 77) + '...' : cmd.raw_input;
    
    tr.innerHTML = `
        <td>${formatTime(cmd.timestamp).split(' ')[1]}</td>
        <td class="code-cell">${cmd.source_ip}</td>
        <td>${createBadge(cmd.protocol.toUpperCase(), cmd.protocol)}</td>
        <td class="code-cell" style="color:var(--text-primary)">${displayCmd}</td>
        <td>${cmd.technique_id ? createBadge(cmd.technique_id, 'technique') : ''}</td>
    `;
    
    tbody.insertBefore(tr, tbody.firstChild);
    
    // Keep max 50 rows
    while (tbody.children.length > 50) {
        tbody.removeChild(tbody.lastChild);
    }
}

function setupLiveFeed() {
    // Attempt SSE
    const evtSource = new EventSource("/api/live");
    evtSource.onmessage = async function(event) {
        // When we get a ping, fetch new commands
        try {
            const res = await fetch('/api/commands/recent?limit=10');
            const data = await res.json();
            
            // Filter only new commands
            const newCmds = data.filter(c => c.command_id > lastFeedCommandId).reverse();
            if (newCmds.length > 0) {
                lastFeedCommandId = newCmds[newCmds.length - 1].command_id;
                newCmds.forEach(cmd => addLiveFeedRow(cmd, true));
            }
        } catch (e) { console.log(e); }
    };
    evtSource.onerror = function() {
        console.log("SSE failed, falling back to polling");
        evtSource.close();
        // Fallback polling
        setInterval(async () => {
            try {
                const res = await fetch('/api/commands/recent?limit=10');
                const data = await res.json();
                const newCmds = data.filter(c => c.command_id > lastFeedCommandId).reverse();
                if (newCmds.length > 0) {
                    lastFeedCommandId = newCmds[newCmds.length - 1].command_id;
                    newCmds.forEach(cmd => addLiveFeedRow(cmd, true));
                }
            } catch(e) {}
        }, 10000);
    };
}

// --- Heatmap ---
async function loadHeatmapData() {
    try {
        const res = await fetch('/api/techniques/heatmap');
        const data = await res.json();
        if (typeof renderHeatmap === 'function') {
            renderHeatmap('heatmap-container', data);
        }
    } catch (e) { console.error('Error loading heatmap:', e); }
}

// --- Modal ---
async function openSessionDetail(id) {
    try {
        const res = await fetch(`/api/sessions/${id}`);
        const data = await res.json();
        
        if (data.error) return alert(data.error);
        
        // Setup Meta
        const metaDiv = document.getElementById('modal-meta');
        metaDiv.innerHTML = `
            <span>IP: <strong class="code-cell">${data.source_ip}</strong></span>
            <span>Protocol: ${createBadge(data.protocol.toUpperCase(), data.protocol)}</span>
            <span>Duration: <strong>${formatDuration(data.duration_seconds)}</strong></span>
            <span>Cluster: <strong>${data.cluster_label || 'None'}</strong></span>
        `;
        
        if (data.is_bot) {
            const botType = data.is_bot === 'bot' ? 'bot' : (data.is_bot === 'human' ? 'human' : 'unknown');
            if (botType !== 'unknown') {
                metaDiv.innerHTML += `<span>Class: ${createBadge(botType.toUpperCase(), botType)}</span>`;
            }
        }
        
        // Setup Commands
        const listDiv = document.getElementById('modal-command-list');
        listDiv.innerHTML = '';
        
        data.commands.forEach(c => {
            const delay = c.time_since_prev_ms ? `+${c.time_since_prev_ms}ms` : 'Start';
            let tagsHtml = (c.techniques || []).map(t => createBadge(t.id, 'technique')).join('');
            
            // Basic syntax highlighting for the command text
            let textHtml = c.raw_input
                .replace(/(\/etc\/[a-zA-Z0-9_-]+)/g, '<span style="color:#fde047">$1</span>') // paths in yellow
                .replace(/(\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b)/g, '<span style="color:#00f0ff">$1</span>'); // IPs in cyan
                
            listDiv.innerHTML += `
                <div class="command-item">
                    <div class="command-header">
                        <span>#${c.sequence_number} | ${formatTime(c.timestamp)} | <span style="color:var(--accent-amber)">${delay}</span></span>
                        <span>${tagsHtml}</span>
                    </div>
                    <div class="command-text">${textHtml}</div>
                </div>
            `;
        });
        
        document.getElementById('session-modal').classList.add('active');
        document.body.style.overflow = 'hidden'; // Prevent background scrolling
        
    } catch (e) { console.error('Error:', e); }
}

function closeModal() {
    document.getElementById('session-modal').classList.remove('active');
    document.body.style.overflow = '';
}
