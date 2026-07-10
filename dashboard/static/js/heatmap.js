/**
 * Custom Heatmap Renderer for MIRAGE Dashboard
 * Creates a CSS Grid based matrix heatmap without external plugins
 */

function renderHeatmap(containerId, data) {
    const container = document.getElementById(containerId);
    
    if (!data.clusters || data.clusters.length === 0 || !data.techniques || data.techniques.length === 0) {
        container.innerHTML = '<div style="color:var(--text-muted); padding: 2rem 0;">No clustering data available. Please run the analytics pipeline.</div>';
        return;
    }
    
    // Clear container
    container.innerHTML = '';
    
    // Find max value for color scaling
    let maxVal = 0;
    data.matrix.forEach(row => {
        row.forEach(val => {
            if (val > maxVal) maxVal = val;
        });
    });
    
    if (maxVal === 0) maxVal = 1; // Prevent division by zero
    
    // Container styling
    container.style.display = 'grid';
    // Column 1 is for row labels, rest are for techniques
    container.style.gridTemplateColumns = `minmax(150px, auto) repeat(${data.techniques.length}, 40px)`;
    container.style.gap = '4px';
    container.style.padding = '10px';
    container.style.overflowX = 'auto';
    
    // Row 1: Header (Technique IDs)
    // Empty top-left cell
    const emptyCell = document.createElement('div');
    container.appendChild(emptyCell);
    
    // Technique headers
    data.techniques.forEach((techId, colIndex) => {
        const header = document.createElement('div');
        header.textContent = techId;
        header.style.fontFamily = "'JetBrains Mono', monospace";
        header.style.fontSize = '0.7rem';
        header.style.color = 'var(--text-secondary)';
        header.style.transform = 'rotate(-45deg)';
        header.style.transformOrigin = 'bottom left';
        header.style.height = '60px';
        header.style.display = 'flex';
        header.style.alignItems = 'flex-end';
        header.style.paddingBottom = '5px';
        
        // Tooltip for full name
        const techName = data.technique_names[techId] || techId;
        header.title = techName;
        
        container.appendChild(header);
    });
    
    // Rows: Clusters
    data.clusters.forEach((clusterLabel, rowIndex) => {
        // Row label
        const rowHeader = document.createElement('div');
        rowHeader.textContent = clusterLabel;
        rowHeader.style.fontSize = '0.8rem';
        rowHeader.style.fontWeight = '500';
        rowHeader.style.display = 'flex';
        rowHeader.style.alignItems = 'center';
        rowHeader.style.justifyContent = 'flex-end';
        rowHeader.style.paddingRight = '10px';
        rowHeader.style.color = 'var(--text-primary)';
        container.appendChild(rowHeader);
        
        // Data cells
        data.matrix[rowIndex].forEach((val, colIndex) => {
            const cell = document.createElement('div');
            
            // Calculate opacity (min 0.05 so boxes are visible, max 0.9)
            const opacity = val === 0 ? 0.02 : 0.1 + (val / maxVal) * 0.8;
            const techId = data.techniques[colIndex];
            const techName = data.technique_names[techId] || techId;
            
            cell.style.height = '40px';
            cell.style.borderRadius = '4px';
            cell.style.backgroundColor = val === 0 ? 'rgba(255,255,255,0.02)' : `rgba(0, 240, 255, ${opacity})`;
            cell.style.border = val === 0 ? '1px solid rgba(255,255,255,0.05)' : `1px solid rgba(0, 240, 255, ${Math.min(1, opacity + 0.2)})`;
            cell.style.transition = 'all 0.2s ease';
            cell.style.cursor = 'default';
            
            // Text (only show if value > 0)
            if (val > 0) {
                cell.textContent = val;
                cell.style.display = 'flex';
                cell.style.alignItems = 'center';
                cell.style.justifyContent = 'center';
                cell.style.fontSize = '0.75rem';
                cell.style.fontWeight = '600';
                cell.style.color = opacity > 0.5 ? '#050810' : '#fff';
            }
            
            // Hover effect
            cell.addEventListener('mouseenter', () => {
                cell.style.transform = 'scale(1.1)';
                cell.style.zIndex = '10';
                cell.style.boxShadow = '0 0 10px rgba(0,240,255,0.5)';
                if (val > 0) {
                    // Show custom tooltip logic if desired, or just title
                    cell.title = `${techName} (${techId}): ${val} sessions in ${clusterLabel}`;
                }
            });
            
            cell.addEventListener('mouseleave', () => {
                cell.style.transform = 'scale(1)';
                cell.style.zIndex = '1';
                cell.style.boxShadow = 'none';
            });
            
            container.appendChild(cell);
        });
    });
    
    // Add legend below
    const legend = document.createElement('div');
    legend.style.gridColumn = '1 / -1';
    legend.style.marginTop = '20px';
    legend.style.display = 'flex';
    legend.style.alignItems = 'center';
    legend.style.justifyContent = 'flex-end';
    legend.style.gap = '10px';
    legend.style.fontSize = '0.75rem';
    legend.style.color = 'var(--text-muted)';
    
    legend.innerHTML = `
        <span>0</span>
        <div style="width: 100px; height: 8px; border-radius: 4px; background: linear-gradient(90deg, rgba(255,255,255,0.02), rgba(0, 240, 255, 0.9));"></div>
        <span>${maxVal} (Frequency)</span>
    `;
    
    container.appendChild(legend);
}
