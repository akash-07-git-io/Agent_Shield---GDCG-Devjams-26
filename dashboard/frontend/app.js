const API_BASE = '/api';

let currentEscrowId = null;

async function fetchStats() {
    try {
        const res = await fetch(`${API_BASE}/dashboard/stats`);
        const data = await res.json();
        
        document.getElementById('score-val').textContent = data.security_score;
        document.getElementById('threats-val').textContent = data.threats_detected;
        document.getElementById('escrow-val').textContent = data.review;
        document.getElementById('allowed-val').textContent = data.allowed;
    } catch (e) {
        console.error("Failed to fetch stats", e);
    }
}

async function fetchEvents() {
    try {
        const res = await fetch(`${API_BASE}/events`);
        const events = await res.json();
        
        const tbody = document.getElementById('events-body');
        tbody.innerHTML = '';
        
        events.forEach(ev => {
            const tr = document.createElement('tr');
            
            // Format time
            const time = new Date(ev.timestamp).toLocaleTimeString();
            
            // Tag styling
            let decisionClass = 'tag-allow';
            if (ev.decision === 'BLOCK' || ev.decision === 'ISOLATE') decisionClass = 'tag-block';
            if (ev.decision === 'HUMAN_APPROVAL' || ev.decision === 'ESCROW') decisionClass = 'tag-escrow';
            
            // Action button
            let actionBtn = '-';
            if (ev.decision === 'HUMAN_APPROVAL' || ev.decision === 'ESCROW') {
                actionBtn = `<button class="cyber-btn" onclick="openEscrowModal('${ev.event_id}', '${ev.action}', '${ev.resource}', '${ev.reason}')">REVIEW</button>`;
            }
            
            tr.innerHTML = `
                <td>${time}</td>
                <td>${ev.agent_id}</td>
                <td><span style="color:var(--primary-cyan)">${ev.tool}</span><br><small>${ev.action}</small></td>
                <td>${ev.resource}<br><small style="color:var(--text-dim)">${ev.destination || ''}</small></td>
                <td>${parseFloat(ev.risk_score).toFixed(2)}<br><small>${ev.risk_category}</small></td>
                <td><span class="tag ${decisionClass}">${ev.decision}</span></td>
                <td>${actionBtn}</td>
            `;
            tbody.appendChild(tr);
        });
    } catch (e) {
        console.error("Failed to fetch events", e);
    }
}

function openEscrowModal(eventId, action, resource, reason) {
    currentEscrowId = eventId;
    const details = document.getElementById('modal-details');
    details.innerHTML = `
        <p><strong>Event ID:</strong> ${eventId}</p>
        <p><strong>Action:</strong> ${action}</p>
        <p><strong>Resource:</strong> ${resource}</p>
        <p><strong>Reason:</strong> <span style="color:var(--accent-red)">${reason}</span></p>
    `;
    document.getElementById('escrow-modal').classList.add('active');
}

function closeEscrowModal() {
    document.getElementById('escrow-modal').classList.remove('active');
    currentEscrowId = null;
}

async function resolveEscrow(decision) {
    if (!currentEscrowId) return;
    
    try {
        await fetch(`${API_BASE}/approval/${currentEscrowId}`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ decision: decision })
        });
        
        closeEscrowModal();
        fetchStats();
        fetchEvents();
    } catch (e) {
        console.error("Failed to resolve escrow", e);
        alert("Failed to submit decision to gateway");
    }
}

// Event Listeners
document.getElementById('btn-close').addEventListener('click', closeEscrowModal);
document.getElementById('btn-approve').addEventListener('click', () => resolveEscrow('APPROVE'));
document.getElementById('btn-reject').addEventListener('click', () => resolveEscrow('REJECT'));

// Poll loop
setInterval(() => {
    fetchStats();
    fetchEvents();
}, 2000);

// Initial load
fetchStats();
fetchEvents();
