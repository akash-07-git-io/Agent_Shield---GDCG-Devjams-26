/**
 * AGENTSHIELD - ENTERPRISE AI SECURITY GATEWAY DASHBOARD
 * Client Application Logic & Telemetry Controller
 */

const API_BASE = '/api';

// Global Application State
let state = {
    currentView: 'overview',
    stats: {},
    events: [],
    policies: [],
    agents: [],
    playbooks: [],
    health: {},
    activityFilter: 'ALL',
    searchQuery: '',
    currentEscrowEvent: null,
    selectedEventId: null,
    pollingInterval: null
};

// 7-Stage Pipeline Explanations
const PIPELINE_STAGES = {
    1: {
        title: 'AGENT',
        desc: 'Autonomous AI agent executes tool calls based on user prompt or autonomous task workflow.',
        detail: 'Action object created with Agent ID, Tool, Resource, Destination, and Context.',
        latency: '~0.4ms'
    },
    2: {
        title: 'INTERCEPT',
        desc: 'AgentShield Zero-Trust Gateway intercepts all outbound execution requests before runtime delivery.',
        detail: 'Gateway holds the execution payload in a secure execution barrier.',
        latency: '1.2ms'
    },
    3: {
        title: 'ANALYSE',
        desc: 'Intent Intelligence Engine (Gemma-Edge) evaluates prompt, semantic context, and risk indicators.',
        detail: 'Detects prompt injections, goal hijacking, and unauthorized egress destinations.',
        latency: '14.8ms'
    },
    4: {
        title: 'SCORE',
        desc: 'Risk Engine aggregates multi-dimensional anomaly indicators and computes numerical risk (0-100).',
        detail: 'Assigns Threat Category (Data Exfiltration, Prompt Injection, Privilege Escalation, etc.).',
        latency: '1.1ms'
    },
    5: {
        title: 'POLICY',
        desc: 'Deterministic Rule Engine evaluates matched enterprise constraints (default_policies.yaml).',
        detail: 'Evaluates priority rules: RULE-001 through RULE-006 with fail-closed guarantee.',
        latency: '0.8ms'
    },
    6: {
        title: 'DECIDE',
        desc: 'Gateway enforces decision: ALLOW, WARN, HUMAN_APPROVAL (ESCROW), BLOCK, or ISOLATE.',
        detail: 'Triggers automated remediation playbook and contains malicious activity.',
        latency: '0.6ms'
    },
    7: {
        title: 'AUDIT',
        desc: 'Cryptographic evidence record generated with SHA-256 hash and persisted to immutable ledger.',
        detail: 'Full forensic audit chain (WHO, WHAT, WHY, RISK, POLICY, DECISION, WHEN).',
        latency: '2.1ms'
    }
};

/* ==========================================================================
   INITIALIZATION & NAVIGATION
   ========================================================================== */
document.addEventListener('DOMContentLoaded', () => {
    initNavigation();
    loadAllData();
    startRealtimeSync();
});

function initNavigation() {
    const navItems = document.querySelectorAll('#nav-menu .nav-item');
    navItems.forEach(item => {
        item.addEventListener('click', (e) => {
            e.preventDefault();
            const targetView = item.getAttribute('data-view');
            navigateTo(targetView);
        });
    });
}

function navigateTo(viewId) {
    state.currentView = viewId;

    // Update Nav Active Class
    document.querySelectorAll('#nav-menu .nav-item').forEach(item => {
        if (item.getAttribute('data-view') === viewId) {
            item.classList.add('active');
        } else {
            item.classList.remove('active');
        }
    });

    // Update Active View Panel
    document.querySelectorAll('.view-section').forEach(section => {
        section.classList.remove('active-view');
    });

    const targetSection = document.getElementById(`view-${viewId}`);
    if (targetSection) {
        targetSection.classList.add('active-view');
    }

    // Update Topbar Title
    const titleMap = {
        'overview': 'SECURITY OVERVIEW',
        'live-activity': 'LIVE AGENT ACTIVITY STREAM',
        'threats': 'THREAT INVESTIGATION LEDGER',
        'agents': 'AUTHENTICATED AGENT FLEET',
        'policies': 'SECURITY POLICY RULEBOOK',
        'audit': 'IMMUTABLE FORENSIC AUDIT LEDGER',
        'playbooks': 'INCIDENT RESPONSE PLAYBOOKS',
        'system-health': 'SYSTEM HEALTH & TELEMETRY',
        'settings': 'CONFIG & ATTACK SIMULATOR'
    };

    const titleElem = document.getElementById('current-view-title');
    if (titleElem) {
        titleElem.textContent = titleMap[viewId] || 'AGENTSHIELD DASHBOARD';
    }
}

/* ==========================================================================
   DATA LOADING & POLLING
   ========================================================================== */
async function loadAllData() {
    await Promise.all([
        fetchStats(),
        fetchEvents(),
        fetchPolicies(),
        fetchAgents(),
        fetchPlaybooks(),
        fetchHealth()
    ]);
}

function startRealtimeSync() {
    if (state.pollingInterval) clearInterval(state.pollingInterval);

    state.pollingInterval = setInterval(async () => {
        await Promise.all([
            fetchStats(),
            fetchEvents(),
            fetchHealth()
        ]);
        updateSyncTime();
    }, 2000);
}

function updateSyncTime() {
    const syncElem = document.getElementById('last-sync-time');
    if (syncElem) {
        const now = new Date();
        syncElem.textContent = `SYNCED ${now.toLocaleTimeString()}`;
    }
}

/* ==========================================================================
   API FETCH CALLS
   ========================================================================== */
async function fetchStats() {
    try {
        const res = await fetch(`${API_BASE}/dashboard/stats`);
        if (!res.ok) return;
        const data = await res.json();
        state.stats = data;
        renderStats();
    } catch (e) {
        console.warn('Dashboard stats fetch error', e);
    }
}

async function fetchEvents() {
    try {
        const res = await fetch(`${API_BASE}/events`);
        if (!res.ok) return;
        const data = await res.json();
        state.events = data;
        renderEvents();
    } catch (e) {
        console.warn('Events fetch error', e);
    }
}

async function fetchPolicies() {
    try {
        const res = await fetch(`${API_BASE}/policies`);
        if (!res.ok) return;
        const data = await res.json();
        state.policies = data;
        renderPolicies();
    } catch (e) {
        console.warn('Policies fetch error', e);
    }
}

async function fetchAgents() {
    try {
        const res = await fetch(`${API_BASE}/agents`);
        if (!res.ok) return;
        const data = await res.json();
        state.agents = data;
        renderAgents();
    } catch (e) {
        console.warn('Agents fetch error', e);
    }
}

async function fetchPlaybooks() {
    try {
        const res = await fetch(`${API_BASE}/policies/playbooks`);
        if (!res.ok) return;
        const data = await res.json();
        state.playbooks = data;
        renderPlaybooks();
    } catch (e) {
        console.warn('Playbooks fetch error', e);
    }
}

async function fetchHealth() {
    try {
        const res = await fetch(`${API_BASE}/system/health`);
        if (!res.ok) return;
        const data = await res.json();
        state.health = data;
        renderHealth();
    } catch (e) {
        console.warn('Health fetch error', e);
    }
}

/* ==========================================================================
   RENDER METHODS
   ========================================================================== */
function renderStats() {
    const s = state.stats;
    const postureScore = s.security_score !== undefined ? s.security_score : 82;

    const postureElem = document.getElementById('overview-posture-score');
    const gaugeFillElem = document.getElementById('overview-gauge-fill');
    if (postureElem) postureElem.textContent = postureScore;
    if (gaugeFillElem) gaugeFillElem.style.width = `${Math.min(100, Math.max(0, postureScore))}%`;

    const blockedElem = document.getElementById('metric-blocked');
    const escrowElem = document.getElementById('metric-escrow');
    const threatsElem = document.getElementById('metric-threats');
    const allowedElem = document.getElementById('metric-allowed');

    if (blockedElem) blockedElem.textContent = s.blocked ?? 0;
    if (escrowElem) escrowElem.textContent = s.review ?? 0;
    if (threatsElem) threatsElem.textContent = s.threats_detected ?? 0;
    if (allowedElem) allowedElem.textContent = s.allowed ?? 0;

    // Badges in sidebar
    const navActivityCount = document.getElementById('nav-activity-count');
    const navThreatCount = document.getElementById('nav-threat-count');
    if (navActivityCount) navActivityCount.textContent = s.total_actions ?? state.events.length;
    if (navThreatCount) navThreatCount.textContent = s.threats_detected ?? (s.blocked + s.review);
}

function renderEvents() {
    const events = state.events;

    // 1. Render Overview Recent Events (Top 5)
    const overviewBody = document.getElementById('overview-events-body');
    if (overviewBody) {
        overviewBody.innerHTML = '';
        events.slice(0, 5).forEach(ev => {
            overviewBody.appendChild(createEventTableRow(ev, true));
        });
    }

    // 2. Render Live Activity Table with search & filter
    renderLiveActivityTable();

    // 3. Render Threats Table (Blocked or Escrow only)
    const threatsBody = document.getElementById('threats-table-body');
    if (threatsBody) {
        threatsBody.innerHTML = '';
        const threats = events.filter(e => e.decision === 'BLOCK' || e.decision === 'ESCROW' || e.decision === 'HUMAN_APPROVAL' || e.risk_score >= 0.7);
        threats.forEach(ev => {
            const tr = document.createElement('tr');
            tr.onclick = () => openInvestigationModal(ev.event_id);

            const timeStr = formatTime(ev.timestamp);
            const riskPercent = Math.round(ev.risk_score * 100);
            const confidencePercent = ev.intent_analysis?.confidence ? Math.round(ev.intent_analysis.confidence * 100) : 98;

            tr.innerHTML = `
                <td class="time-cell">${timeStr}</td>
                <td class="agent-cell">${ev.agent_id}</td>
                <td><span class="category-tag" style="background:var(--red-bg); color:var(--red-block); border-color:var(--red-border);">${ev.risk_category}</span></td>
                <td class="resource-cell">${escapeHtml(ev.resource)} ${ev.destination ? `<span class="destination-sub">→ ${escapeHtml(ev.destination)}</span>` : ''}</td>
                <td style="font-family:var(--font-mono); color:var(--cyan-primary);">${confidencePercent}%</td>
                <td class="risk-cell" style="color:${getRiskColor(ev.risk_score)};">${riskPercent}/100</td>
                <td><span class="tag-mono">${ev.policy_id || 'RULE-001'}</span></td>
                <td><button class="btn-action-small" onclick="event.stopPropagation(); openInvestigationModal('${ev.event_id}')">INVESTIGATE</button></td>
            `;
            threatsBody.appendChild(tr);
        });
    }

    // 4. Render Audit Ledger Table
    const auditBody = document.getElementById('audit-table-body');
    if (auditBody) {
        auditBody.innerHTML = '';
        events.forEach(ev => {
            const tr = document.createElement('tr');
            tr.onclick = () => openInvestigationModal(ev.event_id);
            const timeStr = formatTime(ev.timestamp);

            tr.innerHTML = `
                <td><span class="tag-mono" style="color:var(--cyan-primary);">${ev.event_id}</span></td>
                <td class="time-cell">${timeStr}</td>
                <td class="agent-cell">${ev.agent_id}</td>
                <td><span style="font-family:var(--font-mono); font-weight:600;">${ev.tool}</span><br><small style="color:var(--text-muted);">${ev.action}</small></td>
                <td class="resource-cell">${escapeHtml(ev.resource)}</td>
                <td style="font-size:0.8rem; color:var(--text-secondary); max-width:260px; overflow:hidden; text-overflow:ellipsis;">${escapeHtml(ev.reason)}</td>
                <td>${renderDecisionBadge(ev.decision)}</td>
                <td style="font-family:var(--font-mono); font-size:0.7rem; color:var(--text-muted);">${(ev.hash_signature || 'sha256:verified').substring(0, 24)}...</td>
            `;
            auditBody.appendChild(tr);
        });
    }
}

function renderLiveActivityTable() {
    const tableBody = document.getElementById('live-activity-table-body');
    if (!tableBody) return;

    tableBody.innerHTML = '';
    let filtered = state.events;

    // Filter by decision
    if (state.activityFilter !== 'ALL') {
        if (state.activityFilter === 'ESCROW') {
            filtered = filtered.filter(e => e.decision === 'ESCROW' || e.decision === 'HUMAN_APPROVAL');
        } else {
            filtered = filtered.filter(e => e.decision === state.activityFilter);
        }
    }

    // Search query filter
    if (state.searchQuery.trim()) {
        const q = state.searchQuery.toLowerCase();
        filtered = filtered.filter(e =>
            (e.agent_id && e.agent_id.toLowerCase().includes(q)) ||
            (e.tool && e.tool.toLowerCase().includes(q)) ||
            (e.resource && e.resource.toLowerCase().includes(q)) ||
            (e.destination && e.destination.toLowerCase().includes(q)) ||
            (e.reason && e.reason.toLowerCase().includes(q)) ||
            (e.event_id && e.event_id.toLowerCase().includes(q))
        );
    }

    const totalCounter = document.getElementById('activity-total-counter');
    if (totalCounter) totalCounter.textContent = `EVENTS: ${filtered.length}`;

    filtered.forEach(ev => {
        tableBody.appendChild(createEventTableRow(ev, false));
    });
}

function createEventTableRow(ev, isMini = false) {
    const tr = document.createElement('tr');
    tr.onclick = () => openInvestigationModal(ev.event_id);

    const timeStr = formatTime(ev.timestamp);
    const riskPercent = Math.round(ev.risk_score * 100);
    const riskColor = getRiskColor(ev.risk_score);

    let actionBtn = `<button class="btn-action-small" onclick="event.stopPropagation(); openInvestigationModal('${ev.event_id}')">INVESTIGATE</button>`;
    if (ev.decision === 'ESCROW' || ev.decision === 'HUMAN_APPROVAL') {
        actionBtn = `<button class="btn-action-small" style="border-color:var(--purple-escrow); color:var(--purple-escrow);" onclick="event.stopPropagation(); openEscrowModal('${ev.event_id}')">REVIEW</button>`;
    }

    if (isMini) {
        tr.innerHTML = `
            <td class="time-cell">${timeStr}</td>
            <td class="agent-cell">${ev.agent_id}</td>
            <td class="action-cell">
                <span class="action-tool">${ev.tool}</span>
                <span class="action-verb">${ev.action}</span>
            </td>
            <td class="resource-cell">${escapeHtml(ev.resource)} ${ev.destination ? `<span class="destination-sub">→ ${escapeHtml(ev.destination)}</span>` : ''}</td>
            <td class="risk-cell" style="color:${riskColor};">${riskPercent}</td>
            <td>${renderDecisionBadge(ev.decision)}</td>
            <td>${actionBtn}</td>
        `;
    } else {
        tr.innerHTML = `
            <td class="time-cell">${timeStr}</td>
            <td class="agent-cell">${ev.agent_id}</td>
            <td class="action-cell">
                <span class="action-tool">${ev.tool}</span>
                <span class="action-verb">${ev.action}</span>
            </td>
            <td class="resource-cell">${escapeHtml(ev.resource)} ${ev.destination ? `<span class="destination-sub">→ ${escapeHtml(ev.destination)}</span>` : ''}</td>
            <td class="risk-cell" style="color:${riskColor};">${riskPercent} / 100</td>
            <td><span class="category-tag">${ev.risk_category || 'NONE'}</span></td>
            <td>${renderDecisionBadge(ev.decision)}</td>
            <td>${actionBtn}</td>
        `;
    }

    return tr;
}

function renderPolicies() {
    const tbody = document.getElementById('policies-table-body');
    if (!tbody) return;

    tbody.innerHTML = '';
    state.policies.forEach(p => {
        const tr = document.createElement('tr');
        tr.innerHTML = `
            <td><span class="tag-mono" style="color:var(--cyan-primary);">${p.id}</span></td>
            <td style="font-weight:600; color:var(--text-primary);">${escapeHtml(p.name)}<br><small style="color:var(--text-muted); font-weight:400;">${escapeHtml(p.description || '')}</small></td>
            <td style="font-family:var(--font-mono); font-size:0.75rem; color:var(--text-secondary);">${escapeHtml(p.conditions || p.resource_patterns?.join(', ') || 'Global rule')}</td>
            <td><span class="category-tag">${p.threat_category || 'SECURITY'}</span></td>
            <td>${renderDecisionBadge(p.decision)}</td>
            <td style="font-size:0.8rem; color:var(--text-secondary);">${escapeHtml(p.remediation || 'Log & Alert')}</td>
        `;
        tbody.appendChild(tr);
    });
}

function renderAgents() {
    const grid = document.getElementById('agent-fleet-grid');
    if (!grid) return;

    grid.innerHTML = '';
    state.agents.forEach(ag => {
        const card = document.createElement('div');
        card.className = 'agent-fleet-card';

        const allowedChips = ag.allowed_tools.map(t => `<span class="tool-chip allowed">✓ ${t}</span>`).join(' ');
        const restrictedChips = ag.restricted_tools.map(t => `<span class="tool-chip restricted">✕ ${t}</span>`).join(' ');

        card.innerHTML = `
            <div class="fleet-card-header">
                <div>
                    <div class="fleet-agent-id">● ${ag.agent_id}</div>
                    <div style="font-size:0.8rem; color:var(--text-secondary);">${ag.name} (${ag.role})</div>
                </div>
                <span class="badge-decision badge-allow">${ag.status}</span>
            </div>

            <div class="agent-meta-rows">
                <div class="agent-meta-item">
                    <span class="meta-k">Assigned User</span>
                    <span class="meta-v">${ag.user_id}</span>
                </div>
                <div class="agent-meta-item">
                    <span class="meta-k">Inference Model</span>
                    <span class="meta-v">${ag.model}</span>
                </div>
                <div class="agent-meta-item">
                    <span class="meta-k">Actions Today</span>
                    <span class="meta-v">${ag.actions_today} (${ag.blocked_today} Blocked)</span>
                </div>
                <div class="agent-meta-item">
                    <span class="meta-k">Avg Risk Score</span>
                    <span class="meta-v">${Math.round(ag.avg_risk * 100)} / 100</span>
                </div>
            </div>

            <div>
                <div style="font-family:var(--font-mono); font-size:0.7rem; color:var(--text-muted); margin-bottom:4px;">ALLOWED CAPABILITIES</div>
                <div class="tools-chip-group">${allowedChips}</div>
            </div>

            <div>
                <div style="font-family:var(--font-mono); font-size:0.7rem; color:var(--text-muted); margin-bottom:4px;">RESTRICTED ESCROW TOOLS</div>
                <div class="tools-chip-group">${restrictedChips}</div>
            </div>
        `;
        grid.appendChild(card);
    });
}

function renderPlaybooks() {
    const container = document.getElementById('playbooks-container');
    if (!container) return;

    container.innerHTML = '';
    state.playbooks.forEach(pb => {
        const pbCard = document.createElement('div');
        pbCard.className = 'card-panel card-panel-elevated';

        const stepsHtml = pb.steps.map(s => `
            <div class="playbook-step-item">
                <span class="step-check-icon">✓</span>
                <div>
                    <strong style="color:var(--text-primary); font-family:var(--font-mono); font-size:0.8rem;">Step ${s.step}: ${s.action}</strong>
                    <span class="tag-mono" style="margin-left:6px; font-size:0.65rem;">${s.status}</span>
                </div>
            </div>
        `).join('');

        pbCard.innerHTML = `
            <div class="panel-header">
                <div>
                    <div style="font-size:1.05rem; font-weight:700; color:var(--cyan-primary); font-family:var(--font-mono);">${pb.name}</div>
                    <div style="font-size:0.8rem; color:var(--text-secondary); margin-top:2px;">Trigger Category: <strong style="color:var(--red-block);">${pb.threat_category}</strong></div>
                </div>
                <span class="tag-mono" style="color:var(--green-allow); border-color:var(--green-border);">EXECUTED: ${pb.executed_count} TIMES</span>
            </div>
            <p style="font-size:0.85rem; color:var(--text-secondary); margin-bottom:1rem;">${pb.trigger}</p>
            <div style="display:flex; flex-direction:column; gap:0.6rem;">${stepsHtml}</div>
        `;
        container.appendChild(pbCard);
    });
}

function renderHealth() {
    const grid = document.getElementById('health-services-grid');
    if (!grid || !state.health.services) return;

    grid.innerHTML = '';
    state.health.services.forEach(srv => {
        const card = document.createElement('div');
        card.className = 'health-service-card';
        card.innerHTML = `
            <div class="service-header">
                <span class="service-name">${srv.name}</span>
                <span class="badge-decision badge-allow">● ${srv.status}</span>
            </div>
            <div style="display:flex; justify-content:space-between; font-size:0.75rem; color:var(--text-secondary);">
                <span>Telemetry Latency</span>
                <span class="service-latency">${srv.latency}</span>
            </div>
            ${srv.model ? `<div style="font-size:0.72rem; color:var(--text-muted); font-family:var(--font-mono);">Model: ${srv.model}</div>` : ''}
            ${srv.active_rules ? `<div style="font-size:0.72rem; color:var(--text-muted); font-family:var(--font-mono);">Active Rules: ${srv.active_rules}</div>` : ''}
        `;
        grid.appendChild(card);
    });

    const statusBadge = document.getElementById('gateway-status-badge');
    if (statusBadge) {
        statusBadge.textContent = state.health.gateway_connected ? 'PROTECTED (ONLINE)' : 'SIMULATED (ONLINE)';
    }
}

/* ==========================================================================
   THE MONEY SCREEN: THREAT INVESTIGATION SPLIT-SCREEN MODAL
   ========================================================================== */
function openInvestigationModal(eventId) {
    const event = state.events.find(e => e.event_id === eventId);
    if (!event) return;

    state.selectedEventId = eventId;

    // Fill Left Context
    document.getElementById('inv-event-id').textContent = event.event_id;
    document.getElementById('inv-agent-id').textContent = event.agent_id;
    document.getElementById('inv-user-id').textContent = event.user_id || 'developer-01';
    document.getElementById('inv-tool-action').textContent = `${event.tool} (${event.action})`;
    document.getElementById('inv-resource').textContent = event.resource;
    document.getElementById('inv-destination').textContent = event.destination || 'N/A (Local Resource)';
    document.getElementById('inv-timestamp').textContent = formatTimestampFull(event.timestamp);
    document.getElementById('inv-context').textContent = event.context || 'Autonomous execution workflow';
    document.getElementById('inv-payload-preview').textContent = event.payload_preview || `${event.tool}:${event.action} on ${event.resource}`;
    document.getElementById('inv-hash-signature').textContent = event.hash_signature || `sha256:proof_${event.event_id}`;

    // Fill Right Multi-Stage Reasoning Chain
    const intent = event.intent_analysis || {};
    document.getElementById('inv-intent-desc').textContent = intent.intent || 'Observed tool execution request.';
    document.getElementById('inv-intent-confidence').textContent = `CONFIDENCE: ${intent.confidence ? Math.round(intent.confidence * 100) : 98}%`;

    const indicatorsElem = document.getElementById('inv-risk-indicators');
    indicatorsElem.innerHTML = '';
    if (intent.risk_indicators && intent.risk_indicators.length > 0) {
        intent.risk_indicators.forEach(ind => {
            const pill = document.createElement('span');
            pill.className = 'indicator-pill';
            pill.textContent = ind;
            indicatorsElem.appendChild(pill);
        });
    } else {
        indicatorsElem.innerHTML = '<span class="indicator-pill" style="background:var(--green-bg); color:var(--green-allow); border-color:var(--green-border);">clean_telemetry</span>';
    }

    const riskPercent = Math.round(event.risk_score * 100);
    const riskElem = document.getElementById('inv-risk-score');
    riskElem.textContent = `${riskPercent} / 100`;
    riskElem.style.color = getRiskColor(event.risk_score);

    document.getElementById('inv-risk-category').textContent = event.risk_category || 'NONE';
    document.getElementById('inv-model-version').textContent = event.model_version || 'model-armor-v1.0+gemma-edge';
    document.getElementById('inv-latency').textContent = `${event.latency_ms || 14.2}ms`;

    document.getElementById('inv-policy-id').textContent = event.policy_id || 'RULE-001';
    document.getElementById('inv-policy-reason').textContent = event.reason;

    const decBadge = document.getElementById('inv-decision-badge');
    decBadge.className = `badge-decision ${getDecisionBadgeClass(event.decision)}`;
    decBadge.textContent = `${event.decision === 'BLOCK' ? '🔴' : (event.decision === 'ESCROW' ? '🟣' : '🟢')} ${event.decision}`;

    document.getElementById('inv-playbook-key').textContent = event.playbook || 'DEFAULT_ISOLATE';
    document.getElementById('inv-remediation-text').textContent = event.remediation || 'Execution evaluated and logged to immutable audit ledger.';

    document.getElementById('investigation-modal').classList.add('active');
}

function closeInvestigationModal() {
    document.getElementById('investigation-modal').classList.remove('active');
    state.selectedEventId = null;
}

/* ==========================================================================
   ESCROW APPROVAL WORKFLOW
   ========================================================================== */
function openEscrowModal(eventId) {
    let event = state.events.find(e => e.event_id === eventId || e.escrow_id === eventId);
    if (!event) {
        event = {
            event_id: eventId || 'EVT-00123',
            agent_id: 'devops-agent-01',
            tool: 'db_query',
            action: 'write',
            resource: 'production_users',
            reason: 'Triggered RULE-003: Write operation on production database requires human administrator approval.'
        };
    }

    state.currentEscrowEvent = event;

    const idElem = document.getElementById('escrow-event-id');
    const agentElem = document.getElementById('escrow-agent-id');
    const actElem = document.getElementById('escrow-action');
    const resElem = document.getElementById('escrow-resource');
    const reasonElem = document.getElementById('escrow-reason');

    if (idElem) idElem.textContent = event.event_id;
    if (agentElem) agentElem.textContent = event.agent_id;
    if (actElem) actElem.textContent = `${event.tool} (${event.action})`;
    if (resElem) resElem.textContent = event.resource;
    if (reasonElem) reasonElem.textContent = event.reason;

    const modal = document.getElementById('escrow-modal');
    if (modal) modal.classList.add('active');
}

function closeEscrowModal() {
    const modal = document.getElementById('escrow-modal');
    if (modal) modal.classList.remove('active');
    state.currentEscrowEvent = null;
}

async function handleEscrowDecision(decision) {
    const eventId = state.currentEscrowEvent?.event_id || document.getElementById('escrow-event-id')?.textContent?.trim() || 'EVT-00123';
    
    // Disable buttons to indicate active processing
    const rejectBtn = document.getElementById('btn-escrow-reject');
    const approveBtn = document.getElementById('btn-escrow-approve');
    if (rejectBtn) rejectBtn.disabled = true;
    if (approveBtn) approveBtn.disabled = true;

    try {
        // 1. Send API request
        await fetch(`${API_BASE}/approval/${eventId}`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ decision: decision, reviewer: 'security-operator' })
        });

        // 2. Instant client-side state update for snappy UI feel
        const ev = state.events.find(e => e.event_id === eventId || e.escrow_id === eventId);
        if (ev) {
            ev.decision = decision === 'APPROVE' ? 'ALLOW' : 'BLOCK';
            ev.reason = `Human operator resolved escrow: ${decision === 'APPROVE' ? 'Approved execution' : 'Rejected & Blocked'}`;
        }

        // Close modal
        closeEscrowModal();

        // 3. Immediately re-render stats & tables
        await Promise.all([fetchStats(), fetchEvents()]);

        // 4. Show toast notification
        showToast(
            decision === 'APPROVE' ? '✓ ESCROW RESOLVED: ACTION ALLOWED' : '✕ ESCROW RESOLVED: ACTION BLOCKED',
            decision === 'APPROVE' ? 'var(--green-allow)' : 'var(--red-block)'
        );
    } catch (e) {
        console.error('Escrow resolve error', e);
        closeEscrowModal();
    } finally {
        if (rejectBtn) rejectBtn.disabled = false;
        if (approveBtn) approveBtn.disabled = false;
    }
}

function showToast(message, color = 'var(--cyan-primary)') {
    let toast = document.getElementById('agent-toast');
    if (!toast) {
        toast = document.createElement('div');
        toast.id = 'agent-toast';
        toast.style.position = 'fixed';
        toast.style.bottom = '24px';
        toast.style.right = '24px';
        toast.style.padding = '12px 22px';
        toast.style.background = '#111115';
        toast.style.border = '1px solid ' + color;
        toast.style.color = '#F9FAFB';
        toast.style.fontFamily = 'var(--font-mono)';
        toast.style.fontSize = '0.82rem';
        toast.style.fontWeight = '600';
        toast.style.borderRadius = '8px';
        toast.style.boxShadow = '0 10px 30px rgba(0,0,0,0.9), 0 0 15px ' + color;
        toast.style.zIndex = '9999';
        toast.style.transition = 'all 0.3s cubic-bezier(0.16, 1, 0.3, 1)';
        toast.style.display = 'flex';
        toast.style.alignItems = 'center';
        toast.style.gap = '8px';
        document.body.appendChild(toast);
    }
    toast.innerHTML = `<span style="color:${color}; font-size:1.1rem;">●</span> <span>${message}</span>`;
    toast.style.borderColor = color;
    toast.style.opacity = '1';
    toast.style.transform = 'translateY(0)';

    setTimeout(() => {
        if (toast) {
            toast.style.opacity = '0';
            toast.style.transform = 'translateY(12px)';
        }
    }, 3200);
}

/* ==========================================================================
   PIPELINE INSPECTOR
   ========================================================================== */
function inspectPipelineStage(stageNum) {
    const stage = PIPELINE_STAGES[stageNum];
    if (!stage) return;

    // Highlight active node
    document.querySelectorAll('.pipeline-step-node').forEach((node, index) => {
        if (index + 1 === stageNum) {
            node.classList.add('active-step');
        } else {
            node.classList.remove('active-step');
        }
    });

    const box = document.getElementById('pipeline-inspector-box');
    if (box) {
        box.innerHTML = `
            <div class="inspector-info">
                Stage 0${stageNum}: <strong>${stage.title}</strong> — ${stage.desc} <span style="color:var(--text-muted); font-size:0.75rem;">(${stage.detail})</span>
            </div>
            <div class="inspector-action">Telemetry Latency: ${stage.latency}</div>
        `;
    }
}

/* ==========================================================================
   DEMO ATTACK SIMULATOR
   ========================================================================== */
async function triggerSimulator(scenarioId) {
    try {
        const res = await fetch(`${API_BASE}/simulate/trigger`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ scenario_id: scenarioId })
        });

        if (res.ok) {
            const data = await res.json();
            const createdEvt = data.event;

            // Immediately update local state
            await Promise.all([fetchStats(), fetchEvents()]);

            // Provide immediate contextual feedback
            if (scenarioId === 'EXFILTRATION') {
                showToast('🔴 ATTACK BLOCKED: DATA EXFILTRATION ATTEMPT (RULE-001)', 'var(--red-block)');
            } else if (scenarioId === 'INJECTION') {
                showToast('🔴 ATTACK BLOCKED: PROMPT INJECTION DETECTED (RULE-004)', 'var(--red-block)');
            } else if (scenarioId === 'ESCROW') {
                showToast('🟣 ACTION ESCROWED: HUMAN APPROVAL REQUIRED (RULE-003)', 'var(--purple-escrow)');
                if (createdEvt && createdEvt.event_id) {
                    // Open Escrow Modal instantly with zero delay
                    openEscrowModal(createdEvt.event_id);
                }
            } else if (scenarioId === 'SAFE') {
                showToast('🟢 DIAGNOSTIC PASSED: SAFE READ-ONLY ACTION ALLOWED (RULE-002)', 'var(--green-allow)');
            }
        }
    } catch (e) {
        console.error('Simulation error', e);
        showToast('Simulation error: Check Gateway connection', 'var(--amber-warn)');
    }
}

/* ==========================================================================
   FILTERS & UTILITIES
   ========================================================================== */
function setActivityFilter(filterName) {
    state.activityFilter = filterName;
    document.querySelectorAll('.filter-group .filter-btn').forEach(btn => {
        if (btn.getAttribute('data-filter') === filterName) {
            btn.classList.add('active');
        } else {
            btn.classList.remove('active');
        }
    });
    renderLiveActivityTable();
}

function filterEventsTable() {
    const input = document.getElementById('activity-search-input');
    state.searchQuery = input ? input.value : '';
    renderLiveActivityTable();
}

function exportAuditLedgerJSON() {
    const dataStr = "data:text/json;charset=utf-8," + encodeURIComponent(JSON.stringify(state.events, null, 2));
    const downloadAnchor = document.createElement('a');
    downloadAnchor.setAttribute("href", dataStr);
    downloadAnchor.setAttribute("download", `AgentShield_Audit_Evidence_${new Date().toISOString().slice(0, 10)}.json`);
    document.body.appendChild(downloadAnchor);
    downloadAnchor.click();
    downloadAnchor.remove();
}

function renderDecisionBadge(decision) {
    const d = (decision || '').toUpperCase();
    if (d === 'BLOCK' || d === 'ISOLATE') {
        return '<span class="badge-decision badge-block">🔴 BLOCK</span>';
    } else if (d === 'ESCROW' || d === 'HUMAN_APPROVAL' || d === 'REVIEW') {
        return '<span class="badge-decision badge-escrow">🟣 ESCROW</span>';
    } else if (d === 'WARN') {
        return '<span class="badge-decision badge-warn">🟡 WARN</span>';
    } else {
        return '<span class="badge-decision badge-allow">🟢 ALLOW</span>';
    }
}

function getDecisionBadgeClass(decision) {
    const d = (decision || '').toUpperCase();
    if (d === 'BLOCK' || d === 'ISOLATE') return 'badge-block';
    if (d === 'ESCROW' || d === 'HUMAN_APPROVAL') return 'badge-escrow';
    if (d === 'WARN') return 'badge-warn';
    return 'badge-allow';
}

function getRiskColor(score) {
    if (score >= 0.85) return 'var(--red-block)';
    if (score >= 0.6) return 'var(--amber-warn)';
    if (score >= 0.3) return 'var(--purple-escrow)';
    return 'var(--green-allow)';
}

function formatTime(timestamp) {
    if (!timestamp) return 'Just now';
    try {
        const d = new Date(timestamp);
        return d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
    } catch {
        return timestamp;
    }
}

function formatTimestampFull(timestamp) {
    if (!timestamp) return '2026-08-30 10:44:12 UTC';
    try {
        const d = new Date(timestamp);
        return d.toUTCString();
    } catch {
        return timestamp;
    }
}

function escapeHtml(text) {
    if (!text) return '';
    const map = { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#039;' };
    return String(text).replace(/[&<>"']/g, m => map[m]);
}
