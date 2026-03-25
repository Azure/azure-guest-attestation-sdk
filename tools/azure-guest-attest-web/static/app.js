// Azure Guest Attestation — Web UI Application Logic

// ---------------------------------------------------------------------------
// Navigation
// ---------------------------------------------------------------------------

document.querySelectorAll('.nav-btn').forEach(btn => {
    btn.addEventListener('click', () => {
        // Deactivate all nav buttons and panels
        document.querySelectorAll('.nav-btn').forEach(b => b.classList.remove('active'));
        document.querySelectorAll('.panel').forEach(p => p.classList.remove('active'));

        // Activate clicked button and corresponding panel
        btn.classList.add('active');
        const panelId = 'panel-' + btn.dataset.panel;
        const panel = document.getElementById(panelId);
        if (panel) panel.classList.add('active');
    });
});

// Update footer time
function updateTime() {
    const el = document.getElementById('footer-time');
    if (el) el.textContent = new Date().toLocaleTimeString();
}
setInterval(updateTime, 1000);
updateTime();

// ---------------------------------------------------------------------------
// API helpers
// ---------------------------------------------------------------------------

async function apiGet(path) {
    const response = await fetch(path);
    return response.json();
}

async function apiPost(path, body) {
    const response = await fetch(path, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
    });
    return response.json();
}

// ---------------------------------------------------------------------------
// Result rendering
// ---------------------------------------------------------------------------

function showLoading(resultId) {
    const el = document.getElementById(resultId);
    el.innerHTML = `
        <div class="result-card">
            <div class="result-header">
                <div class="result-status loading">
                    <span class="status-dot loading"></span>
                    Loading…
                </div>
            </div>
        </div>
    `;
}

function showResult(resultId, data) {
    const el = document.getElementById(resultId);
    const now = new Date().toLocaleTimeString();

    if (!data.success) {
        el.innerHTML = `
            <div class="result-card">
                <div class="result-header">
                    <div class="result-status error">
                        <span class="status-dot error"></span>
                        Error
                    </div>
                    <span class="result-time">${now}</span>
                </div>
                <div class="result-body">
                    <pre>${escapeHtml(data.error || 'Unknown error')}</pre>
                </div>
            </div>
        `;
        return;
    }

    el.innerHTML = `
        <div class="result-card">
            <div class="result-header">
                <div class="result-status success">
                    <span class="status-dot success"></span>
                    Success
                </div>
                <span class="result-time">${now}</span>
            </div>
            <div class="result-body">
                ${renderData(data.data)}
            </div>
        </div>
    `;
}

function showError(resultId, message) {
    showResult(resultId, { success: false, error: message });
}

function renderData(data) {
    if (data === null || data === undefined) {
        return '<pre>(no data)</pre>';
    }
    if (typeof data === 'string') {
        return `<pre>${escapeHtml(data)}</pre>`;
    }
    return renderObject(data);
}

function renderObject(obj, depth = 0) {
    if (typeof obj !== 'object' || obj === null) {
        return `<span>${escapeHtml(String(obj))}</span>`;
    }

    if (Array.isArray(obj)) {
        if (obj.length === 0) return '<span>[]</span>';
        // For arrays of objects (like events), use a compact display
        if (obj.length > 20 && typeof obj[0] === 'object') {
            const first10 = obj.slice(0, 10);
            const last5 = obj.slice(-5);
            let html = '<div class="collapsible">';
            html += `<button class="collapsible-header" onclick="toggleCollapsible(this)">`;
            html += `<span class="arrow">▶</span> Array (${obj.length} items)`;
            html += '</button>';
            html += '<div class="collapsible-body">';
            html += '<pre>' + escapeHtml(JSON.stringify(first10, null, 2)) + '</pre>';
            html += `<p style="color: var(--text-muted); padding: 0.5rem 0;">... ${obj.length - 15} more items ...</p>`;
            html += '<pre>' + escapeHtml(JSON.stringify(last5, null, 2)) + '</pre>';
            html += '</div></div>';
            return html;
        }
        return '<pre>' + escapeHtml(JSON.stringify(obj, null, 2)) + '</pre>';
    }

    // Render as key-value table for objects at top level
    let html = '<table class="kv-table">';
    for (const [key, value] of Object.entries(obj)) {
        html += '<tr>';
        html += `<td>${escapeHtml(key)}</td>`;

        if (typeof value === 'object' && value !== null) {
            // Check for special renderable fields
            if (key === 'tee_report_pretty' || key === 'pretty') {
                html += `<td><div class="pretty-block"><pre>${escapeHtml(String(value))}</pre></div></td>`;
            } else if (key === 'tee_report_hex' || key === 'raw_hex' || key === 'hex') {
                const hexStr = String(value);
                if (hexStr.length > 80) {
                    html += `<td><div class="hex-display">${escapeHtml(hexStr)}</div></td>`;
                } else {
                    html += `<td>${escapeHtml(hexStr)}</td>`;
                }
            } else if (key === 'token') {
                const tokenStr = String(value);
                html += `<td><div class="hex-display" style="max-height: 120px">${escapeHtml(tokenStr)}</div></td>`;
            } else if (key === 'request_json') {
                // Try to pretty-print the JSON string
                let pretty = value;
                try { pretty = JSON.stringify(JSON.parse(value), null, 2); } catch (_) {}
                html += '<td>';
                html += '<div class="collapsible">';
                html += `<button class="collapsible-header" onclick="toggleCollapsible(this)">`;
                html += `<span class="arrow">▶</span> JSON (click to expand)`;
                html += '</button>';
                html += `<div class="collapsible-body"><div class="pretty-block"><pre>${escapeHtml(String(pretty))}</pre></div></div>`;
                html += '</div>';
                html += '</td>';
            } else if (key === 'token_header' || key === 'token_payload' || key === 'header' || key === 'payload') {
                html += `<td><div class="pretty-block"><pre>${escapeHtml(JSON.stringify(value, null, 2))}</pre></div></td>`;
            } else if (key === 'runtime_claims') {
                if (value === null) {
                    html += '<td><span style="color:var(--text-muted)">(no runtime claims present)</span></td>';
                } else {
                    html += `<td><div class="pretty-block"><pre>${escapeHtml(JSON.stringify(value, null, 2))}</pre></div></td>`;
                }
            } else if (key === 'banks') {
                html += '<td>' + renderPcrBanks(value) + '</td>';
            } else if (key === 'events') {
                html += '<td>' + renderEvents(value) + '</td>';
            } else if (key === 'replayed_pcrs_sha256') {
                html += `<td><div class="pretty-block"><pre>${escapeHtml(JSON.stringify(value, null, 2))}</pre></div></td>`;
            } else {
                // Nested object — render as sub-table or JSON
                const subKeys = Object.keys(value);
                if (subKeys.length <= 8 && subKeys.every(k => typeof value[k] !== 'object')) {
                    // Flat sub-object: inline table
                    html += '<td>';
                    html += '<table class="kv-table">';
                    for (const [sk, sv] of Object.entries(value)) {
                        html += `<tr><td>${escapeHtml(sk)}</td><td>${escapeHtml(String(sv))}</td></tr>`;
                    }
                    html += '</table>';
                    html += '</td>';
                } else {
                    html += `<td><div class="pretty-block"><pre>${escapeHtml(JSON.stringify(value, null, 2))}</pre></div></td>`;
                }
            }
        } else if (typeof value === 'string' && value.length > 100) {
            html += `<td><div class="hex-display">${escapeHtml(value)}</div></td>`;
        } else {
            html += `<td>${escapeHtml(String(value))}</td>`;
        }

        html += '</tr>';
    }
    html += '</table>';
    return html;
}

function renderPcrBanks(banks) {
    let html = '';
    for (const [alg, pcrs] of Object.entries(banks)) {
        html += '<div class="collapsible">';
        html += `<button class="collapsible-header" onclick="toggleCollapsible(this)">`;
        html += `<span class="arrow">▶</span> ${escapeHtml(alg)} (${Object.keys(pcrs).length} PCRs)`;
        html += '</button>';
        html += '<div class="collapsible-body">';
        html += '<table class="kv-table">';
        for (const [pcr, digest] of Object.entries(pcrs)) {
            html += `<tr><td>${escapeHtml(pcr)}</td><td style="font-size:0.78rem">${escapeHtml(digest)}</td></tr>`;
        }
        html += '</table>';
        html += '</div></div>';
    }
    return html || '<span>(no PCR banks)</span>';
}

function renderEvents(events) {
    if (!Array.isArray(events) || events.length === 0) {
        return '<span>(no events)</span>';
    }
    let html = '<div class="collapsible">';
    html += `<button class="collapsible-header" onclick="toggleCollapsible(this)">`;
    html += `<span class="arrow">▶</span> ${events.length} events (click to expand)`;
    html += '</button>';
    html += '<div class="collapsible-body">';
    html += '<table class="kv-table">';
    html += '<tr><td><strong>PCR</strong></td><td><strong>Type</strong></td></tr>';
    const displayEvents = events.length > 50 ? events.slice(0, 50) : events;
    for (const evt of displayEvents) {
        const typeName = evt.event_type_name || evt.event_type;
        html += `<tr><td>PCR[${evt.pcr_index}]</td><td>${escapeHtml(typeName)} (${escapeHtml(evt.event_type)})</td></tr>`;
    }
    if (events.length > 50) {
        html += `<tr><td colspan="2" style="color: var(--text-muted)">... ${events.length - 50} more events</td></tr>`;
    }
    html += '</table>';
    html += '</div></div>';
    return html;
}

function toggleCollapsible(btn) {
    btn.classList.toggle('open');
    const body = btn.nextElementSibling;
    if (body) body.classList.toggle('open');
}

function escapeHtml(str) {
    const div = document.createElement('div');
    div.textContent = str;
    return div.innerHTML;
}

// ---------------------------------------------------------------------------
// Toggle MAA endpoint field
// ---------------------------------------------------------------------------

function toggleMaaEndpoint(prefix) {
    const provider = document.getElementById(prefix + '-provider').value;
    const group = document.getElementById(prefix + '-endpoint-group');
    if (group) {
        group.style.display = provider === 'maa' ? 'block' : 'none';
    }
}

// ---------------------------------------------------------------------------
// API action handlers
// ---------------------------------------------------------------------------

async function runDiagnose() {
    showLoading('result-diagnose');
    try {
        const data = await apiGet('/api/diagnose');
        showResult('result-diagnose', data);
    } catch (e) {
        showError('result-diagnose', e.message);
    }
}

async function runCvmReport() {
    showLoading('result-cvm-report');
    try {
        const userData = document.getElementById('cvm-user-data').value;
        let url = '/api/cvm-report';
        if (userData) url += '?user_data=' + encodeURIComponent(userData);
        const data = await apiGet(url);
        showResult('result-cvm-report', data);
    } catch (e) {
        showError('result-cvm-report', e.message);
    }
}

async function runTeeReport() {
    showLoading('result-tee-report');
    try {
        const userData = document.getElementById('tee-user-data').value;
        let url = '/api/tee-report';
        if (userData) url += '?user_data=' + encodeURIComponent(userData);
        const data = await apiGet(url);
        showResult('result-tee-report', data);
    } catch (e) {
        showError('result-tee-report', e.message);
    }
}

async function runTdQuote() {
    showLoading('result-td-quote');
    try {
        const data = await apiGet('/api/td-quote');
        showResult('result-td-quote', data);
    } catch (e) {
        showError('result-td-quote', e.message);
    }
}

async function runIsolationEvidence() {
    showLoading('result-isolation-evidence');
    try {
        const data = await apiGet('/api/isolation-evidence');
        showResult('result-isolation-evidence', data);
    } catch (e) {
        showError('result-isolation-evidence', e.message);
    }
}

async function runAkCert() {
    showLoading('result-ak-cert');
    try {
        const data = await apiGet('/api/ak-cert');
        showResult('result-ak-cert', data);
    } catch (e) {
        showError('result-ak-cert', e.message);
    }
}

async function runAkPub() {
    showLoading('result-ak-pub');
    try {
        const data = await apiGet('/api/ak-pub');
        showResult('result-ak-pub', data);
    } catch (e) {
        showError('result-ak-pub', e.message);
    }
}

async function runPcrs() {
    showLoading('result-pcrs');
    try {
        const indices = document.getElementById('pcr-indices').value;
        let url = '/api/pcrs';
        if (indices) url += '?indices=' + encodeURIComponent(indices);
        const data = await apiGet(url);
        showResult('result-pcrs', data);
    } catch (e) {
        showError('result-pcrs', e.message);
    }
}

async function runEventLog() {
    showLoading('result-event-log');
    try {
        const data = await apiGet('/api/event-log');
        showResult('result-event-log', data);
    } catch (e) {
        showError('result-event-log', e.message);
    }
}

async function runGuestAttest() {
    showLoading('result-guest-attest');
    try {
        const provider = document.getElementById('ga-provider').value;
        const endpoint = document.getElementById('ga-endpoint').value;
        const payload = document.getElementById('ga-payload').value;
        const pcrs = document.getElementById('ga-pcrs').value;
        const decode = document.getElementById('ga-decode').checked;

        const body = {
            provider,
            decode_token: decode,
        };
        if (provider === 'maa' && endpoint) body.endpoint = endpoint;
        if (payload) body.client_payload = payload;
        if (pcrs) {
            body.pcr_indices = pcrs.split(',').map(s => parseInt(s.trim())).filter(n => !isNaN(n));
        }

        const data = await apiPost('/api/guest-attest', body);
        showResult('result-guest-attest', data);
    } catch (e) {
        showError('result-guest-attest', e.message);
    }
}

async function runTeeAttest() {
    showLoading('result-tee-attest');
    try {
        const endpoint = document.getElementById('ta-endpoint').value;
        const decode = document.getElementById('ta-decode').checked;

        const data = await apiPost('/api/tee-attest', {
            endpoint,
            decode_token: decode,
        });
        showResult('result-tee-attest', data);
    } catch (e) {
        showError('result-tee-attest', e.message);
    }
}

async function runParseToken() {
    showLoading('result-parse-token');
    try {
        const token = document.getElementById('pt-token').value.trim();
        if (!token) {
            showError('result-parse-token', 'Please paste a JWT token');
            return;
        }

        const data = await apiPost('/api/parse-token', { token });
        showResult('result-parse-token', data);
    } catch (e) {
        showError('result-parse-token', e.message);
    }
}
