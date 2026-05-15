/* HomeNetGuard Dashboard — Main JS */
'use strict';

// ─── Socket.IO connection ────────────────────────────────────
const socket = io({ transports: ['websocket', 'polling'] });

// ─── State ───────────────────────────────────────────────────
const state = {
  bpsHistory: Array(60).fill(0),
  lastStats: {},
  charts: {},
};

// ─── DOM refs ─────────────────────────────────────────────────
const $ = (id) => document.getElementById(id);

// ─── Clock ────────────────────────────────────────────────────
function updateClock() {
  const el = $('utc-clock');
  if (el) el.textContent = new Date().toUTCString().slice(17, 25) + ' UTC';
}
setInterval(updateClock, 1000);
updateClock();

// ─── Relative time ────────────────────────────────────────────
function relativeTime(iso) {
  const diff = Math.floor((Date.now() - new Date(iso)) / 1000);
  if (diff < 60)  return `${diff}s ago`;
  if (diff < 3600) return `${Math.floor(diff/60)}m ago`;
  return `${Math.floor(diff/3600)}h ago`;
}

// ─── Format bytes ─────────────────────────────────────────────
function fmtBytes(b) {
  if (b < 1024)        return b + ' B';
  if (b < 1048576)     return (b/1024).toFixed(1) + ' KB';
  if (b < 1073741824)  return (b/1048576).toFixed(1) + ' MB';
  return (b/1073741824).toFixed(2) + ' GB';
}

// ─── Severity badge ───────────────────────────────────────────
function sevBadge(sev) {
  return `<span class="badge badge-${sev}">${sev}</span>`;
}

// ─── Protocol badge ───────────────────────────────────────────
function protoBadge(proto) {
  const cls = proto ? `badge-${proto.toLowerCase()}` : '';
  return `<span class="badge ${cls}">${proto || '?'}</span>`;
}

// ─── Socket events ────────────────────────────────────────────
socket.on('connect', () => {
  console.log('[HNG] WebSocket connected');
  const ind = $('connection-indicator');
  if (ind) { ind.className = 'indicator indicator-live'; }
});

socket.on('disconnect', () => {
  const ind = $('connection-indicator');
  if (ind) { ind.className = 'indicator indicator-offline'; }
});

socket.on('stats_update', (data) => {
  state.lastStats = data;
  updateKPIs(data.stats);
  updateAlertFeed(data.alerts || []);
  updateFlowsTable(data.flows || []);
  updateBpsChart(data.stats?.total_bytes || 0);
});

// ─── KPI update ───────────────────────────────────────────────
function updateKPIs(stats) {
  if (!stats) return;

  setKPI('kpi-flows', stats.total_flows || 0);
  setKPI('kpi-bytes', fmtBytes(stats.total_bytes || 0));
  setKPI('kpi-src-ips', stats.unique_src_ips || 0);

  const alertCount = (state.lastStats.alerts || []).length;
  const alertEl = $('kpi-alerts');
  if (alertEl) {
    alertEl.textContent = alertCount;
    alertEl.className = `kpi-value ${alertCount > 0 ? 'danger' : 'ok'}`;
  }
}

function setKPI(id, value) {
  const el = $(id);
  if (el) el.textContent = value;
}

// ─── Alert feed ───────────────────────────────────────────────
function updateAlertFeed(alerts) {
  const feed = $('alert-feed');
  if (!feed) return;

  if (!alerts.length) {
    feed.innerHTML = `<div class="empty-state"><span class="empty-state-icon">✓</span>No active alerts</div>`;
    updateTicker([]);
    return;
  }

  feed.innerHTML = alerts.map(a => `
    <div class="alert-item sev-${a.severity}"
         onclick="window.location='/alerts'" style="cursor:pointer;">
      <span class="alert-icon">${sevIcon(a.severity)}</span>
      <div class="alert-body">
        <div class="alert-type">${a.alert_type.replace(/_/g,' ').toUpperCase()}</div>
        <div class="alert-desc">${a.description}</div>
        <div class="alert-meta">
          ${a.src_ip ? `<span class="text-mono">${a.src_ip}</span>` : ''}
        </div>
      </div>
      <span class="alert-time">${relativeTime(a.timestamp)}</span>
    </div>
  `).join('');

  updateTicker(alerts.filter(a => a.severity === 'critical'));
}

function sevIcon(sev) {
  return { critical: '🔴', high: '🟠', medium: '🟡', low: '🔵', info: '⚪' }[sev] || '⚫';
}

function updateTicker(criticalAlerts) {
  const ticker = $('ticker-content');
  if (!ticker) return;
  if (!criticalAlerts.length) { ticker.textContent = ''; return; }
  ticker.textContent = criticalAlerts.map(a =>
    `⚠ ${a.alert_type.toUpperCase()}: ${a.description}`
  ).join('   ···   ');
}

// ─── Live flows table ─────────────────────────────────────────
let _flowRows = [];
const MAX_FLOW_ROWS = 100;

function updateFlowsTable(flows) {
  const tbody = $('flows-tbody');
  if (!tbody || !flows.length) return;

  flows.forEach(f => {
    const rep = false; // reputation checked server-side via row class
    const rowClass = `row-new row-${(f.protocol||'').toLowerCase()}`;
    const tr = document.createElement('tr');
    tr.className = rowClass;
    tr.innerHTML = `
      <td class="text-mono">${f.timestamp ? f.timestamp.slice(11,19) : '--'}</td>
      <td class="ip-address">${f.src_ip || '--'}</td>
      <td class="ip-address">${f.dst_ip || '--'}</td>
      <td>${protoBadge(f.protocol)}</td>
      <td class="port">${f.src_port || '--'}</td>
      <td class="port">${f.dst_port || '--'}</td>
      <td class="text-mono">${fmtBytes(f.bytes || 0)}</td>
      <td class="text-mono">${f.src_country || '--'}</td>
    `;
    tbody.insertBefore(tr, tbody.firstChild);
    _flowRows.push(tr);

    if (_flowRows.length > MAX_FLOW_ROWS) {
      const old = _flowRows.shift();
      old.remove();
    }
  });
}

// ─── BPS Chart (Chart.js) ─────────────────────────────────────
function initBpsChart() {
  const canvas = $('bps-chart');
  if (!canvas || !window.Chart) return;

  const ctx = canvas.getContext('2d');
  const labels = Array(60).fill('');

  const gradient = ctx.createLinearGradient(0, 0, 0, canvas.height);
  gradient.addColorStop(0, 'rgba(0,255,136,0.25)');
  gradient.addColorStop(1, 'rgba(0,255,136,0)');

  state.charts.bps = new Chart(ctx, {
    type: 'line',
    data: {
      labels,
      datasets: [{
        data: [...state.bpsHistory],
        borderColor: '#00ff88',
        borderWidth: 2,
        fill: true,
        backgroundColor: gradient,
        tension: 0.4,
        pointRadius: 0,
      }]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      animation: false,
      scales: {
        x: { display: false },
        y: {
          grid: { color: '#1e2a38', drawBorder: false },
          ticks: { color: '#4a5568', font: { family: 'JetBrains Mono', size: 10 },
            callback: (v) => fmtBytes(v) },
        }
      },
      plugins: { legend: { display: false }, tooltip: {
        backgroundColor: '#0e1319',
        borderColor: '#1e2a38',
        borderWidth: 1,
        titleColor: '#8899aa',
        bodyColor: '#00ff88',
        bodyFont: { family: 'JetBrains Mono' },
        callbacks: { label: (ctx) => fmtBytes(ctx.parsed.y) + '/s' },
      }},
    }
  });
}

function updateBpsChart(totalBytes) {
  const chart = state.charts.bps;
  if (!chart) return;
  state.bpsHistory.push(totalBytes);
  state.bpsHistory.shift();
  chart.data.datasets[0].data = [...state.bpsHistory];
  chart.update('none');
}

// ─── Protocol Pie Chart ───────────────────────────────────────
async function loadProtocolChart() {
  const canvas = $('proto-chart');
  if (!canvas || !window.Chart) return;

  try {
    const res = await fetch('/api/protocols');
    const data = await res.json();
    if (!data.length) return;

    const colors = ['#00ff88','#00d4ff','#ff7b2c','#ffcc00','#ff3b5c','#6b7f99'];
    const ctx = canvas.getContext('2d');

    if (state.charts.proto) state.charts.proto.destroy();
    state.charts.proto = new Chart(ctx, {
      type: 'doughnut',
      data: {
        labels: data.map(d => d.protocol),
        datasets: [{
          data: data.map(d => d.count),
          backgroundColor: data.map((_, i) => colors[i % colors.length]),
          borderWidth: 0,
          hoverOffset: 4,
        }]
      },
      options: {
        responsive: true,
        plugins: {
          legend: { position: 'right', labels: { color: '#8899aa', font: { size: 11 }, padding: 12 }},
          tooltip: {
            backgroundColor: '#0e1319', borderColor: '#1e2a38', borderWidth: 1,
            titleColor: '#8899aa', bodyColor: '#e8f0fe',
          }
        }
      }
    });
  } catch (e) { console.error('Protocol chart error', e); }
}

// ─── Geo Map (Leaflet) ────────────────────────────────────────
let _map = null;
let _markers = [];

function initGeoMap() {
  const mapEl = $('geo-map');
  if (!mapEl || !window.L) return;

  _map = L.map('geo-map', { zoomControl: true, scrollWheelZoom: false })
    .setView([20, 0], 2);

  L.tileLayer('https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png', {
    attribution: '&copy; OpenStreetMap &copy; CartoDB',
    subdomains: 'abcd', maxZoom: 18,
  }).addTo(_map);
}

async function updateGeoMap() {
  if (!_map) return;
  try {
    const res = await fetch('/api/geo-data');
    const points = await res.json();

    _markers.forEach(m => _map.removeLayer(m));
    _markers = [];

    points.forEach(p => {
      // Simple geocoding stub — real lat/lon would come from GeoIP
      // Using random offset for demo (real impl needs lat/lon from GeoIP)
      const isMalicious = p.status === 'malicious';
      const color = isMalicious ? '#ff3b5c' : '#00ff88';
      const radius = Math.max(4, Math.min(15, Math.log2((p.bytes || 1) + 1)));

      // Skip if no meaningful geo data available
      // In production, lat/lon from GeoIP2 reader would be stored in flows
    });
  } catch(e) { /* geo map is optional */ }
}

// ─── Top IPs table ────────────────────────────────────────────
async function loadTopIPs() {
  const tbody = $('top-ips-tbody');
  if (!tbody) return;
  try {
    const res = await fetch('/api/top-ips');
    const data = await res.json();
    if (!data.length) {
      tbody.innerHTML = `<tr><td colspan="3" class="empty-state">No data yet</td></tr>`;
      return;
    }
    tbody.innerHTML = data.map((ip, i) => `
      <tr>
        <td class="text-mono">${i+1}</td>
        <td class="ip-address">${ip.ip}</td>
        <td class="text-mono">${fmtBytes(ip.total_bytes)}</td>
      </tr>
    `).join('');
  } catch(e) { console.error('Top IPs error', e); }
}

// ─── Alert modal ──────────────────────────────────────────────
async function openAlertModal(alertId) {
  const overlay = $('alert-modal');
  if (!overlay) return;
  // Fetch alert details and populate modal
  const alerts = state.lastStats.alerts || [];
  const alert = alerts.find(a => a.id === alertId);
  if (alert) {
    const body = $('modal-body');
    if (body) body.innerHTML = `
      <div style="display:flex;flex-direction:column;gap:10px;">
        <div>${sevBadge(alert.severity)} ${protoBadge(alert.alert_type)}</div>
        <div class="text-mono" style="font-size:0.8rem;">${alert.description}</div>
        ${alert.src_ip ? `<div>Source: <span class="ip-address">${alert.src_ip}</span></div>` : ''}
        <div class="text-muted" style="font-size:0.72rem;">${alert.timestamp}</div>
      </div>
    `;
  }
  overlay.classList.remove('hidden');
}

function closeAlertModal() {
  const overlay = $('alert-modal');
  if (overlay) overlay.classList.add('hidden');
}

// ─── Acknowledge alert ────────────────────────────────────────
async function acknowledgeAlert(alertId) {
  await fetch(`/api/alerts/${alertId}/acknowledge`, { method: 'POST' });
  closeAlertModal();
}

// ─── Stop capture ─────────────────────────────────────────────
async function stopCapture() {
  if (!confirm('Stop packet capture?')) return;
  // CLI manages the sniffer process — we just signal via API stub
  console.log('[HNG] Stop capture requested');
}

// ─── Init ─────────────────────────────────────────────────────
document.addEventListener('DOMContentLoaded', () => {
  initBpsChart();
  initGeoMap();
  loadProtocolChart();
  loadTopIPs();
  setInterval(loadTopIPs, 10000);
  setInterval(loadProtocolChart, 30000);
  setInterval(updateGeoMap, 15000);
});
