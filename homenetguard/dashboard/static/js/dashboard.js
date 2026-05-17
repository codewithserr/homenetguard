/* HomeNetGuard Dashboard — Main JS */
'use strict';

// ─── Socket.IO connection ────────────────────────────────────
// WebSocket upgrades break Werkzeug 3.x (simple-websocket bypasses WSGI start_response).
// Polling transport is pure HTTP — fully compatible and data still arrives in ≤2s.
const socket = io({ transports: ['polling'] });

// ─── IP Ownership cache & classifier ─────────────────────────
const _ownershipCache = {};

const _KNOWN_GOOD = [
  'google', 'googleapis', 'gstatic', 'cloudflare', 'apple', 'icloud',
  'microsoft', 'azure', 'akamai', 'fastly', 'amazon', 'aws',
  'meta', 'facebook', 'cdn', 'netflix', 'twitch', 'youtube',
  'twitter', 'x corp', 'mozilla', 'mozilla foundation',
];
const _CLOUD_HOSTING = [
  'digitalocean', 'linode', 'vultr', 'ovh', 'hetzner', 'contabo',
  'scaleway', 'upcloud', 'ionos', 'rackspace', 'leaseweb',
  'choopa', 'as-choopa', 'serverius', 'quadranet', 'psychz',
  'datacamp', 'm247', 'serverroom', 'hostinger', 'bluehost',
];

function classifyOrg(org) {
  if (!org) return 'unknown';
  const lower = org.toLowerCase();
  if (_KNOWN_GOOD.some(k => lower.includes(k))) return 'good';
  if (_CLOUD_HOSTING.some(k => lower.includes(k))) return 'cloud';
  if (lower.match(/telecom|telekom|telefon|comcast|verizon|at&t|att |sprint|t-mobile|tmobile|vodafone|orange|swisscom|btgroup|bt group|telia|deutsche|isp|broadband/)) return 'isp';
  return 'unknown';
}

function orgBadge(org, isBlacklisted) {
  if (!org) return '<span class="org-badge org-unknown">unknown</span>';
  const cls = isBlacklisted ? 'org-bad' : `org-${classifyOrg(org)}`;
  const short = org.length > 28 ? org.slice(0, 26) + '…' : org;
  return `<span class="org-badge ${cls}" title="${org}">${short}</span>`;
}

async function loadOwnership() {
  try {
    const res = await fetch('/api/ip-ownership');
    const data = await res.json();
    Object.assign(_ownershipCache, data);
  } catch(e) { /* silent — ownership is best-effort */ }
}

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
  updateSidebarStats(data);
});

function updateSidebarStats(data) {
  const sniffer = data.sniffer || {};
  const sysSniff = $('sys-sniffer');
  const sysBps = $('sys-bps');
  const sysPkts = $('sys-packets');
  if (sysSniff) sysSniff.textContent = sniffer.running ? 'ACTIVE' : 'IDLE';
  if (sysBps && data.stats) {
    const bytes = data.stats.total_bytes || 0;
    sysBps.textContent = bytes > 0
      ? (bytes > 1048576 ? (bytes / 1048576).toFixed(1) + ' MB' : (bytes / 1024).toFixed(0) + ' KB')
      : '0 B';
  }
  if (sysPkts) sysPkts.textContent = sniffer.packets_captured || 0;
}

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
    const dstOwn = _ownershipCache[f.dst_ip] || {};
    const srcOwn = _ownershipCache[f.src_ip] || {};
    const org = dstOwn.org || dstOwn.isp || srcOwn.org || srcOwn.isp || null;
    const isBlacklisted = dstOwn.is_blacklisted || srcOwn.is_blacklisted || false;
    const rowClass = `row-new row-${(f.protocol||'').toLowerCase()}${isBlacklisted ? ' row-malicious' : ''}`;
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
      <td>${orgBadge(org, isBlacklisted)}</td>
      <td class="text-mono" style="font-size:0.68rem;">${f.src_country || '--'}</td>
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
let _mapLayers = [];

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

function _clearMapLayers() {
  _mapLayers.forEach(l => { try { _map.removeLayer(l); } catch(_) {} });
  _mapLayers = [];
}

function _circleMarker(lat, lon, color, radius, tooltip) {
  const m = L.circleMarker([lat, lon], {
    radius,
    color,
    fillColor: color,
    fillOpacity: 0.7,
    weight: 1.5,
    opacity: 0.9,
  }).bindTooltip(tooltip, {
    className: 'leaflet-dark-tooltip',
    direction: 'top',
    offset: [0, -4],
  });
  return m;
}

async function updateGeoMap() {
  if (!_map) return;
  try {
    const res = await fetch('/api/geo-data');
    const points = await res.json();
    if (!points.length) return;

    _clearMapLayers();

    // Home marker — approximate center of all local traffic
    // Use the midpoint of the bounding box as "home" origin for lines
    const lats = points.map(p => p.lat);
    const lons = points.map(p => p.lon);
    // We don't have the local machine's real lat/lon (private IP),
    // so draw markers only — no lines unless we have a home coordinate.

    points.forEach(p => {
      const isMalicious = p.status === 'malicious';
      const isSuspicious = (p.abuse_score || 0) >= 40;
      const color = isMalicious ? '#ff3b5c'
                  : isSuspicious ? '#ffcc00'
                  : '#00ff88';
      const radius = Math.max(5, Math.min(18, 4 + Math.log2((p.bytes || 1) + 1)));

      const own = _ownershipCache[p.ip] || {};
      const orgName = p.org || own.org || own.isp || null;
      const label = [
        `<b class="ip-address">${p.ip}</b>`,
        orgName ? `🏢 ${orgName}` : '',
        p.city ? `📍 ${p.city}, ${p.country}` : (p.country ? `📍 ${p.country}` : ''),
        `📦 ${fmtBytes(p.bytes || 0)}  ·  ${p.flows || 1} flow${(p.flows||1) !== 1 ? 's' : ''}`,
        p.asn ? `<span style="color:#4a5568;">${p.asn}</span>` : '',
        isMalicious ? '🚫 <b style="color:#ff3b5c">BLACKLISTED</b>' : '',
      ].filter(Boolean).join('<br>');

      const marker = _circleMarker(p.lat, p.lon, color, radius, label);
      marker.addTo(_map);
      _mapLayers.push(marker);

      // Pulse ring for malicious IPs
      if (isMalicious) {
        const ring = L.circleMarker([p.lat, p.lon], {
          radius: radius + 6,
          color: '#ff3b5c',
          fillColor: 'transparent',
          fillOpacity: 0,
          weight: 1,
          opacity: 0.4,
        }).addTo(_map);
        _mapLayers.push(ring);
      }
    });

    // Inject tooltip CSS once
    if (!document.getElementById('leaflet-dark-tooltip-style')) {
      const style = document.createElement('style');
      style.id = 'leaflet-dark-tooltip-style';
      style.textContent = `
        .leaflet-dark-tooltip {
          background: #0e1319;
          border: 1px solid #1e2a38;
          color: #e8f0fe;
          font-family: 'JetBrains Mono', monospace;
          font-size: 11px;
          line-height: 1.6;
          padding: 6px 10px;
          border-radius: 3px;
          box-shadow: 0 2px 8px rgba(0,0,0,0.6);
        }
        .leaflet-dark-tooltip::before { border-top-color: #1e2a38; }
        .ip-address { color: #a8d8a8; }
      `;
      document.head.appendChild(style);
    }

  } catch(e) {
    console.debug('[HNG] geo map update error:', e);
  }
}

// ─── Top IPs table ────────────────────────────────────────────
async function loadTopIPs() {
  const tbody = $('top-ips-tbody');
  if (!tbody) return;
  try {
    const res = await fetch('/api/top-ips');
    const data = await res.json();
    if (!data.length) {
      tbody.innerHTML = `<tr><td colspan="4" class="empty-state">No data yet</td></tr>`;
      return;
    }
    tbody.innerHTML = data.map((entry, i) => {
      const own = _ownershipCache[entry.ip] || {};
      const org = own.org || own.isp || null;
      const isBlacklisted = own.is_blacklisted || false;
      return `
        <tr>
          <td class="text-mono">${i+1}</td>
          <td>
            <div class="ip-address" style="line-height:1.8;">${entry.ip}</div>
            <div>${orgBadge(org, isBlacklisted)}</div>
          </td>
          <td class="text-mono">${fmtBytes(entry.total_bytes)}</td>
          <td class="text-mono" style="color:var(--text-muted);">${entry.flow_count || '—'}</td>
        </tr>`;
    }).join('');
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
  loadOwnership().then(() => {
    loadTopIPs();
    updateGeoMap();
  });
  setInterval(loadTopIPs, 10000);
  setInterval(loadProtocolChart, 30000);
  setInterval(updateGeoMap, 15000);
  setInterval(loadOwnership, 60000); // refresh ownership cache every minute
});
