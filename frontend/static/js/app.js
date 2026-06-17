'use strict';

// ══════════════════════════════════════════════════════════
//  STATE
// ══════════════════════════════════════════════════════════
const State = {
  consoleMode: 'live', // 'live' or 'forensic'
  
  // Forensic (Uploaded) Data
  analysisId: null,
  forensicSummary: null,
  forensicThreats: [],
  forensicCustody: [],
  fileHash: '',
  filename: '',
  forensicLogs: [], // logs_sample of 500 rows
  forensicBlocked: new Set(),
  
  // Live SOC Data
  liveSnapshot: null,
  liveThreats: [],
  liveLogs: [],
  liveBlocked: new Set(),
  modsecThreats: [],
  sigmaAlerts: [],
  liveCustody: [],
  
  filteredLogs: [],
  logPage: 0,
  PAGE_SIZE: 25,
  charts: {},
  blockScript: '',
  map: null,
  mapMarkers: [],
  mapLines: []
};

// Host server coordinates (centered at Washington D.C., USA for visualization)
const SERVER_LAT_LON = [38.9072, -77.0369];

// ══════════════════════════════════════════════════════════
//  SOCKET.IO — REAL-TIME
// ══════════════════════════════════════════════════════════
let socket = null;
if (typeof io !== 'undefined') {
  socket = io({ transports: ['websocket', 'polling'] });
  
  socket.on('connect', () => {
    console.log('[Socket] Connected to SOC Core');
  });

  socket.on('disconnect', () => {
    setAgentPill(false, 'Agent Offline');
  });

  socket.on('snapshot', snap => {
    applySnapshot(snap);
  });

  socket.on('agent_status', data => {
    setAgentPill(data.connected, data.connected ? `Agent: ${data.name}` : 'Agent Offline');
    const liveInd = document.getElementById('liveIndicator');
    const status2 = document.getElementById('agentStatus2');
    if (data.connected) {
      if (liveInd) {
        liveInd.textContent = 'LIVE';
        liveInd.className = 'live-badge live';
      }
      if (status2) {
        status2.textContent = data.name;
      }
      clearFeedPlaceholder();
    } else {
      if (liveInd) {
        liveInd.textContent = 'WAITING';
        liveInd.className = 'live-badge waiting';
      }
      if (status2) {
        status2.textContent = 'OFFLINE';
      }
    }
  });

  socket.on('agent_heartbeat', ai => {
    if (ai) {
      const elStatus = document.getElementById('tl-agent-status');
      if (elStatus) {
        elStatus.textContent = ai.status.toUpperCase();
        elStatus.className = 'badge sev-low';
        document.getElementById('tl-hostname').textContent = ai.hostname;
        document.getElementById('tl-os').textContent = ai.os;
        document.getElementById('tl-last-seen').textContent = new Date(ai.last_seen).toLocaleTimeString();
        
        document.getElementById('tl-cpu-pct').textContent = ai.cpu_usage;
        document.getElementById('tl-cpu-fill').style.width = ai.cpu_usage;
        
        document.getElementById('tl-mem-pct').textContent = ai.memory_usage;
        document.getElementById('tl-mem-fill').style.width = ai.memory_usage;
        
        document.getElementById('tl-disk-pct').textContent = ai.disk_usage;
        document.getElementById('tl-disk-fill').style.width = ai.disk_usage;
      }
    }
  });

  socket.on('new_log', entry => {
    State.liveLogs.unshift(entry);
    if (State.liveLogs.length > 2000) State.liveLogs.pop();
    if (State.consoleMode === 'live') {
      appendFeedLine(entry);
    }
  });

  socket.on('new_threat', threat => {
    State.liveThreats.unshift(threat);
    
    if (State.consoleMode === 'live') {
      appendAlertItem(threat);
      showToast(threat);
      activateMitreCell(threat.type);
      plotThreatOnMap(threat.ip, threat.type, threat.severity);
      
      const badge = document.getElementById('threatBadge');
      if (badge) badge.style.display = '';
      
      const elLvThreats = document.getElementById('lv-threats');
      if (elLvThreats) elLvThreats.textContent = State.liveThreats.length;
      
      if (isActiveView('threats')) renderThreats();
      updateDashboardTrendsChart();
    }
  });

  socket.on('stats_update', s => {
    if (State.liveSnapshot) {
      State.liveSnapshot.total = s.total;
      State.liveSnapshot.unique_ips = s.unique_ips;
      State.liveSnapshot.error_rate = s.error_rate;
      State.liveSnapshot.threat_count = s.threat_count;
      State.liveSnapshot.top_ips = s.top_ips;
      State.liveSnapshot.hour_dist = s.hour_dist;
      State.liveSnapshot.status_dist = s.status_dist;
      State.liveSnapshot.sigma_stats = s.sigma_stats;
    }

    if (State.consoleMode === 'live') {
      const elTotal = document.getElementById('lv-total');
      if (elTotal) elTotal.textContent = s.total.toLocaleString();
      const mTotal = document.getElementById('m-total');
      if (mTotal) mTotal.textContent = s.total.toLocaleString();

      const elIps = document.getElementById('lv-ips');
      if (elIps) elIps.textContent = s.unique_ips;
      const mIps = document.getElementById('m-ips');
      if (mIps) mIps.textContent = s.unique_ips;

      const elErrs = document.getElementById('lv-errs');
      if (elErrs) elErrs.textContent = s.error_rate + '%';
      const mErrors = document.getElementById('m-errors');
      if (mErrors) mErrors.textContent = s.error_rate + '%';

      const elThreats = document.getElementById('lv-threats');
      if (elThreats) elThreats.textContent = s.threat_count;
      const mThreats = document.getElementById('m-threats');
      if (mThreats) mThreats.textContent = s.threat_count;
      
      if (s.top_ips) {
        buildTopIPs(s.top_ips);
      }
      
      updateLiveECharts(s);
      if (s.sigma_stats) {
        updateSigmaStatsUI(s.sigma_stats);
      }
    }
  });

  socket.on('modsec_threat', threat => {
    State.modsecThreats.unshift(threat);
    if (State.modsecThreats.length > 50) State.modsecThreats.pop();
    
    if (State.consoleMode === 'live') {
      prependModSecThreatCard(threat);
      const badge = document.getElementById('modsecThreatBadge');
      if (badge) badge.style.display = '';
      if (threat.severity === 'CRITICAL') {
        showModSecToast(threat);
      }
      activateMitreCell(threat.attack_type);
      plotThreatOnMap(threat.attacker_ip, threat.attack_type, threat.severity);
      loadThreatStats();
    }
  });

  socket.on('sigma_alert', alert => {
    State.sigmaAlerts.unshift(alert);
    if (State.sigmaAlerts.length > 100) State.sigmaAlerts.pop();
    
    if (State.consoleMode === 'live') {
      showSigmaToast(alert);
      prependSigmaAlertCard(alert);
      activateMitreCell(alert.category || alert.title);
      plotThreatOnMap(alert.attacker_ip, alert.title, alert.level);
      
      if (isActiveView('threats')) renderThreats();
      updateDashboardTrendsChart();
    }
  });

  socket.on('ip_blocked', data => {
    State.liveBlocked.add(data.ip);
    if (State.consoleMode === 'live' && isActiveView('blocking')) renderBlocking();
  });
} else {
  console.warn('[Socket] Socket.io client not loaded; real-time features disabled.');
}

// ── Helpers ───────────────────────────────────────────────
function setAgentPill(online, label) {
  const pill = document.getElementById('agentPill');
  if (pill) {
    pill.className = 'agent-pill ' + (online ? 'online' : 'offline');
  }
  const lbl = document.getElementById('agentLabel');
  if (lbl) {
    lbl.textContent = label;
  }
}

function applySnapshot(snap) {
  setAgentPill(snap.agent_connected, snap.agent_connected ? `Agent: ${snap.agent_name}` : 'Agent Offline');
  
  const elTotal = document.getElementById('lv-total');
  if (elTotal) elTotal.textContent = snap.total.toLocaleString();
  const mTotal = document.getElementById('m-total');
  if (mTotal) mTotal.textContent = snap.total.toLocaleString();

  const elIps = document.getElementById('lv-ips');
  if (elIps) elIps.textContent = snap.unique_ips;
  const mIps = document.getElementById('m-ips');
  if (mIps) mIps.textContent = snap.unique_ips;

  const elErrs = document.getElementById('lv-errs');
  if (elErrs) elErrs.textContent = snap.error_rate + '%';
  const mErrors = document.getElementById('m-errors');
  if (mErrors) mErrors.textContent = snap.error_rate + '%';

  const elThreats = document.getElementById('lv-threats');
  if (elThreats) elThreats.textContent = snap.threat_count;
  const mThreats = document.getElementById('m-threats');
  if (mThreats) mThreats.textContent = snap.threat_count;
  
  if (snap.top_ips) {
    buildTopIPs(snap.top_ips);
  }
  
  State.liveThreats = snap.threats || [];
  State.liveLogs    = snap.recent_logs || [];
  State.liveBlocked = new Set(snap.blocked_ips || []);
  State.liveCustody     = snap.custody || [];
  State.modsecThreats = snap.modsec_threats || [];
  State.sigmaAlerts   = snap.sigma_alerts || [];
  
  // Populate feeds
  rebuildFeed();
  rebuildAlertFeed();
  rebuildModSecThreatFeed();
  rebuildSigmaThreatFeed();
  
  const badge = document.getElementById('modsecThreatBadge');
  if (badge) {
    badge.style.display = State.modsecThreats.length > 0 ? '' : 'none';
  }
  
  const sigmaBadge = document.getElementById('sigmaThreatBadge');
  if (sigmaBadge) {
    sigmaBadge.style.display = State.sigmaAlerts.length > 0 ? '' : 'none';
  }
  
  updateThreatStatsUI(snap.threat_stats);
  updateSigmaStatsUI(snap.sigma_stats);
  updateLiveECharts({ hour_dist: snap.hour_dist, status_dist: snap.status_dist });
  
  // Populate MITRE matrix cells based on active threats
  syncMitreMatrixState();
  
  // Populate maps markers from existing threats
  syncMapThreatMarkers();
  
  if (isActiveView('threats'))   renderThreats();
  if (isActiveView('blocking'))  renderBlocking();
  if (isActiveView('integrity')) renderIntegrity();
}

function isActiveView(id) {
  return document.getElementById('view-' + id)?.classList.contains('active');
}

// ── Live Feed ─────────────────────────────────────────────
let feedInitialized = false;

function clearFeedPlaceholder() {
  if (!feedInitialized) {
    const feed = document.getElementById('liveFeed');
    if (feed) feed.innerHTML = '';
    const alert = document.getElementById('alertFeed');
    if (alert) alert.innerHTML = '';
    feedInitialized = true;
  }
}

function appendFeedLine(e) {
  clearFeedPlaceholder();
  const feed = document.getElementById('liveFeed');
  if (!feed) return;
  const sc = e.status;
  const cls = sc >= 500 ? 'fl-5xx' : sc >= 400 ? 'fl-4xx' : sc >= 300 ? 'fl-3xx' : 'fl-200';
  const isAttack = sc === 401 || sc === 403 || (e.url || '').includes('..') || (e.user_agent || '').toLowerCase().includes('nikto');
  const div = document.createElement('div');
  div.className = 'feed-line' + (isAttack ? ' highlight' : '');
  div.innerHTML =
    `<span class="fl-ip">${e.ip}</span> ` +
    `<span class="fl-method">${e.method}</span> ` +
    `<span class="fl-url">${e.url}</span> ` +
    `<span class="${cls}">${sc}</span>`;
  feed.appendChild(div);
  while (feed.children.length > 200) feed.removeChild(feed.firstChild);
  if (document.getElementById('autoScroll')?.checked) feed.scrollTop = feed.scrollHeight;
}

function rebuildFeed() {
  clearFeedPlaceholder();
  const feed = document.getElementById('liveFeed');
  if (feed) {
    feed.innerHTML = '';
    State.liveLogs.slice().reverse().forEach(appendFeedLine);
  }
}

function appendAlertItem(t) {
  clearFeedPlaceholder();
  const feed = document.getElementById('alertFeed');
  if (!feed) return;
  const sevCls = t.severity === 'critical' ? 'crit' : t.severity === 'high' ? 'high' : 'med';
  const div = document.createElement('div');
  div.className = `alert-item ${sevCls}`;
  div.innerHTML = `
    <div class="alert-item-title">
      <span>${t.type}</span>
      <span class="badge ${t.severity === 'critical' ? 'sev-critical' : t.severity === 'high' ? 'sev-high' : 'sev-medium'}">${t.severity.toUpperCase()}</span>
    </div>
    <div class="alert-item-detail">${t.detail}</div>
    <div style="display:flex; justify-content:space-between; align-items:center; margin-top:4px;" class="alert-item-time">
      <span style="font-family:var(--mono); color:var(--accent); font-weight:600;">${t.ip}</span>
      <span>${t.timestamp}</span>
    </div>`;
  feed.insertBefore(div, feed.firstChild);
  while (feed.children.length > 50) feed.removeChild(feed.lastChild);
}

function rebuildAlertFeed() {
  const feed = document.getElementById('alertFeed');
  if (feed) {
    feed.innerHTML = '';
    feedInitialized = true;
    State.liveThreats.forEach(appendAlertItem);
    if (!State.liveThreats.length) {
      feed.innerHTML = '<div class="feed-placeholder">No alarms logged</div>';
    }
  }
}

function prependModSecThreatCard(t) {
  const feed = document.getElementById('modsecThreatFeed');
  if (!feed) return;
  
  const placeholder = feed.querySelector('.feed-placeholder');
  if (placeholder) {
    feed.innerHTML = '';
  }
  
  const sev = (t.severity || 'NOTICE').toUpperCase();
  let badgeClass = 'badge-notice';
  let alertClass = 'notice';
  
  if (sev === 'CRITICAL') {
    badgeClass = 'badge-critical';
    alertClass = 'critical';
  } else if (sev === 'ERROR') {
    badgeClass = 'badge-error';
    alertClass = 'error';
  } else if (sev === 'WARNING') {
    badgeClass = 'badge-warning';
    alertClass = 'warning';
  }
  
  const div = document.createElement('div');
  div.className = `alert-item ${alertClass}`;
  div.style.padding = '12px';
  div.style.marginBottom = '8px';
  div.style.borderRadius = '8px';
  
  div.innerHTML = `
    <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 6px;">
      <span style="font-weight: 600; font-size: 13px; color: var(--text);">${t.attack_type}</span>
      <span class="badge ${badgeClass}" style="font-size: 10px; font-weight: 600;">${sev}</span>
    </div>
    <div style="font-size: 12px; color: var(--text2); margin-bottom: 6px; font-family: var(--mono);">
      IP: <span style="color: var(--danger);">${t.attacker_ip}</span>
    </div>
    <div style="font-size: 11px; color: var(--text3); line-height: 1.4; margin-bottom: 6px;">
      <strong>Rule ${t.rule_id}</strong>: ${t.message}
    </div>
    <div style="font-size: 10px; color: var(--text3); text-align: right;">
      ${t.timestamp}
    </div>
  `;
  
  feed.insertBefore(div, feed.firstChild);
  
  while (feed.children.length > 50) {
    feed.removeChild(feed.lastChild);
  }
}

function rebuildModSecThreatFeed() {
  const feed = document.getElementById('modsecThreatFeed');
  if (!feed) return;
  feed.innerHTML = '';
  if (!State.modsecThreats || State.modsecThreats.length === 0) {
    feed.innerHTML = '<div class="feed-placeholder">Awaiting WAF payload blocks...</div>';
    return;
  }
  State.modsecThreats.forEach(prependModSecThreatCard);
}

function showModSecToast(t) {
  const container = document.getElementById('toastContainer');
  if (!container) return;
  const el = document.createElement('div');
  el.className = `toast crit`;
  el.innerHTML = `
    <div class="toast-title" style="color: var(--danger); font-weight: 700;">⚠️ CRITICAL THREAT DETECTED</div>
    <div class="toast-body" style="font-family: var(--mono); margin-top: 4px;">
      ${t.attack_type} — ${t.attacker_ip}<br>
      Rule ${t.rule_id}
    </div>`;
  container.appendChild(el);
  setTimeout(() => el.remove(), 5000);
}

async function loadThreatStats() {
  try {
    const res = await fetch('/api/threats/stats');
    const data = await res.json();
    updateThreatStatsUI(data);
  } catch (e) {
    console.error("Failed to load threat stats:", e);
  }
}

function updateThreatStatsUI(stats) {
  if (!stats) return;
  const total = stats.total || 0;
  const sqli = stats.by_type?.SQLi || 0;
  const xss = stats.by_type?.XSS || 0;
  const rce = stats.by_type?.RCE || 0;
  const other = stats.by_type?.Other || 0;
  
  const elTotal = document.getElementById('stat-total');
  if (elTotal) elTotal.textContent = total;
  const elSqli = document.getElementById('stat-sqli');
  if (elSqli) elSqli.textContent = sqli;
  const elXss = document.getElementById('stat-xss');
  if (elXss) elXss.textContent = xss;
  const elRce = document.getElementById('stat-rce');
  if (elRce) elRce.textContent = rce;
  const elOther = document.getElementById('stat-other');
  if (elOther) elOther.textContent = other;

  const elDashTotal = document.getElementById('dash-stat-total');
  if (elDashTotal) elDashTotal.textContent = total;
  const elDashSqli = document.getElementById('dash-stat-sqli');
  if (elDashSqli) elDashSqli.textContent = sqli;
  const elDashXss = document.getElementById('dash-stat-xss');
  if (elDashXss) elDashXss.textContent = xss;
  const elDashRce = document.getElementById('dash-stat-rce');
  if (elDashRce) elDashRce.textContent = rce;
  const elDashOther = document.getElementById('dash-stat-other');
  if (elDashOther) elDashOther.textContent = other;
  
  // Update HUD threat status based on severity or totals
  const hudLvl = document.getElementById('hudThreatLevel');
  if (hudLvl) {
    if (total === 0) {
      hudLvl.textContent = 'NORMAL';
      hudLvl.style.color = 'var(--accent3)';
    } else if (total < 5) {
      hudLvl.textContent = 'ELEVATED';
      hudLvl.style.color = 'var(--warn)';
    } else {
      hudLvl.textContent = 'CRITICAL';
      hudLvl.style.color = 'var(--danger)';
    }
  }
}

// ── Toast ────────────────────────────────────────────────
function showToast(t) {
  const container = document.getElementById('toastContainer');
  if (!container) return;
  const sevCls = t.severity === 'critical' ? 'crit' : t.severity === 'high' ? 'high' : 'med';
  const el = document.createElement('div');
  el.className = `toast ${sevCls}`;
  el.innerHTML = `
    <div class="toast-title">⚠ ${t.type}</div>
    <div class="toast-body">${t.ip} — ${t.detail.slice(0, 60)}</div>`;
  container.appendChild(el);
  setTimeout(() => el.remove(), 5000);
}

// ── Reset session ────────────────────────────────────────
async function resetSession() {
  if (!confirm('Reset all live data? This clears the current session and database logs.')) return;
  await fetch('/api/realtime/reset', { method: 'POST' });
  State.liveThreats = []; 
  State.liveLogs = []; 
  State.liveBlocked = new Set(); 
  State.modsecThreats = [];
  State.sigmaAlerts = [];
  feedInitialized = false;
  
  const liveFeed = document.getElementById('liveFeed');
  if (liveFeed) liveFeed.innerHTML = '<div class="feed-placeholder">Session reset. Waiting for agent...</div>';
  const alertFeed = document.getElementById('alertFeed');
  if (alertFeed) alertFeed.innerHTML = '<div class="feed-placeholder">No alarms logged</div>';
  const modsecFeed = document.getElementById('modsecThreatFeed');
  if (modsecFeed) modsecFeed.innerHTML = '<div class="feed-placeholder">Awaiting WAF payload blocks...</div>';
  const sigmaFeed = document.getElementById('sigmaThreatFeed');
  if (sigmaFeed) sigmaFeed.innerHTML = '<div class="feed-placeholder">Awaiting Sigma pattern detections...</div>';
  
  document.getElementById('threatBadge').style.display = 'none';
  const modsecBadge = document.getElementById('modsecThreatBadge');
  if (modsecBadge) modsecBadge.style.display = 'none';
  const sigmaBadge = document.getElementById('sigmaThreatBadge');
  if (sigmaBadge) sigmaBadge.style.display = 'none';
  
  // Clear map overlays
  clearMapThreats();
  
  // Reset MITRE grid highlights
  document.querySelectorAll('.mitre-cell').forEach(cell => cell.classList.remove('active-technique'));
  
  // Reset Executive metrics to zero
  ['m-total', 'm-threats', 'm-ips', 'm-errors', 'm-sigma-alerts', 'm-sigma-critical'].forEach(id => {
    const el = document.getElementById(id);
    if (el) el.textContent = id.endsWith('errors') ? '0%' : '0';
  });
  
  // Reset Live view metrics to zero
  ['lv-total', 'lv-threats', 'lv-ips', 'lv-errs'].forEach(id => {
    const el = document.getElementById(id);
    if (el) el.textContent = id.endsWith('errs') ? '0%' : '0';
  });
  
  // Reset checklist items to PENDING
  const checklistItems = [
    'sqli', 'sqli_blind', 'xss_reflected', 'xss_stored', 'xss_dom',
    'csrf', 'cmd', 'upload', 'traversal', 'captcha', 'weak_id',
    'csp', 'javascript', 'auth_bypass', 'redirect', 'crypto', 'api', 'brute'
  ];
  checklistItems.forEach(item => {
    const el = document.getElementById('chk-' + item);
    if (el) {
      el.textContent = 'PENDING';
      el.className = 'badge sev-crit';
    }
  });
  
  updateThreatStatsUI({
    total: 0,
    by_type: { SQLi: 0, XSS: 0, RCE: 0, Other: 0 }
  });
  updateSigmaStatsUI({
    total: 0,
    by_level: { critical: 0, high: 0, medium: 0, low: 0 },
    by_category: {},
    by_rule: {}
  });
  
  // Force update ECharts gauges to zero
  updateLiveECharts({ hour_dist: {}, status_dist: {} });
  updateDashboardTrendsChart();
  
  // Update Cyber Range tab checklist if active
  if (isActiveView('testlab')) {
    pollTestLabStatus();
  }
}

// ── Cmd tabs ─────────────────────────────────────────────
function showCmd(i, el) {
  [0, 1, 2].forEach(j => {
    const box = document.getElementById('cmd' + j);
    if (box) box.style.display = j === i ? '' : 'none';
  });
  document.querySelectorAll('.cmd-tab').forEach((t, j) => t.classList.toggle('active', j === i));
}

// ══════════════════════════════════════════════════════════
//  NAVIGATION
// ══════════════════════════════════════════════════════════
function switchView(id, el) {
  document.querySelectorAll('.view').forEach(v => v.classList.remove('active'));
  const targetView = document.getElementById('view-' + id);
  if (targetView) targetView.classList.add('active');
  
  document.querySelectorAll('.nav-item').forEach(n => n.classList.remove('active'));
  if (el) el.classList.add('active');
  
  if (id === 'threats')   renderThreats();
  if (id === 'logs')      applyLogFilters();
  if (id === 'timeline')  renderTimeline();
  if (id === 'integrity') renderIntegrity();
  if (id === 'blocking')  renderBlocking();
  if (id === 'report')    renderReport();
  if (id === 'testlab')   pollTestLabStatus();
  if (id === 'dashboard') {
    // Redraw ECharts on visibility changes to solve grid layouts offset issue
    setTimeout(() => {
      if (State.charts.dashRadar) State.charts.dashRadar.resize();
      if (State.charts.dashLine) State.charts.dashLine.resize();
      if (State.map) State.map.invalidateSize();
    }, 100);
  }
}

// ══════════════════════════════════════════════════════════
//  UPLOAD (static baselines)
// ══════════════════════════════════════════════════════════
const uploadZone = document.getElementById('uploadZone');
const fileInput  = document.getElementById('fileInput');
const analyzeBtn = document.getElementById('analyzeBtn');
let selectedFiles = [];

if (uploadZone) {
  uploadZone.addEventListener('dragover', e => { e.preventDefault(); uploadZone.classList.add('drag-over') });
  uploadZone.addEventListener('dragleave', () => uploadZone.classList.remove('drag-over'));
  uploadZone.addEventListener('drop', e => { e.preventDefault(); uploadZone.classList.remove('drag-over'); if (e.dataTransfer.files.length) handleFiles(e.dataTransfer.files) });
  fileInput.addEventListener('change', e => handleFiles(e.target.files));
  uploadZone.addEventListener('click', () => fileInput.click());
}

function handleFiles(files) {
  selectedFiles = Array.from(files);
  const fl = document.getElementById('fileList');
  if (fl) {
    fl.innerHTML = selectedFiles.map(f => `<div class="file-item"><span class="mono" style="font-size:12px">${f.name}</span><span class="text-xs text-muted">${(f.size / 1024).toFixed(1)} KB</span></div>`).join('');
  }
  if (analyzeBtn) analyzeBtn.disabled = false;
}

async function startUpload() {
  if (!selectedFiles.length) return;
  const analyst = document.getElementById('analystInput').value.trim() || 'Analyst';
  const fd = new FormData(); 
  fd.append('file', selectedFiles[0]); 
  fd.append('analyst', analyst);
  showProgress(); 
  fakeProgress();
  try {
    const res = await fetch('/api/upload', { method: 'POST', body: fd });
    const data = await res.json();
    if (data.error) { alert('Error: ' + data.error); hideProgress(); return; }
    applyBatchData(data); 
    hideProgress();
  } catch (e) { 
    console.error('Upload failed details:', e);
    alert('Upload failed: ' + e.message); 
    hideProgress(); 
  }
}

function applyBatchData(data) {
  State.analysisId = data.analysis_id || null;
  State.forensicSummary = data.summary; 
  State.forensicThreats = data.threats || [];
  State.forensicCustody = data.custody || []; 
  State.fileHash = data.file_hash || '';
  State.filename = data.filename || '';
  State.forensicLogs = data.logs_sample || []; 
  State.logPage = 0; 
  State.forensicBlocked = new Set();
  
  // Toggle views
  document.getElementById('upload-form-container').style.display = 'none';
  document.getElementById('upload-results-container').style.display = 'block';
  
  // Populate forensic meta info
  document.getElementById('forensic-filename').textContent = 'Forensic Report: ' + State.filename;
  document.getElementById('forensic-hash-label').textContent = 'SHA-256: ' + State.fileHash;
  document.getElementById('forensicFilenameText').textContent = State.filename;
  document.getElementById('forensicHashDisplay').textContent = State.fileHash;
  
  // Reset filter inputs
  document.getElementById('forensicLogSearch').value = '';
  document.getElementById('forensicStatusFilter').value = 'all';
  document.getElementById('forensicMethodFilter').value = 'all';
  
  // Switch to forensic overview tab
  switchForensicSubTab('dashboard');
  
  // Clear files list
  document.getElementById('fileList').innerHTML = '';
  selectedFiles = [];
  document.getElementById('analyzeBtn').disabled = true;
}

function goDashboard() {
  document.querySelectorAll('.view').forEach(v => v.classList.remove('active'));
  document.getElementById('view-dashboard').classList.add('active');
  document.querySelectorAll('.nav-item').forEach((n, i) => { 
    n.classList.remove('active'); 
    if (i === 0) n.classList.add('active'); // Executive Overview dashboard index
  });
  renderDashboard();
}

let _progressInterval = null;
function showProgress() { 
  document.getElementById('progressCard').style.display = 'block'; 
  if (document.getElementById('fileList')) document.getElementById('fileList').style.display = 'none'; 
  if (analyzeBtn) analyzeBtn.disabled = true; 
}
function hideProgress() { document.getElementById('progressCard').style.display = 'none'; }
function fakeProgress() {
  const steps = [
    [12, 'Computing SHA-256 baseline hash...', 't-blue'],
    [24, 'Recording chain of custody log...', 't-green'],
    [40, 'Parsing server combined log signatures...', 't-blue'],
    [55, 'Normalizing header profiles...', 't-blue'],
    [68, 'Running sliding-window heuristic engines...', 't-warn'],
    [78, 'WAF / CSS triggers mapped!', 't-red'],
    [88, 'Drawing chronological timeline metrics...', 't-blue'],
    [95, 'Compiling interactive overlays...', 't-blue'],
    [100, 'Ingest Complete!', 't-green']
  ];
  const fill = document.getElementById('progressFill');
  const pct = document.getElementById('progressPct');
  const term = document.getElementById('terminalLog');
  let i = 0;
  if (term) term.innerHTML = '';
  _progressInterval = setInterval(() => {
    if (i >= steps.length) { clearInterval(_progressInterval); return; }
    const [p, msg, cls] = steps[i++];
    if (fill) fill.style.width = p + '%';
    if (pct) pct.textContent = p + '%';
    const now = new Date(), ts = `${now.getHours().toString().padStart(2, '0')}:${now.getMinutes().toString().padStart(2, '0')}:${now.getSeconds().toString().padStart(2, '0')}`;
    if (term) {
      term.innerHTML += `<div class="t-line"><span class="t-gray">[${ts}]</span> <span class="${cls}">${msg}</span></div>`;
      term.scrollTop = term.scrollHeight;
    }
  }, 380);
}

// ══════════════════════════════════════════════════════════
//  DASHBOARD (Forensic Overview)
// ══════════════════════════════════════════════════════════
function renderDashboard() {
  const snap = State.liveSnapshot;
  if (!snap) return;
  document.getElementById('m-total').textContent  = snap.total.toLocaleString();
  document.getElementById('m-threats').textContent = snap.threat_count;
  document.getElementById('m-ips').textContent     = snap.unique_ips;
  document.getElementById('m-errors').textContent  = snap.error_rate + '%';
  
  buildTopIPs(snap.top_ips);
  initDashboardECharts();
}

function buildTopIPs(topIps) {
  const ips = topIps || (State.consoleMode === 'forensic' ? State.forensicSummary?.top_ips : State.liveSnapshot?.top_ips) || {};
  const sorted = Object.entries(ips).sort((a, b) => b[1] - a[1]).slice(0, 7);
  const max = sorted[0]?.[1] || 1;
  const mal = new Set((State.consoleMode === 'forensic' ? State.forensicThreats : State.liveThreats).map(t => t.ip));
  
  const container = document.getElementById('topIPs');
  if (container) {
    container.innerHTML = sorted.map(([ip, cnt]) => `
      <div style="margin-bottom:12px">
        <div style="display:flex; justify-content:space-between; margin-bottom:5px">
          <span style="font-family:var(--mono); font-size:12px; font-weight:500; color:${mal.has(ip) ? 'var(--danger)' : 'var(--text)'}">${ip}</span>
          <span style="font-size:11px; color:var(--text3)">${cnt.toLocaleString()} req ${mal.has(ip) ? '<span class="badge sev-crit" style="font-size:8px; padding:1px 4px; margin-left:6px;">THREAT</span>' : ''}</span>
        </div>
        <div class="progress-bar" style="margin:0; height:5px"><div class="progress-fill" style="width:${Math.round(cnt / max * 100)}%; background:${mal.has(ip) ? 'var(--danger)' : 'var(--accent)'}"></div></div>
      </div>`).join('');
  }
}

// ══════════════════════════════════════════════════════════
//  APACHE ECHARTS VISUALIZATION LAYER
// ══════════════════════════════════════════════════════════

// 1. Interactive WAF Gauge / Live Hour Stream (Live View)
function updateLiveECharts(s) {
  if (typeof echarts === 'undefined') {
    console.warn('ECharts library not loaded. live chart visualization disabled.');
    return;
  }
  const hourDist   = s.hour_dist   || {};
  const statusDist = s.status_dist || {};
  
  // 1. Hourly Access rates bar
  const hourDom = document.getElementById('liveEChartsHour');
  if (hourDom) {
    try {
      if (!State.charts.liveHour) {
        State.charts.liveHour = echarts.init(hourDom, 'dark', { backgroundColor: 'transparent' });
      }
      const hours = Object.keys(hourDist).map(h => h + ':00');
      const counts = Object.values(hourDist);
      
      State.charts.liveHour.setOption({
        tooltip: { trigger: 'axis', axisPointer: { type: 'shadow' } },
        grid: { left: '3%', right: '4%', bottom: '3%', top: '10%', containLabel: true },
        xAxis: [{ type: 'category', data: hours, axisTick: { alignWithLabel: true }, axisLabel: { color: '#94a3b8', fontSize: 10 } }],
        yAxis: [{ type: 'value', axisLabel: { color: '#94a3b8', fontSize: 10 }, splitLine: { lineStyle: { color: 'rgba(255, 255, 255, 0.05)' } } }],
        series: [{
          name: 'Ingested Requests',
          type: 'bar',
          barWidth: '60%',
          data: counts,
          itemStyle: {
            color: new echarts.graphic.LinearGradient(0, 0, 0, 1, [
              { offset: 0, color: '#00f0ff' },
              { offset: 1, color: '#3b82f6' }
            ])
          }
        }]
      });
    } catch (e) {
      console.error('Failed to update live hourly ECharts:', e);
    }
  }

  // 2. Status Doughnut Chart
  const statusDom = document.getElementById('liveEChartsStatus');
  if (statusDom) {
    try {
      if (!State.charts.liveStatus) {
        State.charts.liveStatus = echarts.init(statusDom, 'dark', { backgroundColor: 'transparent' });
      }
      const groups = { '2xx OK': 0, '3xx Redirect': 0, '4xx Client Err': 0, '5xx Server Err': 0 };
      Object.entries(statusDist).forEach(([k, v]) => {
        if (k.startsWith('2')) groups['2xx OK'] += v;
        else if (k.startsWith('3')) groups['3xx Redirect'] += v;
        else if (k.startsWith('4')) groups['4xx Client Err'] += v;
        else if (k.startsWith('5')) groups['5xx Server Err'] += v;
      });
      
      const chartData = Object.entries(groups).map(([name, value]) => ({ name, value })).filter(item => item.value > 0);
      
      State.charts.liveStatus.setOption({
        tooltip: { trigger: 'item' },
        legend: { bottom: '0', left: 'center', textStyle: { color: '#94a3b8', fontSize: 10 }, itemWidth: 10, itemHeight: 10 },
        series: [{
          name: 'HTTP Profile',
          type: 'pie',
          radius: ['45%', '70%'],
          avoidLabelOverlap: false,
          itemStyle: { borderRadius: 4 },
          label: { show: false },
          emphasis: { label: { show: false } },
          color: ['#10b981', '#3b82f6', '#f59e0b', '#f43f5e'],
          data: chartData
        }]
      });
    } catch (e) {
      console.error('Failed to update live status ECharts:', e);
    }
  }
}

// 2. Dashboard Advanced Charts (Executive Radar + Historical Trends)
function initDashboardECharts() {
  if (typeof echarts === 'undefined') {
    console.warn('ECharts library not loaded. initDashboardECharts disabled.');
    return;
  }
  // Line chart - traffic trend lines
  const lineDom = document.getElementById('dashLineChart');
  const summary = State.liveSnapshot;
  if (lineDom && summary) {
    try {
      if (!State.charts.dashLine) {
        State.charts.dashLine = echarts.init(lineDom, 'dark', { backgroundColor: 'transparent' });
      }
      const h = summary.hourly_traffic || summary.hour_dist || {};
      const labels = Object.keys(h).map(k => k + ':00');
      const counts = Object.values(h);
      
      State.charts.dashLine.setOption({
        tooltip: { trigger: 'axis' },
        grid: { left: '3%', right: '4%', bottom: '3%', top: '10%', containLabel: true },
        xAxis: { type: 'category', boundaryGap: false, data: labels, axisLabel: { color: '#94a3b8', fontSize: 10 } },
        yAxis: { type: 'value', axisLabel: { color: '#94a3b8', fontSize: 10 }, splitLine: { lineStyle: { color: 'rgba(255, 255, 255, 0.05)' } } },
        series: [{
          name: 'Traffic Rate',
          type: 'line',
          smooth: true,
          data: counts,
          symbolSize: 6,
          showSymbol: false,
          lineStyle: { color: '#00f0ff', width: 2 },
          itemStyle: { color: '#00f0ff' },
          areaStyle: {
            color: new echarts.graphic.LinearGradient(0, 0, 0, 1, [
              { offset: 0, color: 'rgba(0, 240, 255, 0.2)' },
              { offset: 1, color: 'rgba(0, 240, 255, 0)' }
            ])
          }
        }]
      });
    } catch (e) {
      console.error('Failed to initialize dashboard line ECharts:', e);
    }
  }
  
  updateDashboardTrendsChart();
}

// Update radar/trend counts based on live ingested threats
function updateDashboardTrendsChart() {
  if (typeof echarts === 'undefined') return;
  const radarDom = document.getElementById('dashRadarChart');
  if (!radarDom) return;
  
  try {
    if (!State.charts.dashRadar) {
      State.charts.dashRadar = echarts.init(radarDom, 'dark', { backgroundColor: 'transparent' });
    }
    
    // Dynamic categories calculation
    const counts = { SQLi: 0, XSS: 0, RCE: 0, LFI: 0, BruteForce: 0, Scanning: 0 };
    const allThreats = State.liveThreats;
    
    allThreats.forEach(t => {
      const type = (t.type || '').toLowerCase();
      if (type.includes('sqli') || type.includes('sql')) counts.SQLi++;
      else if (type.includes('xss') || type.includes('cross-site')) counts.XSS++;
      else if (type.includes('rce') || type.includes('command')) counts.RCE++;
      else if (type.includes('lfi') || type.includes('traversal')) counts.LFI++;
      else if (type.includes('brute') || type.includes('auth')) counts.BruteForce++;
      else if (type.includes('scan') || type.includes('recon')) counts.Scanning++;
    });
    
    const dataMax = Math.max(...Object.values(counts), 5) * 1.2;
    
    State.charts.dashRadar.setOption({
      tooltip: { trigger: 'item' },
      radar: {
        indicator: [
          { name: 'SQL Injection', max: dataMax },
          { name: 'XSS Reflected', max: dataMax },
          { name: 'RCE / Commands', max: dataMax },
          { name: 'Path Traversal / LFI', max: dataMax },
          { name: 'Brute Force Attempts', max: dataMax },
          { name: 'Scanning & Recon', max: dataMax }
        ],
        shape: 'polygon',
        axisName: { color: '#94a3b8', fontSize: 10 },
        splitArea: { show: false },
        splitLine: { lineStyle: { color: 'rgba(255, 255, 255, 0.05)' } },
        axisLine: { lineStyle: { color: 'rgba(255, 255, 255, 0.05)' } }
      },
      series: [{
        name: 'Incident Vectors',
        type: 'radar',
        data: [{
          value: [counts.SQLi, counts.XSS, counts.RCE, counts.LFI, counts.BruteForce, counts.Scanning],
          name: 'Alert Density',
          areaStyle: { color: 'rgba(244, 63, 94, 0.2)' },
          lineStyle: { color: '#f43f5e', width: 2 },
          itemStyle: { color: '#f43f5e' }
        }]
      }]
    });
  } catch (e) {
    console.error('Failed to update dashboard trends radar ECharts:', e);
  }
}


// ══════════════════════════════════════════════════════════
//  MITRE ATT&CK MATRIX INTEGRATION
// ══════════════════════════════════════════════════════════
function activateMitreCell(threatType) {
  const type = (threatType || '').toLowerCase();
  let targetId = '';
  
  if (type.includes('sqli') || type.includes('sql injection')) {
    targetId = 'mitre-sqli';
  } else if (type.includes('csrf') || type.includes('forgery')) {
    targetId = 'mitre-csrf';
  } else if (type.includes('csp') || type.includes('content security')) {
    targetId = 'mitre-csp';
  } else if (type.includes('session') || type.includes('weak_id') || type.includes('fixation')) {
    targetId = 'mitre-session';
  } else if (type.includes('crypto') || type.includes('cryptography')) {
    targetId = 'mitre-crypto';
  } else if (type.includes('api')) {
    targetId = 'mitre-api';
  } else if (type.includes('redirect')) {
    targetId = 'mitre-redirect';
  } else if (type.includes('javascript') || type.includes('js attack') || type.includes('pollution')) {
    targetId = 'mitre-javascript';
  } else if (type.includes('xss') || type.includes('cross-site')) {
    targetId = 'mitre-xss';
  } else if (type.includes('rce') || type.includes('command injection') || type.includes('command')) {
    targetId = 'mitre-rce';
  } else if (type.includes('lfi') || type.includes('directory traversal') || type.includes('inclusion') || type.includes('traversal')) {
    targetId = 'mitre-traversal';
  } else if (type.includes('brute') || type.includes('auth')) {
    if (type.includes('bypass') || type.includes('authorisation') || type.includes('authorization')) {
      targetId = 'mitre-sqli';
    } else {
      targetId = 'mitre-brute';
    }
  } else if (type.includes('scan') || type.includes('recon') || type.includes('vulnerability scanner')) {
    targetId = 'mitre-recon';
  } else if (type.includes('upload') || type.includes('webshell') || type.includes('file upload')) {
    targetId = 'mitre-upload';
  } else if (type.includes('php')) {
    targetId = 'mitre-php';
  }
  
  if (targetId) {
    const el = document.getElementById(targetId);
    if (el) {
      el.classList.add('active-technique');
    }
  }
}

function syncMitreMatrixState() {
  document.querySelectorAll('.mitre-cell').forEach(cell => cell.classList.remove('active-technique'));
  
  // Highlight technique cells based on snapshot data
  const allThreats = State.consoleMode === 'forensic' ? State.forensicThreats : State.liveThreats;
  allThreats.forEach(t => {
    activateMitreCell(t.type);
  });
  
  // Also loop through ModSec threats
  if (State.consoleMode === 'live') {
    State.modsecThreats.forEach(m => {
      activateMitreCell(m.attack_type);
    });
  }
}

// ══════════════════════════════════════════════════════════
//  LEAFLET.JS WORLD ATTACK MAP
// ══════════════════════════════════════════════════════════
function initLeafletMap() {
  const mapDom = document.getElementById('map');
  if (!mapDom || State.map) return;
  
  if (typeof L === 'undefined') {
    console.warn('Leaflet mapping library not loaded. Map visualization disabled.');
    mapDom.innerHTML = '<div style="display: flex; align-items: center; justify-content: center; height: 100%; color: var(--text3); font-size: 13px;">Leaflet Map library not loaded. Offline demo mode active.</div>';
    return;
  }
  
  try {
    // Initialize Leaflet Map centered on global view
    State.map = L.map('map', {
      zoomControl: true,
      minZoom: 1.5,
      maxZoom: 8
    }).setView([20.0, 0.0], 1.5);
    
    // Load CartoDB Dark Matter tile layer for cyberpunk aesthetic
    L.tileLayer('https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png', {
      attribution: '&copy; CartoDB',
      subdomains: 'abcd'
    }).addTo(State.map);
  } catch (e) {
    console.error('Failed to initialize Leaflet Map:', e);
  }
}

// Simple IP Hashing to deterministic Lat/Lon coordinates so all IPs geolocate beautifully
function geolocateIP(ip) {
  if (!ip) return [0, 0];
  // Pre-seed some static coordinates for known subnets or ranges for realistic demonstrations
  const fixedIPs = {
    '192.168.0.10': [34.0522, -118.2437], // Los Angeles, USA
    '192.168.0.22': [52.5200, 13.4050],  // Berlin, Germany
    '172.20.126.109': [39.9042, 116.4074] // Beijing, China
  };
  
  if (fixedIPs[ip]) return fixedIPs[ip];
  
  // Pseudo-random hashing based on IP string
  let hash = 0;
  for (let i = 0; i < ip.length; i++) {
    hash = ip.charCodeAt(i) + ((hash << 5) - hash);
  }
  
  // Bound Latitude to [-50, 65] (inhabited zones) and Longitude to [-150, 140]
  const lat = ((hash % 115) - 50) + (Math.abs(hash % 100) / 100);
  const lon = (((hash * 3) % 290) - 150) + (Math.abs(hash * 7 % 100) / 100);
  return [lat, lon];
}

function plotThreatOnMap(ip, attackType, severity) {
  if (typeof L === 'undefined' || !State.map) return;
  if (!ip) return;
  
  try {
    const origin = geolocateIP(ip);
    const sev = (severity || 'notice').toLowerCase();
    const color = sev === 'critical' ? 'var(--danger)' : sev === 'high' ? 'var(--warn)' : 'var(--accent2)';
    
    // 1. Create a pulsing CSS-based marker circle at origin coordinates
    const pulseIcon = L.divIcon({
      className: 'leaflet-pulse-icon',
      html: `<span class="pulse-marker" style="background: ${color}; box-shadow: 0 0 12px ${color};"></span>`,
      iconSize: [12, 12]
    });
    
    const marker = L.marker(origin, { icon: pulseIcon }).addTo(State.map);
    marker.bindPopup(`<b>WAF Threat Dispatch</b><br>IP: ${ip}<br>Tactic: ${attackType}<br>Severity: ${sev.toUpperCase()}`);
    State.mapMarkers.push(marker);
    
    // 2. Draw curved attack vector line towards centered Server D.C. coordinates
    // Leaflet polyline
    const curve = L.polyline([origin, SERVER_LAT_LON], {
      color: color,
      weight: 1.5,
      opacity: 0.65,
      dashArray: '4, 4',
      dashSpeed: 20
    }).addTo(State.map);
    State.mapLines.push(curve);
    
    // Pan view slightly towards threat origin on critical events
    if (sev === 'critical') {
      State.map.panTo(origin);
    }
    
    // Keep map clean by popping oldest overlays if exceeding 40 elements
    if (State.mapMarkers.length > 40) {
      const oldMarker = State.mapMarkers.shift();
      State.map.removeLayer(oldMarker);
      const oldLine = State.mapLines.shift();
      State.map.removeLayer(oldLine);
    }
  } catch (e) {
    console.error('Failed to plot threat on map:', e);
  }
}

function clearMapThreats() {
  if (typeof L === 'undefined' || !State.map) return;
  State.mapMarkers.forEach(m => {
    try { State.map.removeLayer(m); } catch (e) {}
  });
  State.mapLines.forEach(l => {
    try { State.map.removeLayer(l); } catch (e) {}
  });
  State.mapMarkers = [];
  State.mapLines = [];
}

function syncMapThreatMarkers() {
  if (typeof L === 'undefined' || !State.map) return;
  clearMapThreats();
  
  // Loop through recent alarms and display them on Leaflet World Map
  const allThreats = State.liveThreats.slice(0, 30);
  allThreats.forEach(t => {
    plotThreatOnMap(t.ip, t.type, t.severity);
  });
  
  State.modsecThreats.slice(0, 30).forEach(m => {
    plotThreatOnMap(m.attacker_ip, m.attack_type, m.severity);
  });
}

// ══════════════════════════════════════════════════════════
//  THREATS (Correlated Console)
// ══════════════════════════════════════════════════════════
function renderThreats() {
  const allThreats = [...State.liveThreats];
  const sf = document.getElementById('threatSevFilter').value;
  const tf = document.getElementById('threatTypeFilter').value;
  
  let list = allThreats;
  if (sf !== 'all') list = list.filter(t => (t.severity || '').toLowerCase() === sf.toLowerCase());
  if (tf !== 'all') {
    list = list.filter(t => {
      const type = (t.type || '').toLowerCase();
      const filter = tf.toLowerCase();
      if (filter === 'sqli') return type.includes('sqli') || type.includes('sql');
      if (filter === 'xss') return type.includes('xss') || type.includes('cross-site');
      if (filter === 'rce') return type.includes('rce') || type.includes('command');
      return type === filter;
    });
  }
  
  const sc = { critical: 'sev-critical', high: 'sev-high', medium: 'sev-medium', low: 'sev-low' };
  const targetDom = document.getElementById('threatBody');
  if (targetDom) {
    targetDom.innerHTML = list.length
      ? list.map(t => `
          <tr>
            <td style="font-size:11px">${(t.timestamp || '').slice(11, 19) || '—'}</td>
            <td style="font-weight:600; color:var(--text);">${t.type}</td>
            <td><span class="badge ${sc[(t.severity || '').toLowerCase()] || 'sev-low'}">${(t.severity || '').toUpperCase()}</span></td>
            <td style="color:var(--danger); font-family:var(--mono); font-size:12px">${t.ip}</td>
            <td style="color:var(--text2); font-size:12.5px; font-family:var(--font)">${t.detail}</td>
            <td style="font-family:var(--mono); font-weight:700;">${t.count || '1'}</td>
          </tr>`).join('')
      : '<tr><td colspan="6" style="text-align:center; color:var(--text3); padding:24px">No alerts match filter selections</td></tr>';
  }
}

// ══════════════════════════════════════════════════════════
//  SIEM LOG EXPLORER
// ══════════════════════════════════════════════════════════
function applyLogFilters() {
  const search = (document.getElementById('logSearch').value || '').toLowerCase();
  const sf = document.getElementById('statusFilter').value;
  const mf = document.getElementById('methodFilter').value;
  
  let logs = (State.consoleMode === 'forensic' ? State.forensicLogs : State.liveLogs).slice();
  if (search) {
    logs = logs.filter(l => (l.ip || '').includes(search) || (l.url || '').toLowerCase().includes(search) || (l.method || '').toLowerCase().includes(search));
  }
  if (sf !== 'all') {
    logs = logs.filter(l => String(l.status || '').startsWith(sf[0]));
  }
  if (mf !== 'all') {
    logs = logs.filter(l => l.method === mf);
  }
  State.filteredLogs = logs; 
  State.logPage = 0; 
  renderLogsPage();
}

function renderLogsPage() {
  const { filteredLogs, logPage, PAGE_SIZE } = State;
  const total = filteredLogs.length; 
  const pages = Math.max(1, Math.ceil(total / PAGE_SIZE));
  const page = Math.min(Math.max(0, logPage), pages - 1); 
  State.logPage = page;
  
  const slice = filteredLogs.slice(page * PAGE_SIZE, (page + 1) * PAGE_SIZE);
  const sc = s => {
    if (s >= 500) return 'status-5xx';
    if (s >= 400) return 'status-4xx';
    if (s >= 300) return 'status-3xx';
    return 'status-2xx';
  };
  
  const targetDom = document.getElementById('logBody');
  if (targetDom) {
    targetDom.innerHTML = slice.length 
      ? slice.map(l => `
          <tr>
            <td style="font-size:11px; white-space:nowrap">${l.timestamp || '—'}</td>
            <td style="font-family:var(--mono); font-size:12px">${l.ip || '—'}</td>
            <td><span class="badge status-2xx" style="font-size:10px">${l.method || '—'}</span></td>
            <td style="font-family:var(--mono); font-size:12px; max-width:450px; overflow:hidden; text-overflow:ellipsis; white-space:nowrap; color:var(--text2)" title="${l.url || ''}">${l.url || '—'}</td>
            <td><span class="badge ${sc(l.status)}">${l.status || '—'}</span></td>
            <td style="font-family:var(--mono); font-size:11px">${(l.bytes || 0).toLocaleString()}</td>
            <td style="font-size:11px; max-width:350px; overflow:hidden; text-overflow:ellipsis; white-space:nowrap; color:var(--text3)" title="${l.user_agent || l.agent || ''}">${l.user_agent || l.agent || '—'}</td>
          </tr>`).join('')
      : '<tr><td colspan="7" style="text-align:center; color:var(--text3); padding:24px">No forensic entries match selectors</td></tr>';
      
    document.getElementById('pageInfo').textContent = `Page ${page + 1} of ${pages} (${total.toLocaleString()} rows)`;
    document.getElementById('prevBtn').disabled = page === 0;
    document.getElementById('nextBtn').disabled = page >= pages - 1;
  }
}

function changePage(d) { 
  State.logPage += d; 
  renderLogsPage(); 
}

function exportCSV() {
  if (!State.liveLogs.length) { alert('No live log data available to export.'); return; }
  const keys = ['timestamp', 'ip', 'method', 'url', 'status', 'bytes', 'user_agent'];
  const rows = [keys.join(','), ...State.liveLogs.map(l => keys.map(k => `"${(l[k] || l['agent'] || '').toString().replace(/"/g, '""')}"`).join(','))];
  download('live_export.csv', rows.join('\n'), 'text/csv');
}

// ══════════════════════════════════════════════════════════
//  TIMELINE RECONSTRUCTION
// ══════════════════════════════════════════════════════════
function renderTimeline() {
  const events = State.liveThreats.slice().sort((a, b) => (a.timestamp || '') < (b.timestamp || '') ? -1 : 1);
  const elCount = document.getElementById('tlCount');
  if (elCount) elCount.textContent = `${events.length} security alarms`;
  
  const dc = { critical: '#f43f5e', high: '#f59e0b', medium: '#8b5cf6', low: '#10b981' };
  const targetDom = document.getElementById('timelineItems');
  if (targetDom) {
    targetDom.innerHTML = events.length
      ? events.map(e => `
          <div class="tl-item">
            <div class="tl-time">${(e.timestamp || '').slice(11, 19) || '—'}</div>
            <div class="tl-dot" style="background:${dc[e.severity] || '#64748b'}; box-shadow:0 0 6px ${dc[e.severity] || '#64748b'}"></div>
            <div class="tl-body">
              <div class="tl-title">${e.type}</div>
              <div class="tl-desc">${e.ip} — ${e.detail}</div>
            </div>
            <div class="tl-sev"><span class="badge sev-${e.severity}">${(e.severity || '').toUpperCase()}</span></div>
          </div>`).join('')
      : '<div style="padding:24px; text-align:center; color:var(--text3)">No timeline events. Ingest baseline logs or start the agent.</div>';
  }
  
  // Rebuild Timeline Hour distribution chart
  const hourly = State.liveSnapshot ? State.liveSnapshot.hour_dist || {} : {};
  const hourDom = document.getElementById('timelineHourChart');
  if (hourDom && Object.keys(hourly).length && typeof echarts !== 'undefined') {
    try {
      if (!State.charts.timelineChart) {
        State.charts.timelineChart = echarts.init(hourDom, 'dark', { backgroundColor: 'transparent' });
      }
      const labels = Object.keys(hourly).map(h => h + ':00');
      const counts = Object.values(hourly);
      
      State.charts.timelineChart.setOption({
        tooltip: { trigger: 'axis', axisPointer: { type: 'shadow' } },
        grid: { left: '3%', right: '4%', bottom: '3%', top: '10%', containLabel: true },
        xAxis: { type: 'category', data: labels, axisLabel: { color: '#94a3b8', fontSize: 10 } },
        yAxis: { type: 'value', axisLabel: { color: '#94a3b8', fontSize: 10 }, splitLine: { lineStyle: { color: 'rgba(255, 255, 255, 0.05)' } } },
        series: [{
          name: 'Traffic Ingress',
          type: 'bar',
          barWidth: '60%',
          data: counts,
          itemStyle: {
            color: new echarts.graphic.LinearGradient(0, 0, 0, 1, [
              { offset: 0, color: '#8b5cf6' },
              { offset: 1, color: '#3b82f6' }
            ])
          }
        }]
      });
    } catch (e) {
      console.error('Failed to update timeline ECharts:', e);
    }
  }
}

// ══════════════════════════════════════════════════════════
//  INTEGRITY & FIM
// ══════════════════════════════════════════════════════════
function renderIntegrity() {
  const allCustody = State.liveCustody;
  const elInteg = document.getElementById('integritySection');
  if (elInteg) {
    elInteg.innerHTML = `
      <div class="text-muted text-sm">
        FIM is monitoring active agent paths. Live logs have integrity validation.
      </div>`;
  }
  
  const elCustody = document.getElementById('custodySection');
  if (elCustody) {
    elCustody.innerHTML = allCustody.length
      ? allCustody.map((e, i) => `
          <div class="custody-item">
            <div class="custody-dot"></div>
            <div class="custody-body">
              <div class="custody-action">${i + 1}. ${e.action}</div>
              <div class="custody-detail">${e.detail}</div>
              <div class="custody-meta">${(e.timestamp || '').slice(0, 19)} — ${e.actor}</div>
            </div>
          </div>`).join('')
      : '<div class="text-muted text-sm" style="padding:12px 0">Awaiting incident custody logs.</div>';
  }
}

function verifyHash() {
  const input = document.getElementById('verifyInput').value.trim();
  const result = document.getElementById('verifyResult');
  if (!input) { result.innerHTML = '<span class="text-xs text-muted">Enter SHA-256 fingerprint.</span>'; return; }
  if (!State.fileHash) { result.innerHTML = '<span class="text-xs text-muted">Awaiting baseline logs.</span>'; return; }
  const match = input.toLowerCase() === State.fileHash.toLowerCase();
  result.innerHTML = match ? '<span class="badge sev-low" style="font-size:12px">MATCH — BASELINE FINGERPRINT VERIFIED</span>' : '<span class="badge sev-crit" style="font-size:12px">CRITICAL MISMATCH — POSSIBLE DATA TAMPERING DETECTED!</span>';
}

function exportCustody() {
  const isForensic = State.consoleMode === 'forensic';
  const data = { 
    case_id: 'FLX-' + new Date().toISOString().replace(/[:.]/g, '-'), 
    analyst: document.getElementById(isForensic ? 'forensicRptAnalyst' : 'rptAnalyst')?.value || 'Analyst', 
    filename: isForensic ? State.filename : 'Live SOC Stream', 
    file_hash: isForensic ? State.fileHash : 'N/A - Real-Time Ingest', 
    created: new Date().toISOString(), 
    entries: isForensic ? [...State.forensicCustody] : [...State.liveCustody] 
  };
  download('custody_chain.json', JSON.stringify(data, null, 2), 'application/json');
}

// ══════════════════════════════════════════════════════════
//  FIREWALL IP BLOCKING
// ══════════════════════════════════════════════════════════
function renderBlocking() {
  const allThreats = State.liveThreats;
  const maliciousIPs = [...new Set(allThreats.map(t => t.ip).filter(ip => ip && ip !== 'Multiple'))];
  const allBlocked = new Set([...State.forensicBlocked, ...State.liveBlocked]);
  
  const elBlock = document.getElementById('ipBlockList');
  if (elBlock) {
    elBlock.innerHTML = maliciousIPs.length
      ? maliciousIPs.map(ip => {
          const t = allThreats.find(t => t.ip === ip);
          const blocked = allBlocked.has(ip);
          return `
            <div class="ip-item">
              <div class="ip-info">
                <span class="mono" style="font-size:13px; color:${blocked ? 'var(--text3)' : 'var(--danger)'}; ${blocked ? 'text-decoration:line-through' : ''}">${ip}</span>
                <span class="badge sev-${t?.severity || 'high'}">${(t?.type || 'Threat Vector').replace(/ \/ /g, '/')}</span>
                ${blocked ? '<span class="badge sev-low">BLOCKED</span>' : ''}
              </div>
              <button class="btn btn-sm ${blocked ? 'btn-ghost' : 'btn-danger'}" onclick="blockIP('${ip}')" ${blocked ? 'disabled' : ''}>${blocked ? 'Blocked' : 'Deploy Block'}</button>
            </div>`;
        }).join('')
      : '<div class="text-muted text-sm" style="padding:16px">No hostile IP ranges mapped for blockade.</div>';
  }
  renderFirewallRules(maliciousIPs);
}

async function blockIP(ip) {
  const analyst = document.getElementById('analystInput')?.value || 'Analyst';
  await fetch('/api/realtime/block', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ ip, actor: analyst }) });
  State.liveBlocked.add(ip); 
  if (State.consoleMode === 'forensic') {
    State.forensicBlocked.add(ip);
  }
  renderBlocking();
}

function renderFirewallRules(ips) {
  const out = document.getElementById('firewallOutput');
  if (!ips || !ips.length) { out.innerHTML = '<div class="t-line t-gray"># No active drop rules generated</div>'; return; }
  const allBlocked = new Set([...State.forensicBlocked, ...State.liveBlocked]);
  let html = '<div class="t-line t-gray"># ForensicLogX Auto-Generated Drop Engine</div><br>';
  ips.forEach(ip => {
    const bl = allBlocked.has(ip);
    html += `<div class="t-line t-gray"># Restrict Origin Host IP: ${ip}</div>`;
    html += `<div class="t-line"><span class="${bl ? 't-green' : 't-blue'}">iptables -A INPUT -s ${ip} -j DROP</span></div>`;
    html += `<div class="t-line"><span class="${bl ? 't-green' : 't-blue'}">ufw deny from ${ip} to any</span></div><br>`;
  });
  html += '<div class="t-line t-green"># iptables-save > /etc/iptables/rules.v4</div>';
  if (out) out.innerHTML = html;
  State.blockScript = '#!/bin/bash\n# ForensicLogX Firewall Drops\n\n' + ips.map(ip => `iptables -A INPUT -s ${ip} -j DROP\nufw deny from ${ip} to any`).join('\n') + '\n\niptables-save > /etc/iptables/rules.v4\necho "Drops active."';
}

function showBlockModal() {
  const allThreats = State.liveThreats;
  const allBlocked = new Set([...State.forensicBlocked, ...State.liveBlocked]);
  const ips = [...new Set(allThreats.map(t => t.ip).filter(ip => ip && ip !== 'Multiple' && !allBlocked.has(ip)))];
  if (!ips.length) { alert('All hostile IP ranges are currently dropping packages.'); return; }
  
  document.getElementById('blockCount').textContent = ips.length;
  document.getElementById('blockPreview').textContent = ips.slice(0, 5).map(ip => `iptables -A INPUT -s ${ip} -j DROP`).join('\n') + (ips.length > 5 ? `\n... and ${ips.length - 5} more directive items` : '');
  document.getElementById('blockModal').classList.add('show');
}

async function confirmBlockAll() {
  const allThreats = State.liveThreats;
  const ips = [...new Set(allThreats.map(t => t.ip).filter(ip => ip && ip !== 'Multiple'))];
  const analyst = document.getElementById('analystInput')?.value || 'Analyst';
  for (const ip of ips) {
    await fetch('/api/realtime/block', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ ip, actor: analyst }) });
    State.liveBlocked.add(ip); 
    if (State.consoleMode === 'forensic') {
      State.forensicBlocked.add(ip);
    }
  }
  closeModal('blockModal'); 
  renderBlocking();
}

function downloadBlockScript() { if (!State.blockScript) { alert('No drop directives built.'); return; } download('firewall_drops.sh', State.blockScript, 'text/x-sh'); }

// ══════════════════════════════════════════════════════════
//  INCIDENT REPORTS
// ══════════════════════════════════════════════════════════
function renderReport() {
  const allThreats = State.liveThreats;
  const analyst = document.getElementById('rptAnalyst')?.value || 'Analyst';
  
  document.getElementById('rpt-date').textContent = new Date().toLocaleString();
  document.getElementById('rpt-analyst').textContent = analyst;
  
  const elSumm = document.getElementById('rpt-summary');
  const total = State.liveLogs.length;
  const uniqueIPs = new Set(State.liveLogs.map(l => l.ip)).size;
  const errRate = State.liveSnapshot?.error_rate || 0;
  const critical = allThreats.filter(t => t.severity === 'critical').length;
  const high = allThreats.filter(t => t.severity === 'high').length;
  
  if (elSumm) {
    elSumm.innerHTML = `Live SOC session log monitoring containing <strong>${total.toLocaleString()}</strong> events from active agent streams mapped <strong>${allThreats.length}</strong> live threat indicators: <strong>${critical}</strong> CRITICAL alerts and <strong>${high}</strong> HIGH threats. A total of <strong>${uniqueIPs}</strong> unique host IP addresses resolved.`;
  }
  
  const findings = [
    { label: 'Ingested Events', value: total.toLocaleString(), color: 'var(--accent)' },
    { label: 'Security Alarms', value: allThreats.length, color: 'var(--danger)' },
    { label: 'Critical Threats', value: critical, color: 'var(--danger)' },
    { label: 'Hostile Blocked IPs', value: [...State.forensicBlocked, ...State.liveBlocked].length, color: 'var(--accent3)' }
  ];
  
  const elFinds = document.getElementById('rpt-findings');
  if (elFinds) {
    elFinds.innerHTML = findings.map(f => `
      <div style="background:rgba(255,255,255,0.02); border-radius:8px; padding:16px; border:1px solid var(--border)">
        <div class="text-xs text-muted" style="text-transform:uppercase; letter-spacing:0.5px; font-weight:600;">${f.label}</div>
        <div class="mono" style="font-size:22px; font-weight:700; color:${f.color}; margin-top:6px">${f.value}</div>
      </div>`).join('');
  }
  
  const threatIPs = [...new Set(allThreats.map(t => t.ip).filter(ip => ip !== 'Multiple'))];
  const elRecs = document.getElementById('rpt-recs');
  if (elRecs) {
    elRecs.innerHTML = [
      `Deploy drop rules blocking origin host IP addresses: ${threatIPs.slice(0, 5).join(', ')}.`,
      'Configure ModSecurity WAF rules and restrict input parameter checks.',
      'Enforce baseline parameter checks for OWASP Top 10 vulnerabilities.',
      'Establish FIM integrity checks for all directory nodes.',
      'Export consolidated incident timeline logs for forensic documentation.'
    ].map((r, i) => `<div style="margin-bottom:6px"><strong>${i + 1}.</strong> ${r}</div>`).join('');
  }
}

async function generatePDF() {
  const analyst = document.getElementById('rptAnalyst')?.value || 'Analyst';
  const org = document.getElementById('rptOrg')?.value || '';
  document.getElementById('loadingMsg').textContent = 'Generating executive forensic report...';
  document.getElementById('loadingModal').classList.add('show');
  try {
    const res = await fetch('/api/report/generate', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ analyst, organization: org, analysis_id: null }) });
    if (!res.ok) { const e = await res.json(); alert('Error: ' + e.error); document.getElementById('loadingModal').classList.remove('show'); return; }
    const blob = await res.blob(); 
    const url = URL.createObjectURL(blob); 
    const a = document.createElement('a'); 
    a.href = url; 
    a.download = 'forensic_report.pdf'; 
    a.click(); 
    URL.revokeObjectURL(url);
  } catch (e) {
    alert('PDF failed. Install reportlab: pip install reportlab\n' + e.message);
  }
  document.getElementById('loadingModal').classList.remove('show');
}

// ══════════════════════════════════════════════════════════
//  MODALS / UTILS
// ══════════════════════════════════════════════════════════
function closeModal(id) { 
  document.getElementById(id).classList.remove('show'); 
}

function download(filename, content, type) { 
  const blob = new Blob([content], { type }); 
  const a = document.createElement('a'); 
  a.href = URL.createObjectURL(blob); 
  a.download = filename; 
  a.click(); 
  URL.revokeObjectURL(a.href); 
}

// Left Sidebar quick search handler
function handleSideSearch(val) {
  if (!val) return;
  const searchInput = document.getElementById('logSearch');
  if (searchInput) {
    searchInput.value = val;
    switchView('logs');
    applyLogFilters();
  }
}

// ══════════════════════════════════════════════════════════
//  CYBER RANGE (TEST LAB) STATUS POLLING
// ══════════════════════════════════════════════════════════
async function pollTestLabStatus() {
  if (!isActiveView('testlab')) return;
  try {
    const res = await fetch('/api/testlab/status');
    const data = await res.json();
    if (!data.success) return;
    
    document.getElementById('tl-connected-count').textContent = data.connected_logs.length;
    document.getElementById('tl-connected-list').textContent = data.connected_logs.length > 0 
      ? data.connected_logs.join(', ') 
      : 'No active logs';
      
    document.getElementById('tl-waf-blocks').textContent = data.modsec_alerts;
    document.getElementById('tl-total-attacks').textContent = data.total_attacks;
    document.getElementById('tl-last-read').textContent = data.last_log_time;
    
    const items = [
      'sqli', 'sqli_blind', 'xss_reflected', 'xss_stored', 'xss_dom',
      'csrf', 'cmd', 'upload', 'traversal', 'captcha', 'weak_id',
      'csp', 'javascript', 'auth_bypass', 'redirect', 'crypto', 'api', 'brute'
    ];
    items.forEach(item => {
      const el = document.getElementById('chk-' + item);
      if (el) {
        if (data.checklist[item]) {
          el.textContent = 'DETECTED';
          el.className = 'badge sev-low';
        } else {
          el.textContent = 'PENDING';
          el.className = 'badge sev-crit';
        }
      }
    });

    const ai = data.agent_info;
    if (ai && ai.status) {
      const statusEl = document.getElementById('tl-agent-status');
      if (statusEl) {
        statusEl.textContent = ai.status.toUpperCase();
        statusEl.className = 'badge sev-low';
      }
      document.getElementById('tl-hostname').textContent = ai.hostname;
      document.getElementById('tl-os').textContent = ai.os;
      document.getElementById('tl-last-seen').textContent = new Date(ai.last_seen).toLocaleTimeString();
      
      document.getElementById('tl-cpu-pct').textContent = ai.cpu_usage;
      document.getElementById('tl-cpu-fill').style.width = ai.cpu_usage;
      
      document.getElementById('tl-mem-pct').textContent = ai.memory_usage;
      document.getElementById('tl-mem-fill').style.width = ai.memory_usage;
      
      document.getElementById('tl-disk-pct').textContent = ai.disk_usage;
      document.getElementById('tl-disk-fill').style.width = ai.disk_usage;
    }

    const alertsFeed = document.getElementById('tl-modsec-alerts');
    if (alertsFeed && data.latest_alerts) {
      if (data.latest_alerts.length === 0) {
        alertsFeed.innerHTML = '<div class="feed-placeholder">No alerts triggered</div>';
      } else {
        alertsFeed.innerHTML = data.latest_alerts.map(a => {
          const sevCls = a.severity === 'CRITICAL' ? 'crit' : a.severity === 'HIGH' ? 'high' : 'med';
          const badgeCls = a.severity === 'CRITICAL' ? 'sev-crit' : a.severity === 'HIGH' ? 'sev-high' : 'sev-med';
          return `
            <div class="alert-item ${sevCls}" style="padding: 10px; margin-bottom: 8px; border-radius: 6px;">
              <div style="display: flex; justify-content: space-between; font-weight: 600; font-size: 11.5px; margin-bottom: 4px;">
                <span>Rule ${a.rule_id} (${a.attack_category})</span>
                <span class="badge ${badgeCls}">${a.severity}</span>
              </div>
              <div style="font-size: 11px; color: var(--text2); line-height: 1.4; margin-bottom: 6px; font-family: var(--mono);">${a.rule_message}</div>
              <div style="display: flex; justify-content: space-between; font-size: 10px; color: var(--text3); font-family: var(--mono);">
                <span style="color: var(--accent); font-weight:600;">IP: ${a.source_ip}</span>
                <span>${a.timestamp.slice(11, 19)}</span>
              </div>
            </div>`;
        }).join('');
      }
    }
  } catch (e) {
    console.error('Failed to poll Test Lab status:', e);
  }
}

setInterval(pollTestLabStatus, 3000);

// Initialize script elements on DOM load
window.addEventListener('DOMContentLoaded', () => {
  State.filteredLogs = State.consoleMode === 'forensic' ? State.forensicLogs : State.liveLogs;
  
  // Initialize Leaflet Map
  initLeafletMap();
  
  // Load Sigma Rules repo
  loadSigmaRules();
  
  // Load initial Live Snapshot if socket hasn't pushed yet
  fetch('/api/realtime/snapshot')
    .then(res => res.json())
    .then(snap => {
      State.liveSnapshot = snap;
      State.liveThreats = snap.threats || [];
      State.liveLogs    = snap.recent_logs || [];
      State.liveBlocked = new Set(snap.blocked_ips || []);
      State.liveCustody = snap.custody || [];
      State.modsecThreats = snap.modsec_threats || [];
      State.sigmaAlerts   = snap.sigma_alerts || [];
      
      if (State.consoleMode === 'live') {
        applySnapshot(snap);
      }
    })
    .catch(err => console.error("Error loading initial snapshot:", err));
    
  if (window.lucide) {
    lucide.createIcons();
  }
});

// ══════════════════════════════════════════════════════════
//  SIGMA RULES ENGINE INTERACTIVE VISUALIZER FUNCTIONS
// ══════════════════════════════════════════════════════════

function prependSigmaAlertCard(t) {
  const feed = document.getElementById('sigmaThreatFeed');
  if (!feed) return;
  
  const placeholder = feed.querySelector('.feed-placeholder');
  if (placeholder) {
    feed.innerHTML = '';
  }
  
  const lvl = (t.level || 'low').toUpperCase();
  let badgeClass = 'badge-notice';
  let alertClass = 'notice';
  
  if (lvl === 'CRITICAL') {
    badgeClass = 'badge-critical';
    alertClass = 'critical';
  } else if (lvl === 'HIGH') {
    badgeClass = 'badge-error';
    alertClass = 'error';
  } else if (lvl === 'MEDIUM') {
    badgeClass = 'badge-warning';
    alertClass = 'warning';
  }
  
  const div = document.createElement('div');
  div.className = `alert-item ${alertClass}`;
  div.style.padding = '12px';
  div.style.marginBottom = '8px';
  div.style.borderRadius = '8px';
  
  div.innerHTML = `
    <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 6px;">
      <span style="font-weight: 600; font-size: 13px; color: var(--text);">${t.title}</span>
      <span class="badge ${badgeClass}" style="font-size: 10px; font-weight: 600;">${lvl}</span>
    </div>
    <div style="font-size: 12px; color: var(--text2); margin-bottom: 6px; font-family: var(--mono);">
      IP: <span style="color: var(--danger);">${t.attacker_ip}</span>
    </div>
    <div style="font-size: 11px; color: var(--text3); line-height: 1.4; margin-bottom: 6px;">
      <strong>Rule ID: ${t.rule_id ? t.rule_id.slice(0, 8) : 'unknown'}</strong>: ${t.description || 'Matched signature pattern.'}
    </div>
    <div style="font-size: 10px; color: var(--text3); text-align: right;">
      ${t.timestamp}
    </div>
  `;
  
  feed.insertBefore(div, feed.firstChild);
  
  while (feed.children.length > 50) {
    feed.removeChild(feed.lastChild);
  }
  
  const badge = document.getElementById('sigmaThreatBadge');
  if (badge) badge.style.display = '';
}

function rebuildSigmaThreatFeed() {
  const feed = document.getElementById('sigmaThreatFeed');
  if (!feed) return;
  feed.innerHTML = '';
  if (!State.sigmaAlerts || State.sigmaAlerts.length === 0) {
    feed.innerHTML = '<div class="feed-placeholder">Awaiting Sigma pattern detections...</div>';
    return;
  }
  State.sigmaAlerts.forEach(prependSigmaAlertCard);
}

function showSigmaToast(t) {
  const container = document.getElementById('toastContainer');
  if (!container) return;
  const lvl = (t.level || 'low').toUpperCase();
  const sevCls = lvl === 'CRITICAL' ? 'crit' : lvl === 'HIGH' ? 'high' : 'med';
  const el = document.createElement('div');
  el.className = `toast ${sevCls}`;
  el.innerHTML = `
    <div class="toast-title" style="color: var(--danger); font-weight: 700;">⚠️ SIGMA ALERT DETECTED</div>
    <div class="toast-body" style="font-family: var(--mono); margin-top: 4px;">
      ${t.title} — ${t.attacker_ip}<br>
      Rule ID: ${t.rule_id ? t.rule_id.slice(0, 8) : 'unknown'}
    </div>`;
  container.appendChild(el);
  setTimeout(() => el.remove(), 5000);
}

function updateSigmaStatsUI(stats) {
  if (!stats) return;
  
  // 1. Total active rules
  const elRules = document.getElementById('m-sigma-rules');
  if (elRules && State.sigmaRules) {
    elRules.textContent = State.sigmaRules.length;
  }
  
  // 2. Alert total
  const elAlerts = document.getElementById('m-sigma-alerts');
  if (elAlerts) {
    elAlerts.textContent = stats.total || 0;
  }
  
  // 3. Critical & High
  const elCrit = document.getElementById('m-sigma-critical');
  if (elCrit) {
    const critHigh = (stats.by_level?.critical || 0) + (stats.by_level?.high || 0);
    elCrit.textContent = critHigh;
  }
}

async function loadSigmaRules() {
  try {
    const res = await fetch('/api/sigma/rules/list');
    const data = await res.json();
    State.sigmaRules = data;
    
    // Update the Active Sigma Rules counter
    const elRules = document.getElementById('m-sigma-rules');
    if (elRules) {
      elRules.textContent = data.length;
    }
    
    renderSigmaRulesTable();
  } catch (e) {
    console.error("Failed to load Sigma rules repository:", e);
  }
}

function showSigmaRulesModal() {
  const modal = document.getElementById('sigmaRulesModal');
  if (modal) {
    modal.classList.add('show');
    loadSigmaRules();
  }
}

function renderSigmaRulesTable() {
  const body = document.getElementById('sigmaRulesTableBody');
  if (!body || !State.sigmaRules) return;
  
  body.innerHTML = '';
  
  if (State.sigmaRules.length === 0) {
    body.innerHTML = '<tr><td colspan="5" style="text-align:center;">No rules found in repository.</td></tr>';
    return;
  }
  
  State.sigmaRules.forEach(r => {
    const tr = document.createElement('tr');
    const tagsStr = (r.tags || []).map(t => `<span class="badge badge-notice" style="font-size:10px; margin-right:4px;">${t}</span>`).join('');
    const lvl = (r.level || 'low').toUpperCase();
    let badgeClass = 'badge-notice';
    if (lvl === 'CRITICAL') badgeClass = 'badge-critical';
    else if (lvl === 'HIGH') badgeClass = 'badge-error';
    else if (lvl === 'MEDIUM') badgeClass = 'badge-warning';
    
    tr.className = 'rule-row';
    tr.innerHTML = `
      <td><strong style="color:var(--accent);">${r.title}</strong><br><small style="color:var(--text3); font-family:var(--mono);">${r.path}</small></td>
      <td><span class="badge ${badgeClass}">${lvl}</span></td>
      <td><span class="mono">${r.category}</span></td>
      <td style="color:var(--text2);">${r.description || 'No description provided.'}</td>
      <td>${tagsStr || '—'}</td>
    `;
    body.appendChild(tr);
  });
}

function filterSigmaRules() {
  const q = document.getElementById('sigmaRuleSearch')?.value.toLowerCase() || '';
  const lvl = document.getElementById('sigmaRuleLevelFilter')?.value || 'all';
  const cat = document.getElementById('sigmaRuleCategoryFilter')?.value || 'all';
  
  const body = document.getElementById('sigmaRulesTableBody');
  if (!body || !State.sigmaRules) return;
  
  body.innerHTML = '';
  
  const filtered = State.sigmaRules.filter(r => {
    const mSearch = (
      r.title.toLowerCase().includes(q) ||
      (r.description || '').toLowerCase().includes(q) ||
      r.path.toLowerCase().includes(q) ||
      (r.tags || []).some(t => t.toLowerCase().includes(q))
    );
    const mLvl = lvl === 'all' || r.level.toLowerCase() === lvl;
    const mCat = cat === 'all' || r.category.toLowerCase() === cat;
    return mSearch && mLvl && mCat;
  });
  
  if (filtered.length === 0) {
    body.innerHTML = '<tr><td colspan="5" style="text-align:center;">No matching rules found in repository.</td></tr>';
    return;
  }
  
  filtered.forEach(r => {
    const tr = document.createElement('tr');
    const tagsStr = (r.tags || []).map(t => `<span class="badge badge-notice" style="font-size:10px; margin-right:4px;">${t}</span>`).join('');
    const lvl = (r.level || 'low').toUpperCase();
    let badgeClass = 'badge-notice';
    if (lvl === 'CRITICAL') badgeClass = 'badge-critical';
    else if (lvl === 'HIGH') badgeClass = 'badge-error';
    else if (lvl === 'MEDIUM') badgeClass = 'badge-warning';
    
    tr.className = 'rule-row';
    tr.innerHTML = `
      <td><strong style="color:var(--accent);">${r.title}</strong><br><small style="color:var(--text3); font-family:var(--mono);">${r.path}</small></td>
      <td><span class="badge ${badgeClass}">${lvl}</span></td>
      <td><span class="mono">${r.category}</span></td>
      <td style="color:var(--text2);">${r.description || 'No description provided.'}</td>
      <td>${tagsStr || '—'}</td>
    `;
    body.appendChild(tr);
  });
}

// ══════════════════════════════════════════════════════════
//  CONSOLE MODE SWITCHER
// ══════════════════════════════════════════════════════════
function setConsoleMode(mode) {
  // Global mode switching disabled. System locked to Live SOC mode.
}

// ══════════════════════════════════════════════════════════
//  FORENSIC UPLOAD RESULTS CONSOLE
// ══════════════════════════════════════════════════════════
let forensicCharts = {
  radar: null,
  line: null
};

function resetForensicConsole() {
  State.forensicSummary = null;
  State.forensicThreats = [];
  State.forensicCustody = [];
  State.fileHash = '';
  State.filename = '';
  State.forensicLogs = [];
  
  // Hide results, show uploader form
  document.getElementById('upload-results-container').style.display = 'none';
  document.getElementById('upload-form-container').style.display = 'block';
  
  // Clean up charts
  if (forensicCharts.radar) {
    forensicCharts.radar.dispose();
    forensicCharts.radar = null;
  }
  if (forensicCharts.line) {
    forensicCharts.line.dispose();
    forensicCharts.line = null;
  }
}

function switchForensicSubTab(tabId) {
  // Hide all sub-views
  document.querySelectorAll('.forensic-subview').forEach(v => v.style.display = 'none');
  // Deactivate all forensic sub-tabs buttons
  document.querySelectorAll('.forensic-tab-btn').forEach(b => b.classList.remove('active'));
  
  // Show target sub-view
  const subview = document.getElementById('forensic-subview-' + tabId);
  if (subview) subview.style.display = 'block';
  
  // Activate tab button
  const btn = document.getElementById('forensic-btn-' + tabId);
  if (btn) btn.classList.add('active');
  
  // Trigger sub-view specific logic
  if (tabId === 'dashboard') {
    renderForensicDashboard();
    setTimeout(() => {
      if (forensicCharts.radar) forensicCharts.radar.resize();
      if (forensicCharts.line) forensicCharts.line.resize();
    }, 100);
  } else if (tabId === 'threats') {
    renderForensicThreats();
  } else if (tabId === 'logs') {
    applyForensicLogFilters();
  } else if (tabId === 'custody') {
    renderForensicCustody();
  } else if (tabId === 'reports') {
    renderForensicReport();
  }
}

function renderForensicDashboard() {
  const summary = State.forensicSummary;
  const threats = State.forensicThreats;
  if (!summary) return;
  
  document.getElementById('forensic-m-total').textContent = summary.total_requests.toLocaleString();
  document.getElementById('forensic-m-threats').textContent = threats.length;
  document.getElementById('forensic-m-ips').textContent = summary.unique_ips;
  document.getElementById('forensic-m-errors').textContent = summary.error_rate_pct + '%';
  
  // Render Top Ingress Attack Sources progress indicators
  buildForensicTopIPs(summary.top_ips);
  
  // Render graphs
  initForensicCharts();
}

function buildForensicTopIPs(topIps) {
  const ips = topIps || {};
  const sorted = Object.entries(ips).sort((a, b) => b[1] - a[1]).slice(0, 7);
  const max = sorted[0]?.[1] || 1;
  const mal = new Set(State.forensicThreats.map(t => t.ip));
  
  const container = document.getElementById('forensicTopIPs');
  if (container) {
    container.innerHTML = sorted.map(([ip, cnt]) => `
      <div style="margin-bottom:12px">
        <div style="display:flex; justify-content:space-between; margin-bottom:5px">
          <span style="font-family:var(--mono); font-size:12px; font-weight:500; color:${mal.has(ip) ? 'var(--danger)' : 'var(--text)'}">${ip}</span>
          <span style="font-size:11px; color:var(--text3)">${cnt.toLocaleString()} req ${mal.has(ip) ? '<span class="badge sev-crit" style="font-size:8px; padding:1px 4px; margin-left:6px;">THREAT</span>' : ''}</span>
        </div>
        <div class="progress-bar" style="margin:0; height:5px"><div class="progress-fill" style="width:${Math.round(cnt / max * 100)}%; background:${mal.has(ip) ? 'var(--danger)' : 'var(--accent)'}"></div></div>
      </div>`).join('');
  }
}

function initForensicCharts() {
  if (typeof echarts === 'undefined') return;
  
  const radarDom = document.getElementById('forensicRadarChart');
  if (radarDom && State.forensicThreats) {
    if (!forensicCharts.radar) {
      forensicCharts.radar = echarts.init(radarDom, 'dark', { backgroundColor: 'transparent' });
    }
    const counts = { SQLi: 0, XSS: 0, RCE: 0, LFI: 0, BruteForce: 0, Scanning: 0 };
    State.forensicThreats.forEach(t => {
      const type = (t.type || '').toLowerCase();
      if (type.includes('sqli') || type.includes('sql')) counts.SQLi++;
      else if (type.includes('xss') || type.includes('cross-site')) counts.XSS++;
      else if (type.includes('rce') || type.includes('command')) counts.RCE++;
      else if (type.includes('lfi') || type.includes('traversal')) counts.LFI++;
      else if (type.includes('brute') || type.includes('auth')) counts.BruteForce++;
      else if (type.includes('scan') || type.includes('recon')) counts.Scanning++;
    });
    
    const dataMax = Math.max(...Object.values(counts), 5) * 1.2;
    forensicCharts.radar.setOption({
      tooltip: { trigger: 'item' },
      radar: {
        indicator: [
          { name: 'SQL Injection', max: dataMax },
          { name: 'XSS Reflected', max: dataMax },
          { name: 'RCE / Commands', max: dataMax },
          { name: 'Path Traversal / LFI', max: dataMax },
          { name: 'Brute Force Attempts', max: dataMax },
          { name: 'Scanning & Recon', max: dataMax }
        ],
        shape: 'polygon',
        axisName: { color: '#94a3b8', fontSize: 10 },
        splitArea: { show: false },
        splitLine: { lineStyle: { color: 'rgba(255, 255, 255, 0.05)' } },
        axisLine: { lineStyle: { color: 'rgba(255, 255, 255, 0.05)' } }
      },
      series: [{
        name: 'Incident Vectors',
        type: 'radar',
        data: [{
          value: [counts.SQLi, counts.XSS, counts.RCE, counts.LFI, counts.BruteForce, counts.Scanning],
          name: 'Alert Density',
          areaStyle: { color: 'rgba(244, 63, 94, 0.2)' },
          lineStyle: { color: '#f43f5e', width: 2 },
          itemStyle: { color: '#f43f5e' }
        }]
      }]
    });
  }
  
  const lineDom = document.getElementById('forensicLineChart');
  if (lineDom && State.forensicSummary) {
    if (!forensicCharts.line) {
      forensicCharts.line = echarts.init(lineDom, 'dark', { backgroundColor: 'transparent' });
    }
    const h = State.forensicSummary.hourly_traffic || {};
    const labels = Object.keys(h).map(k => k + ':00');
    const counts = Object.values(h);
    
    forensicCharts.line.setOption({
      tooltip: { trigger: 'axis' },
      grid: { left: '3%', right: '4%', bottom: '3%', top: '10%', containLabel: true },
      xAxis: { type: 'category', boundaryGap: false, data: labels, axisLabel: { color: '#94a3b8', fontSize: 10 } },
      yAxis: { type: 'value', axisLabel: { color: '#94a3b8', fontSize: 10 }, splitLine: { lineStyle: { color: 'rgba(255, 255, 255, 0.05)' } } },
      series: [{
        name: 'Traffic Rate',
        type: 'line',
        smooth: true,
        data: counts,
        symbolSize: 6,
        showSymbol: false,
        lineStyle: { color: '#00f0ff', width: 2 },
        itemStyle: { color: '#00f0ff' },
        areaStyle: {
          color: new echarts.graphic.LinearGradient(0, 0, 0, 1, [
            { offset: 0, color: 'rgba(0, 240, 255, 0.2)' },
            { offset: 1, color: 'rgba(0, 240, 255, 0)' }
          ])
        }
      }]
    });
  }
}

function renderForensicThreats() {
  const list = State.forensicThreats;
  const sc = { critical: 'sev-critical', high: 'sev-high', medium: 'sev-medium', low: 'sev-low' };
  const targetDom = document.getElementById('forensicThreatBody');
  if (targetDom) {
    targetDom.innerHTML = list.length
      ? list.map(t => `
          <tr>
            <td style="font-size:11px">${(t.timestamp || '').slice(11, 19) || '—'}</td>
            <td style="font-weight:600; color:var(--text);">${t.type}</td>
            <td><span class="badge ${sc[(t.severity || '').toLowerCase()] || 'sev-low'}">${(t.severity || '').toUpperCase()}</span></td>
            <td style="color:var(--danger); font-family:var(--mono); font-size:12px">${t.ip}</td>
            <td style="color:var(--text2); font-size:12.5px; font-family:var(--font)">${t.detail}</td>
            <td style="font-family:var(--mono); font-weight:700;">${t.count || '1'}</td>
          </tr>`).join('')
      : '<tr><td colspan="6" style="text-align:center; color:var(--text3); padding:24px">No alerts match filter selections</td></tr>';
  }
}

let forensicFilteredLogs = [];
let forensicLogPage = 0;
const FORENSIC_PAGE_SIZE = 25;

function applyForensicLogFilters() {
  const search = (document.getElementById('forensicLogSearch').value || '').toLowerCase();
  const sf = document.getElementById('forensicStatusFilter').value;
  const mf = document.getElementById('forensicMethodFilter').value;
  
  let logs = State.forensicLogs.slice();
  if (search) {
    logs = logs.filter(l => (l.ip || '').includes(search) || (l.url || '').toLowerCase().includes(search) || (l.method || '').toLowerCase().includes(search));
  }
  if (sf !== 'all') {
    logs = logs.filter(l => String(l.status || '').startsWith(sf[0]));
  }
  if (mf !== 'all') {
    logs = logs.filter(l => l.method === mf);
  }
  forensicFilteredLogs = logs; 
  forensicLogPage = 0; 
  renderForensicLogsPage();
}

function renderForensicLogsPage() {
  const total = forensicFilteredLogs.length; 
  const pages = Math.max(1, Math.ceil(total / FORENSIC_PAGE_SIZE));
  const page = Math.min(Math.max(0, forensicLogPage), pages - 1); 
  forensicLogPage = page;
  
  const slice = forensicFilteredLogs.slice(page * FORENSIC_PAGE_SIZE, (page + 1) * FORENSIC_PAGE_SIZE);
  const sc = s => {
    if (s >= 500) return 'status-5xx';
    if (s >= 400) return 'status-4xx';
    if (s >= 300) return 'status-3xx';
    return 'status-2xx';
  };
  
  const targetDom = document.getElementById('forensicLogBody');
  if (targetDom) {
    targetDom.innerHTML = slice.length 
      ? slice.map(l => `
          <tr>
            <td style="font-size:11px; white-space:nowrap">${l.timestamp || '—'}</td>
            <td style="font-family:var(--mono); font-size:12px">${l.ip || '—'}</td>
            <td><span class="badge status-2xx" style="font-size:10px">${l.method || '—'}</span></td>
            <td style="font-family:var(--mono); font-size:12px; max-width:450px; overflow:hidden; text-overflow:ellipsis; white-space:nowrap; color:var(--text2)" title="${l.url || ''}">${l.url || '—'}</td>
            <td><span class="badge ${sc(l.status)}">${l.status || '—'}</span></td>
            <td style="font-family:var(--mono); font-size:11px">${(l.bytes || 0).toLocaleString()}</td>
            <td style="font-size:11px; max-width:350px; overflow:hidden; text-overflow:ellipsis; white-space:nowrap; color:var(--text3)" title="${l.user_agent || l.agent || ''}">${l.user_agent || l.agent || '—'}</td>
          </tr>`).join('')
      : '<tr><td colspan="7" style="text-align:center; color:var(--text3); padding:24px">No forensic entries match selectors</td></tr>';
      
    document.getElementById('forensicPageInfo').textContent = `Page ${page + 1} of ${pages} (${total.toLocaleString()} rows)`;
    document.getElementById('forensicPrevBtn').disabled = page === 0;
    document.getElementById('forensicNextBtn').disabled = page >= pages - 1;
  }
}

function changeForensicPage(d) {
  forensicLogPage += d;
  renderForensicLogsPage();
}

function renderForensicCustody() {
  const allCustody = State.forensicCustody;
  
  const elCustody = document.getElementById('forensicCustodySection');
  if (elCustody) {
    elCustody.innerHTML = allCustody.length
      ? allCustody.map((e, i) => `
          <div class="custody-item">
            <div class="custody-dot"></div>
            <div class="custody-body">
              <div class="custody-action">${i + 1}. ${e.action}</div>
              <div class="custody-detail">${e.detail}</div>
              <div class="custody-meta">${(e.timestamp || '').slice(0, 19)} — ${e.actor}</div>
            </div>
          </div>`).join('')
      : '<div class="text-muted text-sm" style="padding:12px 0">Awaiting incident custody logs.</div>';
  }
}

function verifyForensicHash() {
  const input = document.getElementById('forensicVerifyInput').value.trim();
  const result = document.getElementById('forensicVerifyResult');
  if (!input) { result.innerHTML = '<span class="text-xs text-muted">Enter SHA-256 fingerprint.</span>'; return; }
  if (!State.fileHash) { result.innerHTML = '<span class="text-xs text-muted">Awaiting baseline logs.</span>'; return; }
  const match = input.toLowerCase() === State.fileHash.toLowerCase();
  result.innerHTML = match ? '<span class="badge sev-low" style="font-size:12px">MATCH — BASELINE FINGERPRINT VERIFIED</span>' : '<span class="badge sev-crit" style="font-size:12px">CRITICAL MISMATCH — POSSIBLE DATA TAMPERING DETECTED!</span>';
}

function renderForensicReport() {
  const threats = State.forensicThreats;
  const threatIPs = [...new Set(threats.map(t => t.ip).filter(ip => ip !== 'Multiple'))];
  
  const elRecs = document.getElementById('forensicRemediationSection');
  if (elRecs) {
    elRecs.innerHTML = [
      `Deploy drop rules blocking origin host IP addresses: ${threatIPs.slice(0, 5).join(', ')}.`,
      'Configure ModSecurity WAF rules and restrict input parameter checks.',
      'Enforce baseline parameter checks for OWASP Top 10 vulnerabilities.',
      'Establish FIM integrity checks for all directory nodes.',
      'Export consolidated incident timeline logs for forensic documentation.'
    ].map((r, i) => `<div style="margin-bottom:6px"><strong>${i + 1}.</strong> ${r}</div>`).join('');
  }
}

async function generateForensicPDF() {
  const analyst = document.getElementById('forensicRptAnalyst')?.value || 'Analyst';
  const org = document.getElementById('forensicRptOrg')?.value || '';
  document.getElementById('loadingMsg').textContent = 'Generating executive forensic report...';
  document.getElementById('loadingModal').classList.add('show');
  try {
    const res = await fetch('/api/report/generate', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ analyst, organization: org, analysis_id: State.analysisId }) });
    if (!res.ok) { const e = await res.json(); alert('Error: ' + e.error); document.getElementById('loadingModal').classList.remove('show'); return; }
    const blob = await res.blob(); 
    const url = URL.createObjectURL(blob); 
    const a = document.createElement('a'); 
    a.href = url; 
    a.download = 'forensic_report.pdf'; 
    a.click(); 
    URL.revokeObjectURL(url);
  } catch (e) {
    alert('PDF failed. Install reportlab: pip install reportlab\n' + e.message);
  }
  document.getElementById('loadingModal').classList.remove('show');
}

function exportForensicCustody() {
  const data = { 
    case_id: 'FLX-' + new Date().toISOString().replace(/[:.]/g, '-'), 
    analyst: document.getElementById('forensicRptAnalyst')?.value || 'Analyst', 
    filename: State.filename, 
    file_hash: State.fileHash, 
    created: new Date().toISOString(), 
    entries: [...State.forensicCustody] 
  };
  download('custody_chain.json', JSON.stringify(data, null, 2), 'application/json');
}

function exportForensicCSV() {
  if (!State.forensicLogs.length) { alert('No log data loaded.'); return; }
  const keys = ['timestamp', 'ip', 'method', 'url', 'status', 'bytes', 'user_agent'];
  const rows = [keys.join(','), ...State.forensicLogs.map(l => keys.map(k => `"${(l[k] || l['agent'] || '').toString().replace(/"/g, '""')}"`).join(','))];
  download('forensic_export.csv', rows.join('\n'), 'text/csv');
}

