/**
 * ForensicLogX — Enterprise Detections Dashboard Script
 * Manages fetching API data, socket updates, and rendering ECharts for the rule-based detection engine.
 */

'use strict';

const DetectionsState = {
    total: 0,
    activeSignatures: 30,
    filteredFps: 0,
    triggerRate: 0,
    attacks: [],
    mitreTactics: {},
    topUrls: {},
    topIps: [],
    suspiciousAgents: [],
    hourlyTrend: {},
    severityStats: { critical: 0, high: 0, medium: 0, low: 0 },
    httpStatusStats: { '2xx': 0, '3xx': 0, '4xx': 0, '5xx': 0 },
    heatmapData: [],
    charts: {}
};

// Hook into view switching to trigger rendering
(function() {
    const originalSwitchView = window.switchView;
    window.switchView = function(id, el) {
        if (typeof originalSwitchView === 'function') {
            originalSwitchView(id, el);
        }
        if (id === 'enterprise-detections') {
            initEnterpriseDetections();
        }
    };
})();

async function initEnterpriseDetections() {
    await fetchDetectionsData();
    renderDetectionsUI();
    initDetectionsCharts();
    
    // Auto-resize charts on navigation
    setTimeout(() => {
        Object.values(DetectionsState.charts).forEach(chart => {
            if (chart) chart.resize();
        });
    }, 100);
}

// Fetch all necessary telemetry from backend
async function fetchDetectionsData() {
    try {
        const [attacksRes, summaryRes, topIpsRes, iocRes] = await Promise.all([
            fetch('/api/detections/attacks?page=1&page_size=50'),
            fetch('/api/detections/attacks/summary'),
            fetch('/api/detections/top-ips'),
            fetch('/api/detections/ioc-library')
        ]);

        const attacksData = await attacksRes.json();
        const summaryData = await summaryRes.json();
        const topIpsData = await topIpsRes.json();
        const iocData = await iocRes.json();

        DetectionsState.attacks = attacksData.attacks || [];
        DetectionsState.total = attacksData.total || 0;
        
        // Parse summary data
        if (summaryData && !summaryData.error) {
            const byCategory = summaryData.by_category || {};
            const bySeverity = summaryData.by_severity || {};
            const byFp = summaryData.by_fp || {};
            
            DetectionsState.filteredFps = byFp.FP || 0;
            const truePositives = byFp.TP || 0;
            const totalAlerts = truePositives + DetectionsState.filteredFps;
            DetectionsState.triggerRate = totalAlerts > 0 ? ((truePositives / totalAlerts) * 100).toFixed(1) : "0.0";
            
            DetectionsState.severityStats = {
                critical: bySeverity.critical || 0,
                high: bySeverity.high || 0,
                medium: bySeverity.medium || 0,
                low: bySeverity.low || 0
            };
        }

        DetectionsState.topIps = topIpsData || [];
        
        // Parse targeted URLs & MITRE tactics from fetched attacks
        const urlCounts = {};
        const tacticsMap = {};
        const agentCounts = {};
        const statusCounts = { '2xx': 0, '3xx': 0, '4xx': 0, '5xx': 0 };
        const hourlyTrend = {};

        DetectionsState.attacks.forEach(atk => {
            // Endpoints
            if (atk.url) {
                urlCounts[atk.url] = (urlCounts[atk.url] || 0) + 1;
            }
            
            // MITRE tactics
            if (atk.mitre_tactic) {
                tacticsMap[atk.mitre_tactic] = (tacticsMap[atk.mitre_tactic] || 0) + 1;
            }
            
            // User agents
            if (atk.user_agent) {
                const ua = atk.user_agent;
                agentCounts[ua] = (agentCounts[ua] || 0) + 1;
            }

            // HTTP status code classification
            const sc = atk.status_code;
            if (sc >= 500) statusCounts['5xx']++;
            else if (sc >= 400) statusCounts['4xx']++;
            else if (sc >= 300) statusCounts['3xx']++;
            else if (sc > 0) statusCounts['2xx']++;

            // Hourly trend parser
            if (atk.timestamp) {
                const hourStr = atk.timestamp.slice(0, 13); // 'YYYY-MM-DDTHH'
                hourlyTrend[hourStr] = (hourlyTrend[hourStr] || 0) + 1;
            }
        });

        DetectionsState.topUrls = urlCounts;
        DetectionsState.mitreTactics = tacticsMap;
        DetectionsState.httpStatusStats = statusCounts;
        DetectionsState.hourlyTrend = hourlyTrend;

        // User agents scanner parser
        const sortedAgents = Object.entries(agentCounts)
            .sort((a, b) => b[1] - a[1])
            .slice(0, 10)
            .map(([ua, count]) => {
                let tool = "Unknown Bot";
                const uaLower = ua.toLowerCase();
                if (uaLower.includes("nikto")) tool = "Nikto Scanner";
                else if (uaLower.includes("sqlmap")) tool = "SQLmap Injection Tool";
                else if (uaLower.includes("nmap")) tool = "Nmap Port Scanner";
                else if (uaLower.includes("gobuster")) tool = "Gobuster Dir Buster";
                else if (uaLower.includes("wfuzz")) tool = "Wfuzz Fuzzer";
                else if (uaLower.includes("python")) tool = "Python Automated Client";
                else if (uaLower.includes("curl")) tool = "Curl CLI Agent";
                return { ua, count, tool };
            });
        DetectionsState.suspiciousAgents = sortedAgents;

    } catch (e) {
        console.error("Failed to load enterprise detections dashboard data:", e);
    }
}

// Render HTML layout values
function renderDetectionsUI() {
    // 1. Update Metrics Counters
    document.getElementById("ent-total-detections").textContent = DetectionsState.total;
    document.getElementById("ent-filtered-fps").textContent = DetectionsState.filteredFps;
    document.getElementById("ent-trigger-rate").textContent = DetectionsState.triggerRate + "%";
    
    // 2. Render Live Feed Table
    const feedContainer = document.getElementById("entLiveFeed");
    if (feedContainer) {
        if (DetectionsState.attacks.length === 0) {
            feedContainer.innerHTML = '<div class="feed-placeholder">Awaiting rule triggers...</div>';
        } else {
            feedContainer.innerHTML = DetectionsState.attacks.map(atk => {
                const isFp = atk.false_positive_flag === 1;
                const isCrit = atk.severity === 'critical';
                const isHigh = atk.severity === 'high';
                const isMed = atk.severity === 'medium';
                
                let badgeClass = 'badge-notice';
                if (isCrit) badgeClass = 'badge-critical';
                else if (isHigh) badgeClass = 'badge-error';
                else if (isMed) badgeClass = 'badge-warning';

                return `
                    <div class="alert-item ${isCrit ? 'crit' : isHigh ? 'high' : 'med'}" style="margin-bottom: 10px; opacity: ${isFp ? 0.5 : 1};">
                        <div class="alert-item-title">
                            <span>${atk.attack_type || atk.category || 'Threat Alert'}</span>
                            <span class="badge ${badgeClass}">${(atk.severity || 'LOW').toUpperCase()}</span>
                        </div>
                        <div class="alert-item-detail">${atk.description || atk.detail}</div>
                        <div style="font-size: 11px; margin-top: 4px; display:flex; justify-content:space-between; align-items:center;">
                            <span style="font-family: var(--mono); color: var(--accent); font-weight:600;">IP: ${atk.source_ip}</span>
                            <span class="text-muted" style="font-size:10px;">${atk.timestamp}</span>
                        </div>
                        <div style="display:flex; justify-content:flex-end; gap:6px; margin-top:6px;">
                            ${isFp ? '<span class="badge badge-notice" style="font-size: 9px;">FALSE POSITIVE</span>' : 
                            `<button class="btn btn-ghost btn-sm" onclick="markAlertFalsePositive(${atk.id})" style="font-size: 9px; padding: 2px 6px;">FP</button>`}
                            <button class="btn btn-danger btn-sm" onclick="blockAttackerIP('${atk.source_ip}')" style="font-size: 9px; padding: 2px 6px;">BLOCK</button>
                        </div>
                    </div>
                `;
            }).join('');
        }
    }

    // 3. MITRE Tactic Heatmap list
    const heatmapContainer = document.getElementById("mitreHeatmapList");
    const mitreBadge = document.getElementById("mitre-intensity-badge");
    if (heatmapContainer) {
        const sortedTactics = Object.entries(DetectionsState.mitreTactics)
            .sort((a, b) => b[1] - a[1]);
        
        if (mitreBadge) {
            mitreBadge.textContent = `${sortedTactics.length} tactics triggered`;
        }

        if (sortedTactics.length === 0) {
            heatmapContainer.innerHTML = '<div class="feed-placeholder">No tactics logged yet</div>';
        } else {
            heatmapContainer.innerHTML = sortedTactics.map(([tactic, count]) => `
                <div class="ip-item" style="margin: 0; padding: 8px 12px; background: rgba(17, 24, 39, 0.4); border: 1px solid var(--border);">
                    <div style="display:flex; align-items:center; gap:8px;">
                        <i data-lucide="shield-alert" style="width:14px; height:14px; color: var(--danger);"></i>
                        <span class="mono" style="font-size:12px; font-weight:600; color: var(--text);">${tactic}</span>
                    </div>
                    <span class="badge sev-high" style="font-family: var(--mono);">${count} alerts</span>
                </div>
            `).join('');
            
            // Re-render lucide icons inside heatmap list
            if (typeof lucide !== 'undefined') {
                lucide.createIcons();
            }
        }
    }

    // 4. Render Top Targeted URLs
    const urlsContainer = document.getElementById("entTopUrls");
    if (urlsContainer) {
        const sortedUrls = Object.entries(DetectionsState.topUrls)
            .sort((a, b) => b[1] - a[1])
            .slice(0, 5);

        if (sortedUrls.length === 0) {
            urlsContainer.innerHTML = '<div class="feed-placeholder">No endpoint data parsed</div>';
        } else {
            urlsContainer.innerHTML = sortedUrls.map(([url, count]) => `
                <div class="ip-item" style="margin-bottom: 8px; padding: 10px;">
                    <div style="display:flex; flex-direction:column; width:100%;">
                        <span class="mono" style="font-size: 11.5px; color: var(--accent); overflow:hidden; text-overflow:ellipsis; white-space:nowrap; max-width:280px;" title="${url}">${url}</span>
                        <div style="display:flex; justify-content:space-between; align-items:center; margin-top:4px;">
                            <span class="text-xs text-muted">Attack vector targets</span>
                            <span class="badge sev-medium" style="font-family: var(--mono);">${count} hits</span>
                        </div>
                    </div>
                </div>
            `).join('');
        }
    }

    // 5. Render Suspicious User Agents
    const agentsContainer = document.getElementById("entSuspiciousAgents");
    if (agentsContainer) {
        if (DetectionsState.suspiciousAgents.length === 0) {
            agentsContainer.innerHTML = '<div class="feed-placeholder">Awaiting bot activity...</div>';
        } else {
            agentsContainer.innerHTML = DetectionsState.suspiciousAgents.map(ag => `
                <div class="ip-item" style="margin-bottom: 8px; padding: 10px;">
                    <div style="display:flex; flex-direction:column; width:100%;">
                        <span class="mono text-muted" style="font-size: 11px; overflow:hidden; text-overflow:ellipsis; white-space:nowrap; max-width:280px;" title="${ag.ua}">${ag.ua}</span>
                        <div style="display:flex; justify-content:space-between; align-items:center; margin-top:4px;">
                            <span class="badge sev-high" style="font-size: 9px; padding: 2px 6px;">${ag.tool}</span>
                            <span class="badge status-404" style="font-family: var(--mono);">${ag.count} probes</span>
                        </div>
                    </div>
                </div>
            `).join('');
        }
    }

    // 6. Render Active campaigns and top IPs
    const campaignsContainer = document.getElementById("entTopAttakers");
    if (campaignsContainer) {
        if (DetectionsState.topIps.length === 0) {
            campaignsContainer.innerHTML = '<div class="feed-placeholder">No campaign activity logged</div>';
        } else {
            campaignsContainer.innerHTML = DetectionsState.topIps.map(attacker => {
                const isBlocked = attacker.blocked === 1;
                return `
                    <div class="ip-item" style="margin-bottom: 8px; padding: 10px; border-left: 3px solid ${isBlocked ? 'var(--accent3)' : 'var(--danger)'};">
                        <div style="display:flex; justify-content:space-between; align-items:center; width:100%;">
                            <div>
                                <span class="mono" style="font-size:12.5px; font-weight:600; color: ${isBlocked ? 'var(--text3)' : 'var(--danger)'};">${attacker.ip}</span>
                                <div style="font-size:10px; color: var(--text3); margin-top:2px;">Last seen: ${attacker.last_seen || 'Unknown'}</div>
                            </div>
                            <div style="display:flex; flex-direction:column; align-items:flex-end; gap:4px;">
                                <span class="badge ${isBlocked ? 'sev-low' : 'sev-high'}" style="font-family:var(--mono);">${attacker.attack_count} attacks</span>
                                ${isBlocked ? '<span style="font-size: 9px; color: var(--accent3); font-weight:600;">BLOCKED</span>' : 
                                `<button class="btn btn-ghost btn-sm" onclick="blockAttackerIP('${attacker.ip}')" style="font-size: 9px; padding: 1px 4px;">BLOCK</button>`}
                            </div>
                        </div>
                    </div>
                `;
            }).join('');
        }
    }
}

// Initialize and redraw Apache ECharts
function initDetectionsCharts() {
    // 1. Timeline Chart (Line)
    const timelineDom = document.getElementById("entTimelineChart");
    if (timelineDom) {
        if (DetectionsState.charts.timeline) DetectionsState.charts.timeline.dispose();
        const chart = echarts.init(timelineDom, 'dark', { backgroundColor: 'transparent' });
        DetectionsState.charts.timeline = chart;

        const timelineEntries = Object.entries(DetectionsState.hourlyTrend)
            .sort((a, b) => a[0].localeCompare(b[0]));
        const xAxisData = timelineEntries.map(e => e[0].slice(11) + ":00");
        const seriesData = timelineEntries.map(e => e[1]);

        chart.setOption({
            tooltip: { trigger: 'axis', axisPointer: { type: 'cross' } },
            xAxis: { type: 'category', boundaryGap: false, data: xAxisData.length ? xAxisData : ["00:00"] },
            yAxis: { type: 'value', splitLine: { lineStyle: { color: 'rgba(255, 255, 255, 0.05)' } } },
            series: [{
                name: 'Rule Hits',
                type: 'line',
                smooth: true,
                data: seriesData.length ? seriesData : [0],
                itemStyle: { color: '#00f0ff' },
                areaStyle: {
                    color: new echarts.graphic.LinearGradient(0, 0, 0, 1, [
                        { offset: 0, color: 'rgba(0, 240, 255, 0.3)' },
                        { offset: 1, color: 'rgba(0, 240, 255, 0)' }
                    ])
                }
            }]
        });
    }

    // 2. Attack Type Doughnut
    const typeDom = document.getElementById("entAttackTypeChart");
    if (typeDom) {
        if (DetectionsState.charts.attackType) DetectionsState.charts.attackType.dispose();
        const chart = echarts.init(typeDom, 'dark', { backgroundColor: 'transparent' });
        DetectionsState.charts.attackType = chart;

        const categoryCounts = {};
        DetectionsState.attacks.forEach(atk => {
            const cat = atk.category || "Other";
            categoryCounts[cat] = (categoryCounts[cat] || 0) + 1;
        });

        const data = Object.entries(categoryCounts).map(([name, value]) => ({ name, value }));

        chart.setOption({
            tooltip: { trigger: 'item' },
            series: [{
                name: 'Attack Types',
                type: 'pie',
                radius: ['40%', '70%'],
                avoidLabelOverlap: false,
                itemStyle: { borderRadius: 6, borderColor: '#0b0f19', borderWidth: 2 },
                label: { show: false, position: 'center' },
                emphasis: { label: { show: true, fontSize: 14, fontWeight: 'bold' } },
                data: data.length ? data : [{ name: 'Benign', value: 0 }]
            }]
        });
    }

    // 3. Severity stacked bar
    const sevDom = document.getElementById("entSeverityChart");
    if (sevDom) {
        if (DetectionsState.charts.severity) DetectionsState.charts.severity.dispose();
        const chart = echarts.init(sevDom, 'dark', { backgroundColor: 'transparent' });
        DetectionsState.charts.severity = chart;

        const s = DetectionsState.severityStats;

        chart.setOption({
            tooltip: { trigger: 'axis', axisPointer: { type: 'shadow' } },
            legend: { data: ['Critical', 'High', 'Medium', 'Low'], textStyle: { color: '#94a3b8' } },
            grid: { left: '3%', right: '4%', bottom: '3%', containLabel: true },
            xAxis: { type: 'value', splitLine: { lineStyle: { color: 'rgba(255, 255, 255, 0.05)' } } },
            yAxis: { type: 'category', data: ['Alerts'] },
            series: [
                { name: 'Critical', type: 'bar', stack: 'total', color: '#f43f5e', data: [s.critical] },
                { name: 'High', type: 'bar', stack: 'total', color: '#f59e0b', data: [s.high] },
                { name: 'Medium', type: 'bar', stack: 'total', color: '#8b5cf6', data: [s.medium] },
                { name: 'Low', type: 'bar', stack: 'total', color: '#10b981', data: [s.low] }
            ]
        });
    }

    // 4. HTTP status profile pie
    const statusDom = document.getElementById("entHttpStatusChart");
    if (statusDom) {
        if (DetectionsState.charts.httpStatus) DetectionsState.charts.httpStatus.dispose();
        const chart = echarts.init(statusDom, 'dark', { backgroundColor: 'transparent' });
        DetectionsState.charts.httpStatus = chart;

        const sc = DetectionsState.httpStatusStats;

        chart.setOption({
            tooltip: { trigger: 'item' },
            series: [{
                name: 'HTTP Status Class',
                type: 'pie',
                radius: '60%',
                data: [
                    { value: sc['2xx'], name: '2xx Success', itemStyle: { color: '#10b981' } },
                    { value: sc['3xx'], name: '3xx Redirect', itemStyle: { color: '#3b82f6' } },
                    { value: sc['4xx'], name: '4xx Client Err', itemStyle: { color: '#f59e0b' } },
                    { value: sc['5xx'], name: '5xx Server Err', itemStyle: { color: '#f43f5e' } }
                ]
            }]
        });
    }

    // 5. 24x7 heatmap grid
    const heatmapDom = document.getElementById("entHeatmapChart");
    if (heatmapDom) {
        if (DetectionsState.charts.heatmap) DetectionsState.charts.heatmap.dispose();
        const chart = echarts.init(heatmapDom, 'dark', { backgroundColor: 'transparent' });
        DetectionsState.charts.heatmap = chart;

        // Initialize empty matrix
        const hours = Array.from({ length: 24 }, (_, i) => i + "h");
        const days = ['Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday', 'Sunday'];
        
        // Heatmap coordinate layout: [dayIndex, hourIndex, count]
        const dataMatrix = [];
        for (let d = 0; d < 7; d++) {
            for (let h = 0; h < 24; h++) {
                dataMatrix.push([d, h, 0]);
            }
        }

        // Fill data based on real logs timestamp
        DetectionsState.attacks.forEach(atk => {
            if (atk.timestamp) {
                const date = new Date(atk.timestamp);
                let day = date.getDay() - 1; // getDay() is 0 (Sun) - 6 (Sat)
                if (day === -1) day = 6;     // Remap Sun to index 6
                const hour = date.getHours();
                const cellIndex = day * 24 + hour;
                if (dataMatrix[cellIndex]) {
                    dataMatrix[cellIndex][2]++;
                }
            }
        });

        chart.setOption({
            tooltip: { position: 'top' },
            grid: { height: '70%', top: '10%' },
            xAxis: { type: 'category', data: hours, splitArea: { show: true } },
            yAxis: { type: 'category', data: days, splitArea: { show: true } },
            visualMap: {
                min: 0,
                max: 10,
                calculable: true,
                orient: 'horizontal',
                left: 'center',
                bottom: '0%',
                inRange: { color: ['rgba(0, 240, 255, 0.05)', 'rgba(0, 240, 255, 0.4)', '#f43f5e'] }
            },
            series: [{
                name: 'Threat Density',
                type: 'heatmap',
                data: dataMatrix,
                label: { show: false },
                emphasis: {
                    itemStyle: { shadowBlur: 10, shadowColor: 'rgba(0, 0, 0, 0.5)' }
                }
            }]
        });
    }
}

// Action button triggers: mark false positive
async function markAlertFalsePositive(attackId) {
    if (!confirm(`Mark alert ID ${attackId} as a False Positive?`)) return;
    try {
        const res = await fetch(`/api/detections/false-positive/${attackId}`, { method: 'POST' });
        const data = await res.json();
        if (data.success) {
            showNotificationToast("Alert flag updated successfully.", "success");
            // Reload details
            initEnterpriseDetections();
        } else {
            showNotificationToast("Failed to mark alert: " + data.error, "error");
        }
    } catch (e) {
        console.error("Failed to post false positive: ", e);
    }
}

// Action button triggers: block IP
async function blockAttackerIP(ip) {
    if (!confirm(`Are you sure you want to block the IP ${ip} on host firewalls?`)) return;
    try {
        const res = await fetch('/api/realtime/block', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ ip, actor: 'SOC Analyst' })
        });
        const data = await res.json();
        if (data.blocked) {
            showNotificationToast(`Firewall drop rules deployed for ${ip}.`, "success");
            initEnterpriseDetections();
        }
    } catch (e) {
        console.error("Failed to block IP: ", e);
    }
}

// Toast helper inside dashboard
function showNotificationToast(msg, type = "success") {
    const container = document.getElementById("toastContainer");
    if (!container) return;
    const el = document.createElement("div");
    el.className = `toast ${type === 'success' ? 'med' : 'crit'}`;
    el.innerHTML = `
        <div class="toast-title">${type === 'success' ? 'ℹ️ SYSTEM TELEMETRY' : '⚠️ SECURITY ALERT'}</div>
        <div class="toast-body">${msg}</div>
    `;
    container.appendChild(el);
    setTimeout(() => el.remove(), 4000);
}

// Handle real-time WebSockets events
function handleNewEnterpriseThreat(threat) {
    // If we're on the detections page view, update in real-time
    if (document.getElementById("view-enterprise-detections")?.classList.contains("active")) {
        // Prepend and reload stats
        DetectionsState.attacks.unshift(threat);
        if (DetectionsState.attacks.length > 2000) DetectionsState.attacks.pop();
        DetectionsState.total++;
        
        // Accumulate status, urls, and tactics in memory
        if (threat.url) DetectionsState.topUrls[threat.url] = (DetectionsState.topUrls[threat.url] || 0) + 1;
        if (threat.mitre_tactic) DetectionsState.mitreTactics[threat.mitre_tactic] = (DetectionsState.mitreTactics[threat.mitre_tactic] || 0) + 1;
        
        const hourStr = threat.timestamp ? threat.timestamp.slice(0, 13) : new Date().toISOString().slice(0, 13);
        DetectionsState.hourlyTrend[hourStr] = (DetectionsState.hourlyTrend[hourStr] || 0) + 1;
        
        const sev = threat.severity ? threat.severity.toLowerCase() : 'medium';
        if (sev in DetectionsState.severityStats) {
            DetectionsState.severityStats[sev]++;
        }
        
        renderDetectionsUI();
        initDetectionsCharts();
    }
}

// WebSocket listener hook
if (typeof socket !== 'undefined' && socket !== null) {
    socket.on('new_threat', threat => {
        handleNewEnterpriseThreat(threat);
    });
}
