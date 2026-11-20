/**
 * DATACAT Tier 2 Central SaaS Observability Dashboard
 * Vanilla JavaScript (Zero External Dependencies)
 */

document.addEventListener("DOMContentLoaded", () => {
  // State
  let currentTab = "overview";
  let autoRefreshEnabled = true;
  let refreshTimer = null;
  let selectedTenant = "";
  let knownTenants = new Set();

  // Elements
  const tenantSelect = document.getElementById("tenant-select");
  const autoRefreshToggle = document.getElementById("auto-refresh-toggle");
  const refreshBtn = document.getElementById("refresh-btn");
  const lastUpdatedTs = document.getElementById("last-updated-ts");
  const modal = document.getElementById("detail-modal");
  const modalCloseBtn = document.getElementById("modal-close-btn");
  const modalTitle = document.getElementById("modal-title");
  const modalContent = document.getElementById("modal-content");
  const incidentBadge = document.getElementById("incident-badge-count");

  // Navigation handlers
  const navItems = document.querySelectorAll(".nav-item");
  navItems.forEach(item => {
    item.addEventListener("click", (e) => {
      e.preventDefault();
      const tab = item.getAttribute("data-tab");
      switchTab(tab);
    });
  });

  function switchTab(tabId) {
    currentTab = tabId;
    navItems.forEach(n => {
      if (n.getAttribute("data-tab") === tabId) {
        n.classList.add("active");
      } else {
        n.classList.remove("active");
      }
    });

    document.querySelectorAll(".tab-pane").forEach(pane => {
      pane.classList.remove("active");
    });
    const targetPane = document.getElementById(`tab-${tabId}`);
    if (targetPane) {
      targetPane.classList.add("active");
    }

    // Refresh active tab data
    fetchCurrentTabData();
  }
  window.switchTab = switchTab;

  // Auto-refresh controls
  autoRefreshToggle.addEventListener("change", (e) => {
    autoRefreshEnabled = e.target.checked;
    if (autoRefreshEnabled) {
      startAutoRefresh();
    } else {
      stopAutoRefresh();
    }
  });

  refreshBtn.addEventListener("click", () => {
    fetchCurrentTabData(true);
  });

  tenantSelect.addEventListener("change", (e) => {
    selectedTenant = e.target.value;
    fetchCurrentTabData(true);
  });

  // Modal close handlers
  modalCloseBtn.addEventListener("click", closeModal);
  modal.addEventListener("click", (e) => {
    if (e.target === modal) closeModal();
  });

  function openModal(title, htmlContent) {
    modalTitle.textContent = title;
    modalContent.innerHTML = htmlContent;
    modal.classList.remove("hidden");
  }

  function closeModal() {
    modal.classList.add("hidden");
  }

  // Formatting helpers
  function getQueryString() {
    return selectedTenant ? `?tenant_id=${encodeURIComponent(selectedTenant)}` : "";
  }

  function formatTime(isoStr) {
    if (!isoStr) return "--:--:--";
    try {
      const d = new Date(isoStr);
      return d.toISOString().replace("T", " ").substring(0, 19);
    } catch {
      return isoStr;
    }
  }

  function getHealthClass(status) {
    switch ((status || "").toUpperCase()) {
      case "EXCELLENT": return "badge-excellent";
      case "GOOD": return "badge-good";
      case "FAIR": return "badge-fair";
      case "POOR": return "badge-poor";
      default: return "badge-good";
    }
  }

  function getMetricFillClass(val, type) {
    if (type === "latency") {
      if (val >= 200) return "poor";
      if (val >= 100) return "fair";
      if (val >= 50) return "good";
      return "excellent";
    }
    if (val >= 90) return "poor";
    if (val >= 75) return "fair";
    if (val >= 60) return "good";
    return "excellent";
  }

  // Tenants loader
  async function loadTenants() {
    try {
      const res = await fetch("/api/v1/dashboard/tenants");
      if (!res.ok) return;
      const data = await res.json();
      (data.tenants || []).forEach(t => {
        if (!knownTenants.has(t)) {
          knownTenants.add(t);
          const opt = document.createElement("option");
          opt.value = t;
          opt.textContent = `Tenant: ${t}`;
          tenantSelect.appendChild(opt);
        }
      });
    } catch (err) {
      console.warn("Failed to load tenants:", err);
    }
  }

  // Data Fetchers
  async function fetchOverview() {
    try {
      const res = await fetch(`/api/v1/dashboard/overview${getQueryString()}`);
      if (!res.ok) return;
      const data = await res.json();

      // Top stat numbers
      document.getElementById("stat-total-collectors").textContent = data.total_collectors || 0;
      document.getElementById("stat-online-collectors").textContent = data.online_collectors || 0;
      document.getElementById("stat-offline-collectors").textContent = data.offline_collectors || 0;
      document.getElementById("stat-verified-events").textContent = data.verified_events || 0;
      document.getElementById("stat-total-events").textContent = data.total_events || 0;
      document.getElementById("stat-rejected-events").textContent = data.rejected_events || 0;
      document.getElementById("stat-active-incidents").textContent = data.active_incidents || 0;

      // Incident badge
      const incCount = data.active_incidents || 0;
      incidentBadge.textContent = incCount;
      if (incCount > 0) {
        incidentBadge.classList.remove("zero");
      } else {
        incidentBadge.classList.add("zero");
      }

      // Health Banner
      const banner = document.getElementById("health-banner");
      const bannerText = document.getElementById("health-banner-text");
      const bannerReason = document.getElementById("health-banner-reason");
      const staleBadge = document.getElementById("stale-alert-badge");

      banner.className = `health-banner banner-${(data.overall_health || "excellent").toLowerCase()}`;
      bannerText.textContent = data.overall_health || "UNKNOWN";
      bannerReason.textContent = data.overall_health_reason || "";

      if (data.overall_health === "POOR" && (data.overall_health_reason || "").toLowerCase().includes("stale")) {
        staleBadge.classList.remove("hidden");
      } else {
        staleBadge.classList.add("hidden");
      }

      // Load Mini Server List
      loadMiniServers();
      // Load Mini Verifications
      loadMiniVerifications();
    } catch (err) {
      console.error("Overview error:", err);
    }
  }

  async function loadMiniServers() {
    const container = document.getElementById("overview-server-list");
    try {
      const res = await fetch(`/api/v1/dashboard/infrastructure${getQueryString()}`);
      if (!res.ok) return;
      const data = await res.json();
      const servers = data.servers || [];

      if (servers.length === 0) {
        container.innerHTML = `<div class="empty-state">No verified telemetry received yet. Run Tier 1 collector to stream data.</div>`;
        return;
      }

      container.innerHTML = servers.slice(0, 4).map(s => `
        <div class="server-mini-item">
          <div>
            <strong>${s.server_id}</strong>
            <div class="server-meta-sub">Tenant: ${s.tenant_id} | CPU: ${s.metrics.cpu_usage}% | RAM: ${s.metrics.memory_usage}%</div>
          </div>
          <div style="text-align: right;">
            <span class="badge ${getHealthClass(s.health_status)}">${s.health_status}</span>
            <div class="server-meta-sub">${s.is_stale ? '<strong style="color:var(--health-poor);">STALE</strong>' : s.seconds_ago + 's ago'}</div>
          </div>
        </div>
      `).join("");
    } catch (err) {
      container.innerHTML = `<div class="empty-state">Failed to load server summaries.</div>`;
    }
  }

  async function loadMiniVerifications() {
    const tbody = document.getElementById("overview-verification-tbody");
    try {
      const res = await fetch(`/api/v1/dashboard/verifications${getQueryString()}&limit=5`);
      if (!res.ok) return;
      const data = await res.json();
      const records = data.verifications || [];

      if (records.length === 0) {
        tbody.innerHTML = `<tr><td colspan="6" class="text-center text-muted">No cryptographic verification records yet.</td></tr>`;
        return;
      }

      tbody.innerHTML = records.map(r => `
        <tr>
          <td class="code-font">${formatTime(r.verified_at_utc)}</td>
          <td><strong>${r.event_id}</strong></td>
          <td>${r.collector_id}</td>
          <td><span class="badge ${r.hash_matched ? 'badge-verified' : 'badge-failed'}">${r.hash_matched ? 'VALID' : 'MISMATCH'}</span></td>
          <td><span class="badge ${r.signature_valid ? 'badge-verified' : 'badge-failed'}">${r.signature_valid ? 'VALID' : 'INVALID'}</span></td>
          <td><span class="badge ${r.status === 'VERIFIED' ? 'badge-verified' : 'badge-failed'}">${r.status}</span></td>
        </tr>
      `).join("");
    } catch (err) {
      tbody.innerHTML = `<tr><td colspan="6" class="text-center">Error loading logs.</td></tr>`;
    }
  }

  async function fetchInfrastructure() {
    const container = document.getElementById("infrastructure-cards");
    try {
      const res = await fetch(`/api/v1/dashboard/infrastructure${getQueryString()}`);
      if (!res.ok) return;
      const data = await res.json();
      const servers = data.servers || [];

      if (servers.length === 0) {
        container.innerHTML = `<div class="empty-state">No monitored servers found for this scope.</div>`;
        return;
      }

      container.innerHTML = servers.map(s => {
        const m = s.metrics || {};
        const cpu = m.cpu_usage || 0;
        const mem = m.memory_usage || 0;
        const disk = m.disk_usage || 0;
        const lat = m.latency_ms || 0;

        return `
          <div class="server-card ${s.is_stale ? 'stale-border' : ''}">
            <div class="server-card-header">
              <div class="server-title-group">
                <h3>
                  <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="2" y="2" width="20" height="8" rx="2"/><rect x="2" y="14" width="20" height="8" rx="2"/></svg>
                  ${s.server_id}
                </h3>
                <div class="server-meta-sub">Tenant: <strong>${s.tenant_id}</strong> | Collector: ${s.collector_id}</div>
              </div>
              <span class="badge ${getHealthClass(s.health_status)}">${s.health_status}</span>
            </div>

            <!-- Health Reason -->
            <div style="font-size: 12px; color: var(--text-muted); margin-bottom: 14px;">
              ${s.health_reason}
            </div>

            <!-- CPU Metric Bar -->
            <div class="metric-bar-group">
              <div class="metric-bar-header">
                <span>CPU Usage</span>
                <strong>${cpu.toFixed(1)}%</strong>
              </div>
              <div class="metric-progress">
                <div class="metric-fill ${getMetricFillClass(cpu, 'cpu')}" style="width: ${Math.min(cpu, 100)}%;"></div>
              </div>
            </div>

            <!-- Memory Metric Bar -->
            <div class="metric-bar-group">
              <div class="metric-bar-header">
                <span>Memory (RAM)</span>
                <strong>${mem.toFixed(1)}%</strong>
              </div>
              <div class="metric-progress">
                <div class="metric-fill ${getMetricFillClass(mem, 'memory')}" style="width: ${Math.min(mem, 100)}%;"></div>
              </div>
            </div>

            <!-- Disk Metric Bar -->
            <div class="metric-bar-group">
              <div class="metric-bar-header">
                <span>Disk Space</span>
                <strong>${disk.toFixed(1)}%</strong>
              </div>
              <div class="metric-progress">
                <div class="metric-fill ${getMetricFillClass(disk, 'disk')}" style="width: ${Math.min(disk, 100)}%;"></div>
              </div>
            </div>

            <!-- Latency Metric -->
            <div class="metric-bar-group">
              <div class="metric-bar-header">
                <span>Network Latency</span>
                <strong>${lat.toFixed(1)} ms</strong>
              </div>
              <div class="metric-progress">
                <div class="metric-fill ${getMetricFillClass(lat, 'latency')}" style="width: ${Math.min((lat / 300) * 100, 100)}%;"></div>
              </div>
            </div>

            <div class="server-footer-info">
              <div>
                <span>Last Telemetry: <strong>${s.seconds_ago}s ago</strong></span>
                ${s.is_stale ? '<span class="badge-alert" style="margin-left: 6px;">STALE</span>' : ''}
              </div>
              <button class="btn-small" onclick="viewServerHistory('${s.server_id}')">Trend Sparkline</button>
            </div>
          </div>
        `;
      }).join("");
    } catch (err) {
      container.innerHTML = `<div class="empty-state">Error loading infrastructure telemetry.</div>`;
    }
  }

  async function fetchCollectors() {
    const tbody = document.getElementById("collectors-tbody");
    try {
      const res = await fetch(`/api/v1/dashboard/collectors${getQueryString()}`);
      if (!res.ok) return;
      const data = await res.json();
      const collectors = data.collectors || [];

      if (collectors.length === 0) {
        tbody.innerHTML = `<tr><td colspan="7" class="text-center text-muted">No collectors registered. Check config/collectors.yaml.</td></tr>`;
        return;
      }

      tbody.innerHTML = collectors.map(c => `
        <tr>
          <td><strong>${c.collector_id}</strong></td>
          <td>${c.tenant_id}</td>
          <td>
            <span class="badge ${c.status === 'ACTIVE' ? 'badge-excellent' : 'badge-poor'}">${c.status}</span>
          </td>
          <td>
            <span class="status-online">
              <span class="dot ${c.is_online ? 'green' : 'gray'}"></span>
              ${c.is_online ? 'Online' : 'Offline'} (${c.last_heartbeat_utc ? formatTime(c.last_heartbeat_utc) : 'Never'})
            </span>
          </td>
          <td class="code-font">${c.last_seen_seq}</td>
          <td><strong style="color:var(--health-excellent);">${c.accepted_events}</strong></td>
          <td><strong style="color:${c.failed_verifications > 0 ? 'var(--health-poor)' : 'var(--text-muted)'};">${c.failed_verifications}</strong></td>
        </tr>
      `).join("");
    } catch (err) {
      tbody.innerHTML = `<tr><td colspan="7" class="text-center">Error loading collectors.</td></tr>`;
    }
  }

  async function fetchVerifications() {
    const tbody = document.getElementById("verifications-tbody");
    try {
      const res = await fetch(`/api/v1/dashboard/verifications${getQueryString()}&limit=50`);
      if (!res.ok) return;
      const data = await res.json();
      const records = data.verifications || [];

      if (records.length === 0) {
        tbody.innerHTML = `<tr><td colspan="8" class="text-center text-muted">No verification audit records.</td></tr>`;
        return;
      }

      tbody.innerHTML = records.map(r => {
        const hashDisplay = r.receipt_hash ? `${r.receipt_hash.substring(0, 10)}...${r.receipt_hash.substring(58)}` : 'N/A';
        return `
          <tr>
            <td class="code-font">${formatTime(r.verified_at_utc)}</td>
            <td><strong>${r.event_id}</strong></td>
            <td>${r.collector_id}</td>
            <td class="code-font" title="${r.receipt_hash || ''}">${hashDisplay}</td>
            <td>
              <span class="check-tag ${r.structure_valid ? 'check-pass' : 'check-fail'}" title="Schema Structure">STR</span>
              <span class="check-tag ${r.collector_registered ? 'check-pass' : 'check-fail'}" title="Collector Registration">REG</span>
              <span class="check-tag ${r.tenant_matched ? 'check-pass' : 'check-fail'}" title="Tenant Association">TNT</span>
              <span class="check-tag ${r.hash_matched ? 'check-pass' : 'check-fail'}" title="SHA-256 Payload Hash">HSH</span>
              <span class="check-tag ${r.signature_valid ? 'check-pass' : 'check-fail'}" title="Ed25519 Signature">SIG</span>
              <span class="check-tag ${r.duplicate_check_passed ? 'check-pass' : 'check-fail'}" title="Duplicate Check">DUP</span>
              <span class="check-tag ${r.sequence_valid ? 'check-pass' : 'check-fail'}" title="Sequence Monotonicity">SEQ</span>
            </td>
            <td><span class="badge ${r.status === 'VERIFIED' ? 'badge-verified' : 'badge-failed'}">${r.status}</span></td>
            <td><small style="color:${r.failure_reason ? 'var(--health-poor)' : 'var(--text-muted)'};">${r.failure_reason || 'Cryptographically Verified'}</small></td>
            <td>
              <button class="btn-small" onclick='viewVerificationAudit(${JSON.stringify(r).replace(/'/g, "&apos;")})'>Inspect</button>
            </td>
          </tr>
        `;
      }).join("");
    } catch (err) {
      tbody.innerHTML = `<tr><td colspan="8" class="text-center">Error loading verification records.</td></tr>`;
    }
  }

  async function fetchEvents() {
    const tbody = document.getElementById("events-tbody");
    const serverFilter = document.getElementById("event-server-filter").value.trim();
    const limit = document.getElementById("event-limit-select").value;

    let url = `/api/v1/dashboard/events${getQueryString()}&limit=${limit}`;
    if (serverFilter) {
      url += `&server_id=${encodeURIComponent(serverFilter)}`;
    }

    try {
      const res = await fetch(url);
      if (!res.ok) return;
      const data = await res.json();
      const events = data.events || [];

      if (events.length === 0) {
        tbody.innerHTML = `<tr><td colspan="9" class="text-center text-muted">No telemetry events match query criteria.</td></tr>`;
        return;
      }

      tbody.innerHTML = events.map(e => {
        const m = e.metrics || {};
        return `
          <tr>
            <td class="code-font">${formatTime(e.timestamp_utc)}</td>
            <td><strong>${e.event_id}</strong></td>
            <td>${e.server_id}</td>
            <td>${e.tenant_id}</td>
            <td><strong style="color:${m.cpu_usage >= 90 ? 'var(--health-poor)' : 'inherit'};">${(m.cpu_usage || 0).toFixed(1)}%</strong></td>
            <td><strong style="color:${m.memory_usage >= 90 ? 'var(--health-poor)' : 'inherit'};">${(m.memory_usage || 0).toFixed(1)}%</strong></td>
            <td>${(m.disk_usage || 0).toFixed(1)}%</td>
            <td>${(m.latency_ms || 0).toFixed(1)} ms</td>
            <td><span class="badge ${getHealthClass(e.health_status)}">${e.health_status}</span></td>
          </tr>
        `;
      }).join("");
    } catch (err) {
      tbody.innerHTML = `<tr><td colspan="9" class="text-center">Error loading telemetry history.</td></tr>`;
    }
  }

  async function fetchIncidents() {
    const container = document.getElementById("incidents-container");
    const anomaliesTbody = document.getElementById("anomalies-tbody");

    // 1. Fetch Correlated Incidents
    try {
      const res = await fetch(`/api/v1/dashboard/incidents${getQueryString()}`);
      if (res.ok) {
        const data = await res.json();
        const incidents = data.incidents || [];

        incidentBadge.textContent = incidents.length;
        if (incidents.length > 0) {
          incidentBadge.classList.remove("zero");
        } else {
          incidentBadge.classList.add("zero");
        }

        if (incidents.length === 0) {
          container.innerHTML = `
            <div class="card" style="text-align: center; padding: 48px;">
              <div style="color: var(--health-excellent); font-size: 36px; margin-bottom: 12px;">
                <svg width="48" height="48" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/></svg>
              </div>
              <h3>All Infrastructure Operating Normally</h3>
              <p class="section-desc">Zero anomalies or security violations detected. Telemetry streams are cryptographically validated.</p>
            </div>
          `;
        } else {
          container.innerHTML = incidents.map(inc => {
            const sevClass = (inc.severity || "medium").toLowerCase();
            const recList = (inc.recommendations || []).map(r => `<li>${r}</li>`).join("");
            const contribSignals = Array.isArray(inc.contributing_metrics) 
              ? inc.contributing_metrics.map(m => `<span class="check-tag check-fail">${m}</span>`).join(" ")
              : JSON.stringify(inc.contributing_metrics);
            const hState = inc.health_state || (sevClass === 'critical' ? 'POOR' : (sevClass === 'high' ? 'FAIR' : 'GOOD'));
            const hBadgeClass = hState.toLowerCase();

            return `
              <div class="incident-card ${sevClass}">
                <div class="incident-card-top">
                  <div>
                    <span class="badge badge-${sevClass === 'critical' ? 'poor' : (sevClass === 'high' ? 'fair' : 'good')}" style="margin-bottom: 6px;">
                      ${inc.severity}
                    </span>
                    <span class="badge badge-${hBadgeClass}" style="margin-bottom: 6px; margin-left: 6px;">
                      Health: ${hState}
                    </span>
                    <div class="incident-title">${inc.title}</div>
                    <div class="incident-meta">
                      Incident: <strong class="code-font">${inc.incident_id}</strong> |
                      Affected Host: <strong>${inc.server_id}</strong> |
                      Tenant: ${inc.tenant_id} |
                      Correlated Anomalies: <strong>${inc.correlated_anomalies_count || 1}</strong> |
                      Detected: ${formatTime(inc.detection_timestamp)}
                    </div>
                  </div>
                  <span class="code-font" style="color:var(--text-dim);">${inc.incident_id}</span>
                </div>

                <div style="margin-bottom: 10px; font-size: 12px;">
                  <span style="color: var(--text-muted);">Contributing Signals:</span> ${contribSignals}
                </div>

                <div class="incident-explanation">
                  <strong>Reason & Statistical Diagnosis:</strong> ${inc.explanation}
                </div>

                <div class="incident-recommendations">
                  <h4>Recommended Investigation & Operational Remediation Steps:</h4>
                  <ol>${recList || '<li>Perform standard host diagnostic audit.</li>'}</ol>
                </div>
              </div>
            `;
          }).join("");
        }
      }
    } catch (err) {
      container.innerHTML = `<div class="empty-state">Error evaluating incidents.</div>`;
    }

    // 2. Fetch Unified AIOps Decisions Stream (A. Statistical, B. ML, C. Combined)
    const decisionsContainer = document.getElementById("aiops-decisions-container");
    if (decisionsContainer) {
      try {
        const resD = await fetch(`/api/v1/aiops/decisions${getQueryString()}&limit=20`);
        if (resD.ok) {
          const dataD = await resD.json();
          const decisions = dataD.decisions || [];
          if (decisions.length === 0) {
            decisionsContainer.innerHTML = `
              <div class="card" style="text-align: center; padding: 32px;">
                <p class="section-desc">No unified AIOps decisions recorded yet. Verified telemetry events will appear here with statistical baseline, Logistic Regression probability, and fused decision status.</p>
              </div>
            `;
          } else {
            decisionsContainer.innerHTML = decisions.map(d => {
              const decClass = (d.final_anomaly_decision || "normal").toLowerCase();
              const sev = d.severity || "NORMAL";
              const sevBadge = sev === "CRITICAL" ? "poor" : (sev === "HIGH" ? "fair" : (sev === "MEDIUM" ? "good" : "excellent"));
              
              // A. Statistical Rows
              const scores = d.statistical_scores || {};
              const statRows = Object.keys(scores).map(m => {
                const s = scores[m] || {};
                const isAnom = s.is_anomaly || false;
                return `
                  <tr>
                    <td class="metric-name">${m}</td>
                    <td>${s.current_value !== undefined ? s.current_value : '--'}</td>
                    <td>${s.rolling_median !== undefined && s.rolling_median !== null ? s.rolling_median : '--'}</td>
                    <td>${s.mad !== undefined && s.mad !== null ? s.mad : '--'}</td>
                    <td>${s.modified_zscore !== undefined && s.modified_zscore !== null ? s.modified_zscore : '--'}</td>
                    <td><span class="check-tag ${isAnom ? 'check-fail' : 'check-pass'}">${isAnom ? 'ANOMALY' : 'NORMAL'}</span></td>
                  </tr>
                `;
              }).join("");

              // B. ML values
              const probPercent = (Number(d.logistic_regression_probability || 0) * 100).toFixed(1);
              const mlPred = d.logistic_regression_prediction === 1 ? "ANOMALY" : "NORMAL";
              const mlBadge = d.logistic_regression_prediction === 1 ? "check-fail" : "check-pass";

              // C. Signals
              const signals = Array.isArray(d.contributing_signals) && d.contributing_signals.length > 0
                ? d.contributing_signals.map(sig => `<span class="check-tag check-fail">${sig}</span>`).join(" ")
                : '<span class="text-muted">None (nominal)</span>';

              const pCount = d.persistence_status?.persistence_count || 0;
              const isWarm = d.persistence_status?.is_warmup ? ' (Warm-up)' : '';

              return `
                <div class="decision-card ${decClass}">
                  <div class="decision-card-header">
                    <div>
                      <strong style="color:#fff; font-size:14px;">Host: ${d.server_id}</strong> &nbsp;
                      <span class="code-font" style="color:var(--text-muted); font-size:12px;">Event: ${d.event_id}</span> &nbsp;
                      <span class="badge badge-${d.health_state ? d.health_state.toLowerCase() : 'good'}">Health: ${d.health_state || 'GOOD'}</span>
                    </div>
                    <div style="font-size:12px; color:var(--text-dim); font-family:var(--font-mono);">
                      ${formatTime(d.timestamp_utc)}
                    </div>
                  </div>

                  <div class="decision-grid-3col">
                    <!-- A. Statistical Analysis -->
                    <div class="decision-col-box">
                      <div class="decision-col-title">
                        <span>A. Statistical Analysis</span>
                        <span class="badge badge-${d.statistical_status === 'ANOMALY' ? 'poor' : 'good'}">${d.statistical_status}</span>
                      </div>
                      <table class="stat-subtable">
                        <thead>
                          <tr>
                            <th>Metric</th>
                            <th>Value</th>
                            <th>Median</th>
                            <th>MAD</th>
                            <th>Mod-Z</th>
                            <th>Status</th>
                          </tr>
                        </thead>
                        <tbody>
                          ${statRows || '<tr><td colspan="6" class="text-center text-muted">No statistical metrics</td></tr>'}
                        </tbody>
                      </table>
                    </div>

                    <!-- B. ML Analysis -->
                    <div class="decision-col-box">
                      <div class="decision-col-title">
                        <span>B. ML Analysis (Logistic Reg)</span>
                        <span class="code-font" style="font-size:10px;">v${d.model_version || '1.0.0'}</span>
                      </div>
                      <div style="font-size:12px; margin-bottom:6px;">
                        Anomaly Probability: <strong style="font-size:14px; color:${probPercent >= 50 ? 'var(--health-poor)' : 'var(--health-excellent)'}">${probPercent}%</strong>
                      </div>
                      <div style="font-size:12px; margin-bottom:6px;">
                        Classification: <span class="check-tag ${mlBadge}">${mlPred}</span>
                      </div>
                      <div style="font-size:12px; margin-bottom:6px; color:var(--text-muted);">
                        Decision Threshold: <strong>0.50</strong>
                      </div>
                      <div style="font-size:12px; color:var(--text-muted);">
                        Model: <strong>Pure-Python Sigmoid</strong>
                      </div>
                    </div>

                    <!-- C. Combined Decision -->
                    <div class="decision-col-box">
                      <div class="decision-col-title">
                        <span>C. Combined Decision</span>
                        <span class="badge badge-${sevBadge}">${sev}</span>
                      </div>
                      <div style="font-size:12px; margin-bottom:6px;">
                        Decision: <strong style="color:#fff; font-size:13px;">${d.final_anomaly_decision}</strong>
                      </div>
                      <div style="font-size:12px; margin-bottom:6px;">
                        Persistence: <strong>Count = ${pCount}${isWarm}</strong>
                      </div>
                      <div style="font-size:12px; margin-bottom:6px;">
                        Signals: ${signals}
                      </div>
                      <button class="btn-sm" style="margin-top:4px;" onclick='viewAIOpsDecisionAudit(${JSON.stringify(d).replace(/'/g, "&#39;")})'>
                        View Decision Audit
                      </button>
                    </div>
                  </div>

                  <div class="incident-explanation" style="margin-bottom:0;">
                    <strong>Decision Explanation:</strong> ${d.explanation || 'Verified operational event evaluated nominal.'}
                  </div>
                </div>
              `;
            }).join("");
          }
        }
      } catch (errD) {
        decisionsContainer.innerHTML = `<div class="empty-state">Error loading AIOps decisions stream.</div>`;
      }
    }

    // 3. Fetch Statistical Anomalies Stream
    if (anomaliesTbody) {
      try {
        const resA = await fetch(`/api/v1/anomalies${getQueryString()}&limit=50`);
        if (resA.ok) {
          const dataA = await resA.json();
          const anomalies = dataA.anomalies || [];
          if (anomalies.length === 0) {
            anomaliesTbody.innerHTML = `<tr><td colspan="8" class="text-center text-muted">No metric anomalies detected. All observed telemetry aligns with expected baselines.</td></tr>`;
          } else {
            anomaliesTbody.innerHTML = anomalies.map(a => `
              <tr>
                <td class="code-font">${formatTime(a.detection_timestamp)}</td>
                <td class="code-font"><strong>${a.anomaly_id}</strong></td>
                <td><strong>${a.server_id}</strong></td>
                <td><span class="check-tag check-fail">${a.metric_name}</span></td>
                <td><strong>${a.observed_value}</strong></td>
                <td>${a.expected_baseline}</td>
                <td><span class="badge badge-${a.severity === 'CRITICAL' ? 'poor' : (a.severity === 'HIGH' ? 'fair' : 'good')}">${a.severity}</span></td>
                <td><small>${a.explanation}</small></td>
              </tr>
            `).join("");
          }
        }
      } catch (errA) {
        anomaliesTbody.innerHTML = `<tr><td colspan="8" class="text-center">Error loading anomalies stream.</td></tr>`;
      }
    }
  }

  // Interactive Inspection Modal
  window.viewAIOpsDecisionAudit = function(record) {
    const jsonStr = JSON.stringify(record, null, 2);
    const sev = record.severity || "NORMAL";
    const sevBadge = sev === "CRITICAL" ? "poor" : (sev === "HIGH" ? "fair" : (sev === "MEDIUM" ? "good" : "excellent"));
    const content = `
      <div style="margin-bottom: 16px;">
        <p><strong>Decision ID:</strong> <span class="code-font">${record.decision_id}</span></p>
        <p><strong>Event ID:</strong> <span class="code-font">${record.event_id}</span> (Host: <strong>${record.server_id}</strong>)</p>
        <p><strong>Combined Status:</strong> <span class="badge badge-${sevBadge}">${record.final_anomaly_decision} (${sev})</span></p>
        <p><strong>Observation Time:</strong> ${record.timestamp_utc}</p>
        <p style="margin-top:8px; line-height:1.5;"><strong>Explanation:</strong> ${record.explanation}</p>
      </div>
      <h4 style="margin-bottom: 8px; color: var(--text-muted);">Unified AIOps Audit Details (Sanitized, Zero PHI):</h4>
      <div class="json-view">${jsonStr}</div>
    `;
    openModal(`AIOps Decision Audit: ${record.decision_id}`, content);
  };

  window.viewVerificationAudit = function(record) {
    const jsonStr = JSON.stringify(record, null, 2);
    const content = `
      <div style="margin-bottom: 16px;">
        <p><strong>Event ID:</strong> ${record.event_id}</p>
        <p><strong>Collector:</strong> ${record.collector_id} (Tenant: ${record.tenant_id})</p>
        <p><strong>Verification Status:</strong> <span class="badge ${record.status === 'VERIFIED' ? 'badge-verified' : 'badge-failed'}">${record.status}</span></p>
        <p><strong>Timestamp:</strong> ${record.verified_at_utc}</p>
        ${record.failure_reason ? `<p style="color:var(--health-poor); margin-top:8px;"><strong>Failure Reason:</strong> ${record.failure_reason}</p>` : ''}
      </div>
      <h4 style="margin-bottom: 8px; color: var(--text-muted);">Sanitized Verification Audit Details:</h4>
      <div class="json-view">${jsonStr}</div>
    `;
    openModal(`Cryptographic Audit: ${record.event_id}`, content);
  };

  window.viewServerHistory = async function(serverId) {
    openModal(`Server Trend: ${serverId}`, `<div class="empty-state">Loading metric history points...</div>`);
    try {
      const res = await fetch(`/api/v1/dashboard/servers/${encodeURIComponent(serverId)}/history${getQueryString()}&limit=20`);
      if (!res.ok) {
        modalContent.innerHTML = `<div class="empty-state">Could not load historical metrics.</div>`;
        return;
      }
      const data = await res.json();
      const points = data.history || [];

      if (points.length < 2) {
        modalContent.innerHTML = `<div class="empty-state">Insufficient history points to render sparkline (needs >= 2 events). Current points: ${points.length}</div>`;
        return;
      }

      // Generate Native SVG Sparkline
      const width = 580;
      const height = 140;
      const padding = 20;

      const cpuPoints = points.map((p, idx) => {
        const x = padding + (idx / (points.length - 1)) * (width - 2 * padding);
        const y = height - padding - ((p.metrics.cpu_usage || 0) / 100) * (height - 2 * padding);
        return `${x.toFixed(1)},${y.toFixed(1)}`;
      }).join(" ");

      const memPoints = points.map((p, idx) => {
        const x = padding + (idx / (points.length - 1)) * (width - 2 * padding);
        const y = height - padding - ((p.metrics.memory_usage || 0) / 100) * (height - 2 * padding);
        return `${x.toFixed(1)},${y.toFixed(1)}`;
      }).join(" ");

      const svgHtml = `
        <div style="margin-bottom: 12px; display:flex; justify-content:space-between; font-size:12px;">
          <span><strong style="color:#3b82f6;">— CPU Usage (%)</strong></span>
          <span><strong style="color:#10b981;">— Memory Usage (%)</strong></span>
          <span>Sample Points: ${points.length}</span>
        </div>
        <svg class="sparkline-svg" viewBox="0 0 ${width} ${height}">
          <!-- Grid lines -->
          <line x1="${padding}" y1="${padding}" x2="${width - padding}" y2="${padding}" stroke="#334155" stroke-dasharray="2" />
          <line x1="${padding}" y1="${height/2}" x2="${width - padding}" y2="${height/2}" stroke="#334155" stroke-dasharray="2" />
          <line x1="${padding}" y1="${height - padding}" x2="${width - padding}" y2="${height - padding}" stroke="#475569" />

          <!-- Polylines -->
          <polyline fill="none" stroke="#3b82f6" stroke-width="2.5" points="${cpuPoints}" />
          <polyline fill="none" stroke="#10b981" stroke-width="2.5" points="${memPoints}" />
        </svg>
        <div style="font-size:11px; color:var(--text-dim); margin-top:8px; display:flex; justify-content:space-between;">
          <span>Oldest: ${formatTime(points[0].timestamp_utc)}</span>
          <span>Latest: ${formatTime(points[points.length - 1].timestamp_utc)}</span>
        </div>
      `;
      modalContent.innerHTML = svgHtml;
    } catch (err) {
      modalContent.innerHTML = `<div class="empty-state">Error plotting sparkline.</div>`;
    }
  };

  // Event filter handlers
  const eventServerInput = document.getElementById("event-server-filter");
  const eventLimitSelect = document.getElementById("event-limit-select");
  if (eventServerInput) {
    eventServerInput.addEventListener("input", debounce(() => fetchEvents(), 300));
  }
  if (eventLimitSelect) {
    eventLimitSelect.addEventListener("change", () => fetchEvents());
  }

  function debounce(fn, ms) {
    let timer;
    return function(...args) {
      clearTimeout(timer);
      timer = setTimeout(() => fn.apply(this, args), ms);
    };
  }

  // Master fetcher based on current tab
  async function fetchCurrentTabData(isManual = false) {
    const now = new Date();
    lastUpdatedTs.textContent = now.toTimeString().substring(0, 8) + " UTC";

    // Always fetch overview stats to keep header & badge in sync
    await fetchOverview();

    // Tab-specific fetch
    switch (currentTab) {
      case "infrastructure":
        await fetchInfrastructure();
        break;
      case "collectors":
        await fetchCollectors();
        break;
      case "verifications":
        await fetchVerifications();
        break;
      case "events":
        await fetchEvents();
        break;
      case "incidents":
        await fetchIncidents();
        break;
    }
  }

  function startAutoRefresh() {
    stopAutoRefresh();
    refreshTimer = setInterval(() => {
      fetchCurrentTabData();
    }, 5000);
  }

  function stopAutoRefresh() {
    if (refreshTimer) {
      clearInterval(refreshTimer);
      refreshTimer = null;
    }
  }

  // Initial load
  loadTenants();
  fetchCurrentTabData();
  startAutoRefresh();
});
