// src/templates/admin/proxyDashboard.js

export function proxyDashboardTemplate(data, user, config) {
  // Extract data with fallbacks
  const { 
    status = {}, 
    queue = {}, 
    federation = {}, 
    csrfToken = '' 
  } = data || {};

  // 1. Status Logic
  const PROXY_URL = config.proxyUrl || '';
  const isConnected = status.proxy_connected ?? false;
  
  // Circuit Breaker Logic
  const circuitState = status.circuit_state || { state: 'UNKNOWN', failures: 0 };
  let circuitClass = 'neutral';
  if (circuitState.state === 'CLOSED') circuitClass = 'success'; 
  if (circuitState.state === 'OPEN') circuitClass = 'danger';     
  if (circuitState.state === 'HALF_OPEN') circuitClass = 'warning';

  // Queue Logic
  const queuedTotal = queue.status?.queued?.total ?? 0;
  // Handle nested object structure safely or fallback to timestamp
  const lastProcessing = queue.lastProcessing 
    ? new Date(queue.lastProcessing.timestamp || queue.lastProcessing).toLocaleString() 
    : 'Never';

  // Federation Data
  const connectedDomains = federation.connected_domains || [];
  const recentActivity = federation.recent_activity || [];
  const recommendations = status.recommendations || [];

  const content = `
    <div class="admin-header">
      <h2>Proxy Node Status</h2>
      <div class="admin-actions">
        <a href="/admin" class="button outline">← Back to Dash</a>
        ${PROXY_URL ? `<a href="${PROXY_URL}/api/health" target="_blank" class="button outline">Ping Proxy</a>` : ''}
      </div>
    </div>

    <!-- 1. HEADS UP DISPLAY (HUD) -->
    <div class="stats-grid">
      
      <!-- Connection Card -->
      <div class="stat-card ${isConnected ? 'success-border' : 'danger-border'}">
        <span class="stat-label">Uplink Status</span>
        <span class="stat-value">${isConnected ? 'ONLINE' : 'OFFLINE'}</span>
        <span class="stat-desc">
           ${PROXY_URL ? new URL(PROXY_URL).hostname : 'No Proxy Configured'}
        </span>
      </div>

      <!-- Circuit Breaker Card -->
      <div class="stat-card ${circuitClass}-border">
        <span class="stat-label">Circuit Breaker</span>
        <span class="stat-value">${circuitState.state}</span>
        <span class="stat-desc">${circuitState.failures} failures detected</span>
      </div>

      <!-- Queue Card -->
      <div class="stat-card ${queuedTotal > 0 ? 'warning-border' : ''}">
        <span class="stat-label">Outbox Queue</span>
        <span class="stat-value">${queuedTotal}</span>
        <span class="stat-desc">Last run: ${lastProcessing}</span>
      </div>

    </div>

    ${recommendations.length > 0 ? `
    <div class="alert-box warning">
      <strong>System Recommendations:</strong>
      <ul>
        ${recommendations.map(r => `<li>${r}</li>`).join('')}
      </ul>
    </div>
    ` : ''}

    <hr class="divider">

    <!-- 2. QUEUE MANAGEMENT -->
    <div class="dashboard-section">
      <div class="section-header">
        <h3><span class="icon">⇄</span> Message Queue</h3>
        <form action="/admin/process-queue" method="POST">
          <input type="hidden" name="csrf_token" value="${csrfToken}">
          <button type="submit" class="button">Force Process Now ↻</button>
        </form>
      </div>
      
      ${queuedTotal === 0 ? '<p class="text-muted">Queue is clear.</p>' : `
        <p>There are <strong>${queuedTotal}</strong> items waiting to be sent.</p>
      `}
    </div>

    <!-- 3. FEDERATION DIRECTORY -->
    <div class="dashboard-section">
      <h3><span class="icon">🛡</span> Trusted Domains (${connectedDomains.length})</h3>
      
      <div class="table-responsive">
        <table class="data-table">
          <thead>
            <tr>
              <th>Domain</th>
              <th>Trust Level</th>
              <th>Last Seen</th>
              <th style="text-align:right">Actions</th>
            </tr>
          </thead>
          <tbody>
            ${connectedDomains.map(d => `
              <tr>
                <td><strong>${d.domain}</strong></td>
                <td><span class="badge ${d.trust_level}">${d.trust_level}</span></td>
                <td><small>${new Date(d.last_seen).toLocaleString()}</small></td>
                <td style="text-align:right">
                  <div class="button-group">
                    <form action="/admin/proxy/test-federation" method="POST" style="display:inline">
                      <input type="hidden" name="csrf_token" value="${csrfToken}">
                      <input type="hidden" name="domain" value="${d.domain}">
                      <button type="submit" class="button small outline">Test</button>
                    </form>

                    <form action="/api/federation/remove" method="POST" style="display:inline" onsubmit="return confirm('Disconnect from ${d.domain}?');">
                      <input type="hidden" name="csrf_token" value="${csrfToken}">
                      <input type="hidden" name="domain" value="${d.domain}">
                      <button type="submit" class="button small danger">Remove</button>
                    </form>
                  </div>
                </td>
              </tr>
            `).join('')}
            ${connectedDomains.length === 0 ? '<tr><td colspan="4" class="text-center">No active federation peers.</td></tr>' : ''}
          </tbody>
        </table>
      </div>

      <!-- Add Domain Form -->
      <details class="admin-details" style="margin-top: 1rem;">
        <summary>+ Connect New Domain</summary>
        <form action="/api/federation/connect" method="POST" class="inline-form">
          <input type="hidden" name="csrf_token" value="${csrfToken}">
          <input type="text" name="domain" placeholder="example.deadlight.boo" required>
          <label>
            <input type="checkbox" name="auto_discover" checked> Auto-Discover
          </label>
          <button type="submit">Connect</button>
        </form>
      </details>
    </div>

    <!-- 4. RECENT ACTIVITY LOG -->
    <div class="dashboard-section">
      <h3><span class="icon">terminal</span> Activity Log</h3>
      <div class="terminal-window">
        <ul>
        ${recentActivity.length > 0 ? recentActivity.map(a => `
          <li>
            <span class="log-time">[${new Date(a.timestamp).toLocaleTimeString()}]</span>
            <span class="log-type">[${a.type}]</span>
            ${a.title || 'Unknown Action'} 
            <span class="text-muted">(${a.domain || 'system'})</span>
          </li>
        `).join('') : '<li class="text-muted">No recent activity logged.</li>'}
        </ul>
      </div>
    </div>
  `;

  return content;
}