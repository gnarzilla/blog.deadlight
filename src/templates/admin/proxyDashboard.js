// src/templates/admin/proxyDashboard.js - Improved version
import { renderTemplate } from '../base.js';

// src/templates/admin/proxyDashboard.js - Proxy dashboard template
export function proxyDashboardTemplate(data, user, config) {
  const { status, queue, federation, config: proxyConfig } = data;

  // Status indicators
  const connectedStatus = status.proxy_connected 
    ? '<span style="color: var(--status-healthy);">Connected</span>' 
    : '<span style="color: var(--status-error);">Disconnected</span>';
  
  const circuitStatus = status.circuit_state?.state || proxyConfig.circuitState?.state || 'UNKNOWN';
  const circuitColor = circuitStatus === 'CLOSED' 
    ? 'var(--status-healthy)' 
    : circuitStatus === 'OPEN' ? 'var(--status-error)' : 'var(--status-warning)';

  // Queue summary
  const queuedTotal = queue.status.queued_operations?.total || 0;
  const queueColor = queuedTotal > 0 ? 'var(--status-warning)' : 'var(--status-healthy)';

  // Domains table
  const domainsHtml = federation.connected_domains.length > 0 ? `
    <table style="width: 100%; border-collapse: collapse; margin-top: 1rem;">
      <thead>
        <tr style="border-bottom: 1px solid var(--border-color);">
          <th style="text-align: left; padding: 0.5rem;">Domain</th>
          <th style="text-align: left; padding: 0.5rem;">Trust Level</th>
          <th style="text-align: left; padding: 0.5rem;">Last Seen</th>
          <th style="text-align: left; padding: 0.5rem;">Actions</th>
        </tr>
      </thead>
      <tbody>
        ${federation.connected_domains.map(d => `
          <tr style="border-bottom: 1px solid var(--border-color);">
            <td style="padding: 0.5rem;">${d.domain}</td>
            <td style="padding: 0.5rem;">${d.trust_level}</td>
            <td style="padding: 0.5rem;">${new Date(d.last_seen).toLocaleString() || 'N/A'}</td>
            <td style="padding: 0.5rem;">
              <form method="POST" action="/admin/proxy/test-federation" style="display: inline;">
                <input type="hidden" name="domain" value="${d.domain}">
                <button type="submit" class="button edit-button">Test</button>
              </form>
              <form method="POST" action="/api/federation/remove" style="display: inline;">
                <input type="hidden" name="domain" value="${d.domain}">
                <button type="submit" class="button delete-button">Remove</button>
              </form>
            </td>
          </tr>
        `).join('')}
      </tbody>
    </table>
  ` : '<p>No connected domains.</p>';

  // Recommendations list
  const recommendationsHtml = status.recommendations ? `
    <ul style="margin: 1rem 0; padding-left: 1.5rem;">
      ${status.recommendations.map(rec => `<li>${rec}</li>`).join('')}
    </ul>
  ` : '';

  const proxyInfoHtml = `

     <div class="card" style="background: var(--card-bg); border: 1px solid var(--card-border); padding: 1rem; margin-bottom: 1rem;">
       <h2>Proxy Configuration</h2>
      <p><strong>Outbound Proxy URL:</strong> <code>${data.config.proxyUrl || '—'}</code></p>
       <p>
         <strong>Inbound URLs (other blogs to you):</strong><br>
        <code>${data.siteUrl}/.well-known/deadlight</code> – discovery<br>
        <code>${data.siteUrl}/api/federation/inbox</code> – inbox<br>
        <code>${data.siteUrl}/api/federation/outbox</code> – outbox
       </p>
       <p style="font-size:0.85rem; color:var(--text-secondary);">
         Share the three URLs above with any remote instance that wants to federate with you.
       </p>
     </div>
   `;

  // Recent activity (if available from getFederationRealtimeStatus)
  const recentActivityHtml = federation.recent_activity?.length > 0 ? `
    <table style="width: 100%; border-collapse: collapse; margin-top: 1rem;">
      <thead>
        <tr style="border-bottom: 1px solid var(--border-color);">
          <th style="text-align: left; padding: 0.5rem;">Type</th>
          <th style="text-align: left; padding: 0.5rem;">Title</th>
          <th style="text-align: left; padding: 0.5rem;">Domain</th>
          <th style="text-align: left; padding: 0.5rem;">Timestamp</th>
          <th style="text-align: left; padding: 0.5rem;">Status</th>
        </tr>
      </thead>
      <tbody>
        ${federation.recent_activity.map(act => `
          <tr style="border-bottom: 1px solid var(--border-color);">
            <td style="padding: 0.5rem;">${act.type}</td>
            <td style="padding: 0.5rem;">${act.title}</td>
            <td style="padding: 0.5rem;">${act.domain || 'N/A'}</td>
            <td style="padding: 0.5rem;">${new Date(act.timestamp).toLocaleString()}</td>
            <td style="padding: 0.5rem;">${act.status}</td>
          </tr>
        `).join('')}
      </tbody>
    </table>
  ` : '<p>No recent activity.</p>';

  return `
    <div class="container">
      <h1>Proxy Dashboard</h1>
      
      <!-- Proxy Status Card -->
      <div class="card" style="background: var(--card-bg); border: 1px solid var(--card-border); padding: 1rem; margin-bottom: 1rem;">
        <h2>Proxy Status</h2>
        <p>Connected: ${connectedStatus}</p>
        <p>Circuit Breaker: <span style="color: ${circuitColor};">${circuitStatus}</span> (${status.circuit_state?.failures || 0} failures)</p>
        <p>Last Check: ${status.last_check || 'N/A'}</p>
        ${recommendationsHtml}
      </div>
      
      <!-- Queue Status Card -->
      <div class="card" style="background: var(--card-bg); border: 1px solid var(--card-border); padding: 1rem; margin-bottom: 1rem;">
        <h2>Queue Status</h2>
        <p>Total Queued: <span style="color: ${queueColor};">${queuedTotal}</span></p>
        <p>Email Replies: ${queue.status.queued_operations?.email_replies || 0}</p>
        <p>Notifications: ${queue.status.queued_operations?.notifications || 0}</p>
        <p>Federation: ${queue.status.queued_operations?.federation || 0}</p>
        <p>Last Processing: ${queue.lastProcessing?.processed || 0} items (${queue.lastProcessing?.status || 'N/A'})</p>
      </div>
      
      <!-- Connected Domains Card -->
      <div class="card" style="background: var(--card-bg); border: 1px solid var(--card-border); padding: 1rem; margin-bottom: 1rem;">
        <h2>Connected Domains (${federation.connected_domains.length})</h2>
        ${domainsHtml}
      </div>
      
      <!-- Federation Activity Card -->
      <div class="card" style="background: var(--card-bg); border: 1px solid var(--card-border); padding: 1rem; margin-bottom: 1rem;">
        <h2>Recent Federation Activity</h2>
        ${recentActivityHtml}
        <p>Last Outgoing: ${federation.last_outgoing ? `${federation.last_outgoing.title} at ${new Date(federation.last_outgoing.timestamp).toLocaleString()}` : 'None'}</p>
        <p>Last Incoming: ${federation.last_incoming ? `${federation.last_incoming.title} at ${new Date(federation.last_incoming.timestamp).toLocaleString()}` : 'None'}</p>
      </div>
      ${proxyInfoHtml}
      <!-- Quick Actions -->
      <div class="card" style="background: var(--card-bg); border: 1px solid var(--card-border); padding: 1rem;">
        <h2>Quick Actions</h2>
        <div style="display: flex; gap: 0.5rem; flex-wrap: wrap; margin-top: 1rem;">
          <form method="POST" action="/admin/proxy/discover-domain" style="display: flex;">
            <input type="text" name="domain" placeholder="example.com" required style="margin-right: 0.5rem; padding: 0.5rem; border: 1px solid var(--input-border); background: var(--input-bg); color: var(--text-primary);">
            <button type="submit" class="button">Discover Domain</button>
          </form>
          <button onclick="fetch('/admin/proxy/test-blog-api', {method: 'POST'}).then(() => location.reload())" class="button">Test Blog API</button>
          <button onclick="fetch('/admin/proxy/test-email-api', {method: 'POST'}).then(() => location.reload())" class="button">Test Email API</button>
          <button onclick="fetch('/admin/proxy/test-federation', {method: 'POST'}).then(() => location.reload())" class="button">Test Federation</button>
          <button onclick="fetch('/admin/proxy/send-test-email', {method: 'POST'}).then(() => location.reload())" class="button">Send Test Email</button>
          <button onclick="fetch('/admin/process-queue', {method: 'POST'}).then(() => location.reload())" class="button">Process Queue</button>
          <button onclick="fetch('/admin/federation/sync', {method: 'POST'}).then(() => location.reload())" class="button">Sync Federation</button>
        </div>
      </div>
    </div>

    
  `;

    return renderTemplate('Proxy Server Dashboard', content, user, config);
}