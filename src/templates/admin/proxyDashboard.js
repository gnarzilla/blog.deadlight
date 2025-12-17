// src/templates/admin/proxyDashboard.js
import { renderTemplate } from '../base.js';

export function proxyDashboardTemplate(data, user, config) {
  const { status, queue, federation } = data || {};
  const PROXY_URL = config.proxyUrl;

  // Safe data extraction
  const connected = status?.proxy_connected ?? false;
  const circuitState = status?.circuit_state ?? { state: 'UNKNOWN', failures: 0 };
  const queuedTotal = queue?.status?.queued?.total ?? 0;
  const connectedDomains = federation?.connected_domains ?? [];
  const recentActivity = federation?.recent_activity ?? [];
  const recommendations = status?.recommendations ?? [];
  const lastProcessing = queue?.lastProcessing ?? null;

  // Status colors
  const connectedColor = connected ? 'green' : 'red';
  const circuitColor = circuitState.state === 'CLOSED' ? 'green' : circuitState.state === 'OPEN' ? 'red' : 'yellow';
  const queueColor = queuedTotal > 0 ? 'yellow' : 'green';

  // HTML sections
  const statusHtml = `
    <div class="card">
      <h3>Proxy Status</h3>
      <p>Configured Proxy URL: ${PROXY_URL ? `<a href="${PROXY_URL}" target="_blank">${PROXY_URL}</a>` : 'Not Configured'}</p>
      <p>Connected: <span style="color: ${connectedColor};">${connected ? 'Yes' : 'No'}</span></p>
      <p>Circuit Breaker: <span style="color: ${circuitColor};">${circuitState.state} (${circuitState.failures} failures)</span></p>
    </div>
  `;

  const queueHtml = `
    <div class="card">
      <h3>Queue Status</h3>
      <p>Total Queued: <span style="color: ${queueColor};">${queuedTotal}</span></p>
      <p>Last Processed: ${lastProcessing ? new Date(lastProcessing.timestamp).toLocaleString() : 'N/A'}</p>
      <button class="button" onclick="processQueue()">Process Now</button>
    </div>
  `;

  const domainsHtml = `
    <div class="card">
      <h3>Connected Domains (${connectedDomains.length || 0})</h3>
      ${connectedDomains.length > 0 ? `
        <table>
          <thead>
            <tr>
              <th>Domain</th>
              <th>Trust Level</th>
              <th>Last Seen</th>
              <th>Actions</th>
            </tr>
          </thead>
          <tbody>
            ${connectedDomains.map(d => `
              <tr>
                <td>${d.domain}</td>
                <td>${d.trust_level}</td>
                <td>${new Date(d.last_seen).toLocaleString()}</td>
                <td>
                  <button onclick="testDomain('${d.domain}')">Test</button>
                  <button onclick="removeDomain('${d.domain}')">Remove</button>
                </td>
              </tr>
            `).join('')}
          </tbody>
        </table>
      ` : '<p>No connected domains.</p>'}
      <form id="add-domain-form" style="margin-top: 1rem;">
        <input type="text" id="new-domain" placeholder="deadlight.boo" required />
        <button type="submit">Add Domain</button>
      </form>
    </div>
  `;

  const activityHtml = `
    <div class="card">
      <h3>Recent Federation Activity</h3>
      ${recentActivity.length > 0 ? `
        <ul>
          ${recentActivity.map(a => `
            <li>${a.type}: ${a.description} at ${new Date(a.timestamp).toLocaleString()}</li>
          `).join('')}
        </ul>
      ` : '<p>No recent activity.</p>'}
    </div>
  `;

  const recommendationsHtml = `
    <div class="card">
      <h3>Recommendations</h3>
      ${recommendations.length > 0 ? `
        <ul>
          ${recommendations.map(r => `<li>${r}</li>`).join('')}
        </ul>
      ` : '<p>All systems normal.</p>'}
    </div>
  `;

  const content = `
    <div class="container">
      <h1>Proxy Dashboard</h1>
        ${statusHtml}
        ${queueHtml}
        ${domainsHtml}
        ${activityHtml}
        ${recommendationsHtml}
    </div>

    <script>
      // Add domain
      document.getElementById('add-domain-form').onsubmit = async (e) => {
        e.preventDefault();
        const domain = document.getElementById('new-domain').value.trim();
        if (!domain) return;

        const res = await fetch('/api/federation/connect', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ domain, auto_discover: true })
        });
        if (res.ok) {
          location.reload();
        } else {
          alert('Error adding domain');
        }
      };

      // Process queue
      async function processQueue() {
        await fetch('/admin/process-queue', { method: 'POST' });
        location.reload();
      }

      // Test domain
      async function testDomain(domain) {
        await fetch('/admin/proxy/test-federation', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ domain })
        });
        alert('Test complete');
      }

      // Remove domain
      async function removeDomain(domain) {
        if (confirm('Remove domain?')) {
          await fetch('/api/federation/remove', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ domain })
          });
          location.reload();
        }
      }
    </script>

    <style>
      .container { max-width: 1200px; margin: 0 auto; padding: 1rem; }
      .card { background: var(--card-bg, #f8f9fa); border: 1px solid var(--border, #dee2e6); border-radius: 0.25rem; padding: 1rem; margin-bottom: 1rem; }
      .button { padding: 0.5rem 1rem; background: var(--primary, #007bff); color: white; border: none; cursor: pointer; border-radius: 0.25rem; }
      table { width: 100%; border-collapse: collapse; }
      th, td { padding: 0.5rem; border-bottom: 1px solid var(--border, #dee2e6); text-align: left; }
      ul { list-style-type: disc; padding-left: 1.5rem; }
    </style>
  `;

  return content;
}