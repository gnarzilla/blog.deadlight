// src/templates/admin/proxyDashboard.js - Simplified version
import { renderTemplate } from '../base.js';

export function proxyDashboardTemplate(proxyData, user, config, queuedCount = 0) {
    const { status, queue, federation, config: proxyConfig, error } = proxyData;
    const proxyConnected = status?.proxy_connected || false;

    const content = `
        <div class="proxy-dashboard">
            <h1>Proxy Server Dashboard</h1>
            
            <!-- Connection Status -->
            <div class="section">
                <h2>Connection Status</h2>
                <p class="status-line">
                    Status: <strong>${proxyConnected ? 'Connected' : 'Disconnected'}</strong>
                    ${proxyConfig?.proxyUrl ? ` to ${proxyConfig.proxyUrl}` : ''}
                </p>
                ${error ? `<p class="error">Error: ${error}</p>` : ''}
                <button onclick="location.reload()" class="button">Refresh Status</button>
            </div>

            <!-- Service Status -->
            <div class="section">
                <h2>Services</h2>
                <table class="data-table">
                    <tr>
                        <th>Service</th>
                        <th>Status</th>
                        <th>Details</th>
                        <th>Actions</th>
                    </tr>
                    <tr>
                        <td>Blog API</td>
                        <td>${status?.blog_api ? 'Online' : 'Offline'}</td>
                        <td>Version 5.0.0</td>
                        <td><button onclick="handleTestBlogApi()" class="button small">Test</button></td>
                    </tr>
                    <tr>
                        <td>Email Service</td>
                        <td>${status?.email_api ? 'Online' : 'Offline'}</td>
                        <td>Queue: ${queue?.status?.queued_operations?.email || 0}</td>
                        <td><button onclick="handleTestEmailApi()" class="button small">Test</button></td>
                    </tr>
                    <tr>
                        <td>Federation</td>
                        <td>${federation?.status === 'online' ? 'Online' : 'Offline'}</td>
                        <td>Connected: ${federation?.connected_domains?.length || 0} domains</td>
                        <td><button onclick="handleTestFederation()" class="button small">Test</button></td>
                    </tr>
                </table>
            </div>

            <!-- Queue Status -->
            <div class="section">
                <h2>Queue Status</h2>
                <p>Total queued operations: <strong>${queue?.status?.queued_operations?.total || 0}</strong></p>
                <p>Email queue: ${queue?.status?.queued_operations?.email || 0}</p>
                <p>Federation queue: ${queue?.status?.queued_operations?.federation || 0}</p>
                ${queue?.status?.last_processed ? 
                    `<p>Last processed: ${new Date(queue.status.last_processed).toLocaleString()}</p>` : 
                    '<p>No recent processing</p>'
                }
                <div class="button-group">
                    <button onclick="handleProcessQueue()" class="button" ${!proxyConnected ? 'disabled' : ''}>
                        Process Queue Now
                    </button>
                    <button onclick="viewQueueDetails()" class="button">View Details</button>
                </div>
            </div>

            <!-- Federation Management -->
            <div class="section">
                <h2>Federation Network</h2>
                <h3>Connected Domains</h3>
                ${federation?.connected_domains?.length ? `
                    <table class="data-table">
                        <tr>
                            <th>Domain</th>
                            <th>Trust Level</th>
                            <th>Status</th>
                            <th>Actions</th>
                        </tr>
                        ${federation.connected_domains.map(domain => `
                            <tr>
                                <td>${domain.domain}</td>
                                <td>${domain.trust_level || 'Unknown'}</td>
                                <td>${domain.status || 'Active'}</td>
                                <td>
                                    <button onclick="testDomain('${domain.domain}')" class="button small">Test</button>
                                    <button onclick="removeDomain('${domain.domain}')" class="button small delete-button">Remove</button>
                                </td>
                            </tr>
                        `).join('')}
                    </table>
                ` : '<p>No connected domains</p>'}
                
                <h3>Add New Domain</h3>
                <form onsubmit="addFederationDomain(event)" class="inline-form">
                    <input type="text" id="new-domain" placeholder="example.com" required>
                    <button type="submit" class="button">Add Domain</button>
                </form>
                
                <h3>Federation Stats</h3>
                <p>Posts sent: ${federation?.stats?.posts_sent || 0}</p>
                <p>Posts received: ${federation?.stats?.posts_received || 0}</p>
                <p>Comments synced: ${federation?.stats?.comments_synced || 0}</p>
            </div>

            <!-- Testing Actions -->
            <div class="section">
                <h2>Testing & Maintenance</h2>
                <div class="button-group">
                    <button onclick="handleSendTestEmail()" class="button">Send Test Email</button>
                    <button onclick="runHealthCheck()" class="button">Health Check</button>
                    <button onclick="resetCircuitBreaker()" class="button">Reset Circuit Breaker</button>
                    <button onclick="clearFailedOperations()" class="button delete-button">Clear Failed Ops</button>
                </div>
            </div>

            <!-- Activity Log -->
            <div class="section">
                <h2>Recent Activity</h2>
                <div id="activity-log" class="activity-log">
                    <p>No recent activity</p>
                </div>
                <button onclick="clearActivityLog()" class="button small">Clear Log</button>
            </div>
        </div>

        <script>
            // Simple activity logging
            function logActivity(message, type = 'info') {
                const log = document.getElementById('activity-log');
                const time = new Date().toLocaleTimeString();
                const entry = document.createElement('p');
                entry.className = 'log-entry log-' + type;
                entry.textContent = '[' + time + '] ' + message;
                log.insertBefore(entry, log.firstChild);
                
                // Keep only last 20 entries
                while (log.children.length > 20) {
                    log.removeChild(log.lastChild);
                }
            }

            // Handler functions
            async function handleTestBlogApi() {
                try {
                    logActivity('Testing Blog API...', 'info');
                    const response = await fetch('/admin/proxy/test-blog-api', { method: 'POST' });
                    const result = await response.json();
                    logActivity('Blog API test: ' + (result.success ? 'Success' : 'Failed'), 
                               result.success ? 'success' : 'error');
                } catch (error) {
                    logActivity('Blog API test error: ' + error.message, 'error');
                }
            }

            async function handleTestEmailApi() {
                try {
                    logActivity('Testing Email API...', 'info');
                    const response = await fetch('/admin/proxy/test-email', { method: 'POST' });
                    const result = await response.json();
                    logActivity('Email API test: ' + (result.success ? 'Success' : 'Failed'), 
                               result.success ? 'success' : 'error');
                } catch (error) {
                    logActivity('Email API test error: ' + error.message, 'error');
                }
            }

            async function handleTestFederation() {
                try {
                    logActivity('Testing Federation...', 'info');
                    const response = await fetch('/admin/proxy/test-federation', { method: 'POST' });
                    const result = await response.json();
                    logActivity('Federation test: ' + (result.success ? 'Success' : 'Failed'), 
                               result.success ? 'success' : 'error');
                } catch (error) {
                    logActivity('Federation test error: ' + error.message, 'error');
                }
            }

            async function handleProcessQueue() {
                if (confirm('Process all queued operations now?')) {
                    try {
                        logActivity('Processing queue...', 'info');
                        const response = await fetch('/admin/proxy/process-queue', { method: 'POST' });
                        const result = await response.json();
                        logActivity('Queue processed: ' + result.processed + ' items', 'success');
                        setTimeout(() => location.reload(), 1000);
                    } catch (error) {
                        logActivity('Queue processing error: ' + error.message, 'error');
                    }
                }
            }

            async function handleSendTestEmail() {
                const email = prompt('Enter email address for test:');
                if (email) {
                    try {
                        logActivity('Sending test email to ' + email + '...', 'info');
                        const response = await fetch('/admin/proxy/send-test-email', {
                            method: 'POST',
                            headers: { 'Content-Type': 'application/json' },
                            body: JSON.stringify({ email })
                        });
                        const result = await response.json();
                        logActivity('Test email: ' + (result.success ? 'Sent' : 'Failed'), 
                                   result.success ? 'success' : 'error');
                    } catch (error) {
                        logActivity('Test email error: ' + error.message, 'error');
                    }
                }
            }

            async function addFederationDomain(event) {
                event.preventDefault();
                const domain = document.getElementById('new-domain').value;
                
                try {
                    logActivity('Adding domain ' + domain + '...', 'info');
                    const response = await fetch('/admin/proxy/add-federation-domain', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({ domain })
                    });
                    const result = await response.json();
                    if (result.success) {
                        logActivity('Domain ' + domain + ' added successfully', 'success');
                        setTimeout(() => location.reload(), 1000);
                    } else {
                        logActivity('Failed to add domain: ' + result.error, 'error');
                    }
                } catch (error) {
                    logActivity('Add domain error: ' + error.message, 'error');
                }
            }

            async function testDomain(domain) {
                try {
                    logActivity('Testing connection to ' + domain + '...', 'info');
                    const response = await fetch('/admin/proxy/test-federation-domain', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({ domain })
                    });
                    const result = await response.json();
                    logActivity('Domain test ' + domain + ': ' + (result.success ? 'Success' : 'Failed'), 
                               result.success ? 'success' : 'error');
                } catch (error) {
                    logActivity('Domain test error: ' + error.message, 'error');
                }
            }

            async function removeDomain(domain) {
                if (confirm('Remove federation with ' + domain + '?')) {
                    try {
                        const response = await fetch('/admin/proxy/remove-federation-domain', {
                            method: 'POST',
                            headers: { 'Content-Type': 'application/json' },
                            body: JSON.stringify({ domain })
                        });
                        const result = await response.json();
                        if (result.success) {
                            logActivity('Domain ' + domain + ' removed', 'success');
                            setTimeout(() => location.reload(), 1000);
                        }
                    } catch (error) {
                        logActivity('Remove domain error: ' + error.message, 'error');
                    }
                }
            }

            function viewQueueDetails() {
                window.location.href = '/admin/proxy/queue';
            }

            function clearActivityLog() {
                document.getElementById('activity-log').innerHTML = '<p>No recent activity</p>';
            }

            async function runHealthCheck() {
                try {
                    logActivity('Running health check...', 'info');
                    const response = await fetch('/admin/proxy/health-check');
                    const result = await response.json();
                    logActivity('Health check complete', 'success');
                    console.log('Health check results:', result);
                } catch (error) {
                    logActivity('Health check error: ' + error.message, 'error');
                }
            }

            async function resetCircuitBreaker() {
                if (confirm('Reset circuit breaker?')) {
                    try {
                        const response = await fetch('/admin/proxy/reset-circuit', { method: 'POST' });
                        const result = await response.json();
                        logActivity('Circuit breaker reset', 'success');
                        setTimeout(() => location.reload(), 1000);
                    } catch (error) {
                        logActivity('Reset error: ' + error.message, 'error');
                    }
                }
            }

            async function clearFailedOperations() {
                if (confirm('Clear all failed operations from queue?')) {
                    try {
                        const response = await fetch('/admin/proxy/clear-failed', { method: 'POST' });
                        const result = await response.json();
                        logActivity('Cleared ' + result.cleared + ' failed operations', 'success');
                        setTimeout(() => location.reload(), 1000);
                    } catch (error) {
                        logActivity('Clear failed error: ' + error.message, 'error');
                    }
                }
            }
        </script>
    `;

    return renderTemplate('Proxy Server Dashboard', content, user, config);
}