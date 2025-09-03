// src/templates/admin/proxyDashboard.js - Clean template with external JS
import { renderTemplate } from '../base.js';

export function proxyDashboardTemplate(proxyData, user, config, queuedCount = 0) {
    const { status, queue, federation, config: proxyConfig, error } = proxyData;
    const proxyConnected = status?.proxy_connected || false;

    // Define serviceCards array
    const serviceCards = [
        {
            key: 'blog-api',
            title: 'Blog API',
            status: status?.blog_api ? 'running' : 'error',
            details: [
                status?.blog_api ? 'Version: 5.0.0' : 'Not responding',
                `Circuit: ${proxyConfig?.circuitState?.state || 'Unknown'}`
            ],
            testHandler: 'handleTestBlogApi'
        },
        {
            key: 'email-api', 
            title: 'Email API',
            status: status?.email_api ? 'running' : 'error',
            details: [
                `Queue Size: ${queue?.status?.queued_operations?.email || 0}`,
                `Last Processed: ${queue?.status?.last_processed || 'Never'}`
            ],
            testHandler: 'handleTestEmailApi'
        },
        {
            key: 'federation',
            title: 'Email-based Federation',
            status: federation?.status === 'online' ? 'healthy' : 'error',
            details: [
                'Protocol: Email Bridge',
                `Connected Domains: ${federation?.connected_domains?.length || 0}`,
                'Purpose: Instance-to-instance communication'
            ],
            testHandler: 'handleTestFederation'
        },
        {
            key: 'config',
            title: 'Configuration',
            status: proxyConnected ? 'healthy' : 'error',
            details: [
                `Proxy URL: ${proxyConfig?.proxyUrl || 'Not configured'}`,
                `Connection: ${proxyConnected ? 'Active' : 'Inactive'}`,
                status?.timestamp ? `Last Check: ${new Date(status.timestamp).toLocaleString()}` : 'No recent checks'
            ],
            testHandler: null
        },
        {
            key: 'federation-activity',
            title: 'Federation Activity',
            status: 'healthy',
            details: [
                'Protocol: Email Bridge',
                `Connected Domains: ${federation?.connected_domains?.length || 0}`,
                `Pending Posts: ${federation?.pending_posts || 0}`,
                'Recent Activity: Live monitoring'
            ],
            testHandler: 'handleDiscoverDomain'
        }
    ];

    const content = `
        <div class="proxy-dashboard">
            <header class="dashboard-header">
                <h2>Proxy Server Management</h2>
                <div class="status-indicator ${proxyConnected ? 'connected' : 'disconnected'}">
                    ${proxyConnected ? '🟢 Connected' : '🔴 Disconnected'}
                </div>
            </header>

            ${error ? `
                <section class="error-banner">
                    <h3>Connection Error</h3>
                    <p>${error}</p>
                    <button onclick="location.reload()">Retry Connection</button>
                </section>
            ` : ''}

            <section class="queue-status">
                <h3>Outbox Queue</h3>
                <p><span class="queue-count">${queue?.status?.queued_operations?.total || 0}</span> operations pending</p>
                <p class="last-check">Last check: <span class="last-check-time">${new Date().toLocaleTimeString()}</span></p>
                ${proxyConnected ? `
                    <button onclick="handleProcessQueue()" class="button">Process Queue Now</button>
                ` : `
                    <p class="queue-waiting">Waiting for proxy connection...</p>
                `}
            </section>

            <section class="proxy-services-grid">
                ${serviceCards.map(card => `
                    <div class="service-card" data-service="${card.key}">
                        <h3>${card.title}</h3>
                        <div class="service-status ${card.status === 'running' || card.status === 'healthy' ? 'healthy' : 'error'}">
                            Status: ${card.status || 'Unknown'}
                        </div>
                        <div class="service-details">
                            ${card.details.map(d => `<p>${d}</p>`).join('')}
                        </div>
                        ${card.testHandler ? `
                            <button onclick="${card.testHandler}()" class="button small-button">Test</button>
                        ` : `
                            <button onclick="location.reload()" class="button small-button">Refresh</button>
                        `}
                    </div>
                `).join('')}
            </section>

            <section class="federation-live-activity">
                <h3>Live Federation Activity</h3>
                <div class="federation-status">
                    <div class="trust-levels" id="trust-levels">
                        <p>Loading trust relationships...</p>
                    </div>
                </div>
                <div class="activity-stream" id="federation-activity">
                    <p>Connecting to federation activity stream...</p>
                </div>
            </section>

            <section class="proxy-actions">
                <h3>Quick Actions</h3>
                <div class="action-buttons">
                    <button onclick="handleSendTestEmail()" class="button">Send Test Email</button>
                    <button onclick="handleTestFederation()" class="button">Test Federation</button>
                    <button onclick="handleDiscoverDomain()" class="button">Discover New Domain</button>
                    <button onclick="location.reload()" class="button">Refresh All Status</button>
                </div>
            </section>
        </div>

        <script src="/admin/proxyDashboard.js"></script>
    `;

    return renderTemplate('Proxy Server Management', content, user, config);
}