// src/templates/admin/proxyDashboard.js - Clean version without emojis
import { renderTemplate } from '../base.js';

// src/templates/admin/proxyDashboard.js - with inline JavaScript
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
                `Recent Activity: Live monitoring`
            ],
            testHandler: 'handleTestFederation'
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
                <div class="activity-stream" id="federation-activity">
                    <p>Connecting to federation activity stream...</p>
                </div>
            </section>

            <section class="proxy-actions">
                <h3>Quick Actions</h3>
                <div class="action-buttons">
                    <button onclick="handleSendTestEmail()" class="button">Send Test Email</button>
                    <button onclick="handleTestFederation()" class="button">Test Federation</button>
                    <button onclick="location.reload()" class="button">Refresh All Status</button>
                </div>
            </section>
        </div>

        <script>
        (function() {
            'use strict';
            
            console.log('Proxy Dashboard JavaScript initializing...');

            async function fetchJson(path, options = {}) {
                const response = await fetch(path, {
                    ...options,
                    headers: {
                        'Content-Type': 'application/json',
                        ...options.headers
                    }
                });
                
                if (!response.ok) {
                    const errorText = await response.text().catch(() => 'Unknown error');
                    throw new Error(\`\${response.status}: \${errorText}\`);
                }
                
                return await response.json();
            }

            async function performAction(path, options = {}, successMessage) {
                showLoading(options.loadingMessage || 'Working...');
                
                try {
                    const result = await fetchJson(path, options);
                    hideLoading();
                    
                    if (result.success) {
                        alert(successMessage || result.message || 'Success!');
                        setTimeout(() => location.reload(), 1000);
                    } else {
                        alert('Failed: ' + (result.error || 'Operation failed'));
                    }
                    
                    return result;
                } catch (error) {
                    hideLoading();
                    alert('Error: ' + error.message);
                    throw error;
                }
            }

            function showLoading(message = 'Loading...') {
                let loader = document.getElementById('loading-indicator');
                if (!loader) {
                    loader = document.createElement('div');
                    loader.id = 'loading-indicator';
                    loader.style.cssText = 'position: fixed; top: 0; left: 0; right: 0; bottom: 0; background: rgba(0,0,0,0.5); display: flex; align-items: center; justify-content: center; z-index: 2000; color: white; font-size: 18px;';
                    document.body.appendChild(loader);
                }
                loader.textContent = message;
                loader.style.display = 'flex';
            }

            function hideLoading() {
                const loader = document.getElementById('loading-indicator');
                if (loader) loader.style.display = 'none';
            }

            // Global action handlers
            window.handleProcessQueue = () => performAction('/admin/process-outbox', {
                method: 'POST',
                loadingMessage: 'Processing queue...'
            }, 'Queue processed successfully');

            window.handleTestBlogApi = () => performAction('/admin/proxy/test-blog-api', {
                loadingMessage: 'Testing Blog API...'
            }, 'Blog API test completed');

            window.handleTestEmailApi = () => performAction('/admin/proxy/test-email-api', {
                loadingMessage: 'Testing Email API...'
            }, 'Email API test completed');

            window.handleTestFederation = () => performAction('/admin/proxy/test-federation', {
                loadingMessage: 'Testing Federation...'
            }, 'Federation test completed');

            window.handleSendTestEmail = async () => {
                const email = prompt('Enter test email address:');
                if (!email || !email.includes('@')) {
                    alert('Please enter a valid email address');
                    return;
                }
                
                await performAction('/admin/proxy/send-test-email', {
                    method: 'POST',
                    body: JSON.stringify({ email }),
                    loadingMessage: 'Sending test email...'
                }, \`Test email sent to \${email}\`);
            };

            console.log('Proxy Dashboard JavaScript ready');
        })();
        </script>
    `;

    return renderTemplate('Proxy Server Management', content, user, config);
}