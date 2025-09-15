// src/templates/admin/proxyDashboard.js - Enhanced version (continued)
// src/templates/admin/proxyDashboard.js - Enhanced version
import { renderTemplate } from '../base.js';

export function proxyDashboardTemplate(proxyData, user, config, queuedCount = 0) {
    const { status, queue, federation, config: proxyConfig, error } = proxyData;
    const proxyConnected = status?.proxy_connected || false;

    // Enhanced service cards with more details
    const serviceCards = [
        {
            key: 'blog-api',
            title: 'Blog API',
            icon: '📝',
            status: status?.blog_api ? 'running' : 'error',
            statusText: status?.blog_api ? 'Operational' : 'Offline',
            metrics: {
                'Version': '5.0.0',
                'Uptime': status?.blog_api?.uptime || 'Unknown',
                'Response Time': status?.blog_api?.responseTime || 'N/A'
            },
            circuitState: proxyConfig?.circuitState,
            testHandler: 'handleTestBlogApi'
        },
        {
            key: 'email-api', 
            title: 'Email Service',
            icon: '📧',
            status: status?.email_api ? 'running' : 'error',
            statusText: status?.email_api ? 'Processing' : 'Offline',
            metrics: {
                'Queued': queue?.status?.queued_operations?.email || 0,
                'Processed Today': queue?.stats?.processed_today || 0,
                'Failed': queue?.stats?.failed_today || 0
            },
            lastActivity: queue?.status?.last_processed,
            testHandler: 'handleTestEmailApi'
        },
        {
            key: 'federation',
            title: 'Federation Network',
            icon: '🌐',
            status: federation?.status === 'online' ? 'healthy' : 'warning',
            statusText: federation?.status === 'online' ? 'Connected' : 'Limited',
            metrics: {
                'Active Domains': federation?.connected_domains?.length || 0,
                'Pending Sync': federation?.pending_posts || 0,
                'Trust Level': federation?.trust_level || 'Verified'
            },
            connectedDomains: federation?.connected_domains || [],
            testHandler: 'handleTestFederation'
        }
    ];

    const content = `
        <div class="proxy-dashboard enhanced">
            <header class="dashboard-header">
                <div class="header-content">
                    <h2>Proxy Server Dashboard</h2>
                    <div class="connection-status">
                        <div class="status-indicator ${proxyConnected ? 'connected' : 'disconnected'}">
                            <span class="status-dot"></span>
                            ${proxyConnected ? 'Connected' : 'Disconnected'}
                        </div>
                        ${proxyConfig?.proxyUrl ? `
                            <span class="proxy-url">${proxyConfig.proxyUrl}</span>
                        ` : ''}
                    </div>
                </div>
                <div class="header-actions">
                    <button onclick="startLiveMonitoring()" class="button small ${proxyConnected ? '' : 'disabled'}">
                        <span id="monitor-status">▶</span> Live Monitor
                    </button>
                    <button onclick="location.reload()" class="button small">↻ Refresh</button>
                </div>
            </header>

            ${error ? `
                <div class="alert alert-error">
                    <strong>Connection Error:</strong> ${error}
                    <button onclick="retryConnection()" class="button small">Retry</button>
                </div>
            ` : ''}

            <!-- Real-time Metrics Dashboard -->
            <section class="metrics-grid">
                <div class="metric-card">
                    <h4>Queue Status</h4>
                    <div class="metric-value" id="queue-total">${queue?.status?.queued_operations?.total || 0}</div>
                    <div class="metric-label">Pending Operations</div>
                    <div class="metric-trend" id="queue-trend"></div>
                </div>
                
                <div class="metric-card">
                    <h4>Processing Rate</h4>
                    <div class="metric-value" id="process-rate">0</div>
                    <div class="metric-label">ops/min</div>
                    <div class="metric-trend" id="rate-trend"></div>
                </div>
                
                <div class="metric-card">
                    <h4>Federation Health</h4>
                    <div class="metric-value" id="fed-health">${federation?.connected_domains?.length || 0}</div>
                    <div class="metric-label">Active Connections</div>
                    <div class="metric-status ${federation?.status === 'online' ? 'healthy' : 'warning'}"></div>
                </div>
                
                <div class="metric-card">
                    <h4>Circuit Breaker</h4>
                    <div class="metric-value circuit-${proxyConfig?.circuitState?.state?.toLowerCase() || 'unknown'}">
                        ${proxyConfig?.circuitState?.state || 'Unknown'}
                    </div>
                    <div class="metric-label">
                        Failures: ${proxyConfig?.circuitState?.failures || 0}/${proxyConfig?.circuitState?.threshold || 5}
                    </div>
                </div>
            </section>

            <!-- Service Status Cards -->
            <section class="services-section">
                <h3>Service Status</h3>
                <div class="service-cards-grid">
                    ${serviceCards.map(card => `
                        <div class="service-card ${card.status}" data-service="${card.key}">
                            <div class="card-header">
                                <span class="service-icon">${card.icon}</span>
                                <h4>${card.title}</h4>
                                <span class="status-badge ${card.status}">${card.statusText}</span>
                            </div>
                            
                            <div class="card-metrics">
                                ${Object.entries(card.metrics).map(([key, value]) => `
                                    <div class="metric-row">
                                        <span class="metric-key">${key}:</span>
                                        <span class="metric-val">${value}</span>
                                    </div>
                                `).join('')}
                            </div>
                            
                            ${card.circuitState ? `
                                <div class="circuit-info">
                                    <span class="circuit-state ${card.circuitState.state?.toLowerCase()}">
                                        Circuit: ${card.circuitState.state}
                                    </span>
                                </div>
                            ` : ''}
                            
                            ${card.lastActivity ? `
                                <div class="last-activity">
                                    Last: ${new Date(card.lastActivity).toRelativeTime()}
                                </div>
                            ` : ''}
                            
                            <div class="card-actions">
                                ${card.testHandler ? `
                                    <button onclick="${card.testHandler}()" class="button small">Test</button>
                                ` : ''}
                                <button onclick="viewServiceDetails('${card.key}')" class="button small secondary">Details</button>
                            </div>
                        </div>
                    `).join('')}
                </div>
            </section>

            <!-- Live Activity Feed -->
            <section class="activity-section">
                <div class="section-header">
                    <h3>Live Activity Stream</h3>
                    <div class="stream-controls">
                        <select id="activity-filter" onchange="filterActivity(this.value)">
                            <option value="all">All Activity</option>
                            <option value="email">Email</option>
                            <option value="federation">Federation</option>
                            <option value="errors">Errors Only</option>
                        </select>
                        <button onclick="clearActivityLog()" class="button small">Clear</button>
                    </div>
                </div>
                
                <div class="activity-stream" id="activity-stream">
                    <div class="activity-placeholder">
                        Waiting for activity...
                    </div>
                </div>
            </section>

            <!-- Federation Management -->
            <section class="federation-section">
                <h3>Federation Network</h3>
                
                <div class="federation-grid">
                    <div class="connected-domains">
                        <h4>Connected Domains</h4>
                        <div class="domain-list" id="domain-list">
                            ${federation?.connected_domains?.length ? 
                                federation.connected_domains.map(domain => `
                                    <div class="domain-item">
                                        <span class="domain-name">${domain.domain}</span>
                                        <span class="domain-trust ${domain.trust_level}">${domain.trust_level}</span>
                                        <button onclick="manageDomain('${domain.domain}')" class="button tiny">Manage</button>
                                    </div>
                                `).join('') : 
                                '<p class="empty-state">No connected domains</p>'
                            }
                        </div>
                        <button onclick="handleDiscoverDomain()" class="button small">+ Add Domain</button>
                    </div>
                    
                    <div class="federation-stats">
                        <h4>Federation Stats</h4>
                        <div class="stats-grid">
                            <div class="stat">
                                <span class="stat-value">${federation?.stats?.posts_sent || 0}</span>
                                <span class="stat-label">Posts Sent</span>
                            </div>
                            <div class="stat">
                                <span class="stat-value">${federation?.stats?.posts_received || 0}</span>
                                <span class="stat-label">Posts Received</span>
                            </div>
                            <div class="stat">
                                <span class="stat-value">${federation?.stats?.comments_synced || 0}</span>
                                <span class="stat-label">Comments Synced</span>
                            </div>
                        </div>
                    </div>
                </div>
            </section>

            <!-- Action Panel -->
            <section class="actions-section">
                <h3>Management Actions</h3>
                <div class="action-grid">
                    <div class="action-group">
                        <h4>Queue Management</h4>
                        <button onclick="handleProcessQueue()" class="button ${!proxyConnected ? 'disabled' : ''}">
                            Process Queue Now
                        </button>
                        <button onclick="viewQueueDetails()" class="button secondary">View Queue Details</button>
                        <button onclick="clearFailedOperations()" class="button danger">Clear Failed</button>
                    </div>
                    
                    <div class="action-group">
                        <h4>Testing</h4>
                        <button onclick="handleSendTestEmail()" class="button">Send Test Email</button>
                        <button onclick="runHealthCheck()" class="button">Full Health Check</button>
                        <button onclick="testAllServices()" class="button">Test All Services</button>
                    </div>
                    
                    <div class="action-group">
                        <h4>Configuration</h4>
                        <button onclick="viewProxyConfig()" class="button">View Config</button>
                        <button onclick="resetCircuitBreaker()" class="button">Reset Circuit</button>
                        <button onclick="exportLogs()" class="button secondary">Export Logs</button>
                    </div>
                </div>
            </section>
        </div>

        <script src="/admin/proxyDashboard.js"></script>
        <script>
            // Add relative time formatting
            Date.prototype.toRelativeTime = function() {
                const seconds = Math.floor((new Date() - this) / 1000);
                if (seconds < 60) return seconds + 's ago';
                const minutes = Math.floor(seconds / 60);
                if (minutes < 60) return minutes + 'm ago';
                const hours = Math.floor(minutes / 60);
                if (hours < 24) return hours + 'h ago';
                return this.toLocaleDateString();
            };
            // Real-time activity monitoring
            let activitySocket = null;
            let activityBuffer = [];
            const MAX_ACTIVITY_ITEMS = 100;

            function startLiveMonitoring() {
            const monitorBtn = document.querySelector('#monitor-status');
            
            if (activitySocket) {
                // Stop monitoring
                activitySocket.close();
                activitySocket = null;
                monitorBtn.textContent = '▶';
                return;
            }
            
            // Start monitoring
            monitorBtn.textContent = '⏸';
            
            // Connect to EventSource for real-time updates
            const eventSource = new EventSource('/admin/proxy/status-stream');
            
            eventSource.onmessage = (event) => {
                const data = JSON.parse(event.data);
                updateDashboard(data);
                addActivityItem(data);
            };
            
            eventSource.onerror = (error) => {
                console.error('EventSource error:', error);
                monitorBtn.textContent = '▶';
            };
            
            activitySocket = eventSource;
            }

            function addActivityItem(data) {
                const stream = document.getElementById('activity-stream');
                const timestamp = new Date().toLocaleTimeString();
                
                const item = document.createElement('div');
                item.className = 'activity-item ' + (data.type || 'info');
                item.innerHTML = 
                    '<span class="activity-time">' + timestamp + '</span>' +
                    '<span class="activity-type">[' + (data.type || 'INFO').toUpperCase() + ']</span>' +
                    '<span class="activity-message">' + (data.message || '') + '</span>';
                
                // Remove placeholder if it exists
                const placeholder = stream.querySelector('.activity-placeholder');
                if (placeholder) placeholder.remove();
                
                // Add new item at top
                stream.insertBefore(item, stream.firstChild);
                
                // Keep buffer size limited
                while (stream.children.length > MAX_ACTIVITY_ITEMS) {
                    stream.removeChild(stream.lastChild);
                }
                }
                
                function updateDashboard(data) {
                // Update metrics
                if (data.queue) {
                    const queueTotal = document.getElementById('queue-total');
                    if (queueTotal) queueTotal.textContent = data.queue.total || 0;
                }
                
                if (data.federation) {
                    const fedHealth = document.getElementById('fed-health');
                    if (fedHealth) fedHealth.textContent = data.federation.connected || 0;
                }
                
                // Update service statuses
                if (data.services) {
                    Object.entries(data.services).forEach(function(entry) {
                    const service = entry[0];
                    const status = entry[1];
                    const card = document.querySelector('[data-service="' + service + '"]');
                    if (card) {
                        const statusBadge = card.querySelector('.status-badge');
                        if (statusBadge) {
                        statusBadge.textContent = status.operational ? 'Operational' : 'Offline';
                        statusBadge.className = 'status-badge ' + (status.operational ? 'healthy' : 'error');
                        }
                    }
                    });
                }
                }
            </script>
    `;

    return renderTemplate('Proxy Server Dashboard', content, user, config);
}