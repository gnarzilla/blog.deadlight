// src/templates/admin/proxyDashboard.js - Improved version
import { renderTemplate } from '../base.js';

export function proxyDashboardTemplate(proxyData, user, config, queuedCount = 0) {
    const { status, queue, federation, config: proxyConfig, error } = proxyData;
    const proxyConnected = status?.proxy_connected || false;
    
    // Safely extract metrics with defaults
    const metrics = proxyData.metrics || {};
    const protocols = metrics.protocols || {};

    const content = `
        <div class="proxy-dashboard">
            <h1>Proxy Server Dashboard</h1>
            
            <!-- Connection Status -->
            <div class="section">
                <h2>Connection Status</h2>
                <div class="status-indicator ${proxyConnected ? 'connected' : 'disconnected'}">
                    <span class="status-dot"></span>
                    <span class="status-text">
                        Status: <strong>${proxyConnected ? 'Connected' : 'Disconnected'}</strong>
                        ${proxyConfig?.proxyUrl ? ` to ${proxyConfig.proxyUrl}` : ''}
                    </span>
                </div>
                ${error ? `<div class="error-message"><strong>Error:</strong> ${error}</div>` : ''}
                <div class="button-group">
                    <button onclick="location.reload()" class="button">Refresh Status</button>
                    <button onclick="refreshMetrics()" class="button secondary">Refresh Metrics</button>
                </div>
            </div>

            <!-- Real-time Proxy Statistics -->
            <div class="section">
                <h2>Proxy Server Metrics</h2>
                <div class="metrics-grid">
                    <div class="metric-card">
                        <h3>Active Connections</h3>
                        <div class="metric-value" id="active-connections">${metrics.active_connections || 0}</div>
                    </div>
                    <div class="metric-card">
                        <h3>Total Connections</h3>
                        <div class="metric-value" id="total-connections">${metrics.total_connections || 0}</div>
                    </div>
                    <div class="metric-card">
                        <h3>Bandwidth Used</h3>
                        <div class="metric-value" id="bandwidth-metric">
                            ${metrics.bytes_transferred ? formatBytes(metrics.bytes_transferred) : '0 B'}
                        </div>
                    </div>
                    <div class="metric-card">
                        <h3>Uptime</h3>
                        <div class="metric-value" id="uptime-metric">
                            ${metrics.uptime ? formatUptime(metrics.uptime) : '0s'}
                        </div>
                    </div>
                </div>
                
                <!-- Protocol breakdown -->
                <h3>Protocol Usage</h3>
                <div class="table-container">
                    <table class="data-table">
                        <thead>
                            <tr>
                                <th>Protocol</th>
                                <th>Active</th>
                                <th>Total</th>
                                <th>Bytes</th>
                            </tr>
                        </thead>
                        <tbody id="protocol-table">
                            ${Object.keys(protocols).length > 0 ? 
                                Object.entries(protocols).map(([protocol, stats]) => `
                                    <tr>
                                        <td><strong>${protocol.toUpperCase()}</strong></td>
                                        <td>${stats.active || 0}</td>
                                        <td>${stats.total || 0}</td>
                                        <td>${formatBytes(stats.bytes || 0)}</td>
                                    </tr>
                                `).join('') : 
                                '<tr><td colspan="4" class="no-data">No protocol data available</td></tr>'
                            }
                        </tbody>
                    </table>
                </div>
            </div>

            <!-- Service Status -->
            <div class="section">
                <h2>Services</h2>
                <div class="table-container">
                    <table class="data-table">
                        <thead>
                            <tr>
                                <th>Service</th>
                                <th>Status</th>
                                <th>Details</th>
                                <th>Actions</th>
                            </tr>
                        </thead>
                        <tbody>
                            <tr>
                                <td><strong>Blog API</strong></td>
                                <td>
                                    <span class="status-badge ${status?.blog_api ? 'online' : 'offline'}">
                                        ${status?.blog_api ? 'Online' : 'Offline'}
                                    </span>
                                </td>
                                <td>Version ${metrics.blog_version || '5.0.0'}</td>
                                <td><button onclick="handleTestBlogApi()" class="button small">Test</button></td>
                            </tr>
                            <tr>
                                <td><strong>Email Service</strong></td>
                                <td>
                                    <span class="status-badge ${status?.email_api ? 'online' : 'offline'}">
                                        ${status?.email_api ? 'Online' : 'Offline'}
                                    </span>
                                </td>
                                <td>Queue: ${queue?.status?.queued_operations?.email || 0}</td>
                                <td><button onclick="handleTestEmailApi()" class="button small">Test</button></td>
                            </tr>
                            <tr>
                                <td><strong>Federation</strong></td>
                                <td>
                                    <span class="status-badge ${federation?.status === 'online' ? 'online' : 'offline'}">
                                        ${federation?.status === 'online' ? 'Online' : 'Offline'}
                                    </span>
                                </td>
                                <td>Connected: ${federation?.connected_domains?.length || 0} domains</td>
                                <td><button onclick="handleTestFederation()" class="button small">Test</button></td>
                            </tr>
                        </tbody>
                    </table>
                </div>
            </div>

            <!-- Queue Status -->
            <div class="section">
                <h2>Queue Status</h2>
                <div class="queue-stats">
                    <div class="queue-stat">
                        <span class="stat-label">Total Operations:</span>
                        <span class="stat-value" id="queue-total">${queue?.status?.queued_operations?.total || 0}</span>
                    </div>
                    <div class="queue-stat">
                        <span class="stat-label">Email Queue:</span>
                        <span class="stat-value">${queue?.status?.queued_operations?.email || 0}</span>
                    </div>
                    <div class="queue-stat">
                        <span class="stat-label">Federation Queue:</span>
                        <span class="stat-value">${queue?.status?.queued_operations?.federation || 0}</span>
                    </div>
                </div>
                ${queue?.status?.last_processed ? 
                    `<p><strong>Last processed:</strong> ${new Date(queue.status.last_processed).toLocaleString()}</p>` : 
                    '<p class="no-data">No recent processing</p>'
                }
                <div class="button-group">
                    <button onclick="handleProcessQueue()" class="button" ${!proxyConnected ? 'disabled' : ''}>
                        Process Queue Now
                    </button>
                    <button onclick="viewQueueDetails()" class="button secondary">View Details</button>
                </div>
            </div>

            <!-- Federation Management -->
            <div class="section">
                <h2>Federation Network</h2>
                <h3>Connected Domains</h3>
                ${federation?.connected_domains?.length ? `
                    <div class="table-container">
                        <table class="data-table">
                            <thead>
                                <tr>
                                    <th>Domain</th>
                                    <th>Trust Level</th>
                                    <th>Status</th>
                                    <th>Actions</th>
                                </tr>
                            </thead>
                            <tbody>
                                ${federation.connected_domains.map(domain => `
                                    <tr>
                                        <td><strong>${domain.domain}</strong></td>
                                        <td>
                                            <span class="trust-level ${domain.trust_level?.toLowerCase() || 'unknown'}">
                                                ${domain.trust_level || 'Unknown'}
                                            </span>
                                        </td>
                                        <td>
                                            <span class="status-badge ${domain.status === 'Active' ? 'online' : 'offline'}">
                                                ${domain.status || 'Active'}
                                            </span>
                                        </td>
                                        <td>
                                            <button onclick="testDomain('${domain.domain}')" class="button small">Test</button>
                                            <button onclick="removeDomain('${domain.domain}')" class="button small delete-button">Remove</button>
                                        </td>
                                    </tr>
                                `).join('')}
                            </tbody>
                        </table>
                    </div>
                ` : '<p class="no-data">No connected domains</p>'}
                
                <h3>Add New Domain</h3>
                <form onsubmit="addFederationDomain(event)" class="inline-form">
                    <input type="text" id="new-domain" placeholder="example.com" required>
                    <button type="submit" class="button">Add Domain</button>
                </form>
                
                <h3>Federation Stats</h3>
                <div class="federation-stats">
                    <div class="stat-item">
                        <span class="stat-number">${federation?.stats?.posts_sent || 0}</span>
                        <span class="stat-label">Posts Sent</span>
                    </div>
                    <div class="stat-item">
                        <span class="stat-number">${federation?.stats?.posts_received || 0}</span>
                        <span class="stat-label">Posts Received</span>
                    </div>
                    <div class="stat-item">
                        <span class="stat-number">${federation?.stats?.comments_synced || 0}</span>
                        <span class="stat-label">Comments Synced</span>
                    </div>
                </div>
            </div>

            <!-- Testing Actions -->
            <div class="section">
                <h2>Testing & Maintenance</h2>
                <div class="button-grid">
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
                    <p class="no-data">No recent activity</p>
                </div>
                <button onclick="clearActivityLog()" class="button small secondary">Clear Log</button>
            </div>
        </div>

        <script>
            // Configuration
            const CONFIG = {
                PROXY_BASE_URL: '${proxyConfig?.proxyUrl || ''}',
                API_BASE_URL: '${config?.baseUrl || ''}',
                REFRESH_INTERVAL: 30000, // 30 seconds
                MAX_LOG_ENTRIES: 20
            };

            // Helper functions
            function formatBytes(bytes) {
                if (!bytes || bytes === 0) return '0 B';
                const k = 1024;
                const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
                const i = Math.floor(Math.log(bytes) / Math.log(k));
                return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
            }

            function formatUptime(seconds) {
                if (!seconds || seconds < 60) return Math.floor(seconds || 0) + 's';
                if (seconds < 3600) return Math.floor(seconds / 60) + 'm ' + Math.floor(seconds % 60) + 's';
                if (seconds < 86400) {
                    const hours = Math.floor(seconds / 3600);
                    const minutes = Math.floor((seconds % 3600) / 60);
                    return hours + 'h ' + minutes + 'm';
                }
                const days = Math.floor(seconds / 86400);
                const hours = Math.floor((seconds % 86400) / 3600);
                return days + 'd ' + hours + 'h';
            }

            // Activity logging
            function logActivity(message, type = 'info') {
                const log = document.getElementById('activity-log');
                if (log.querySelector('.no-data')) {
                    log.innerHTML = '';
                }
                
                const time = new Date().toLocaleTimeString();
                const entry = document.createElement('div');
                entry.className = 'log-entry log-' + type;
                entry.innerHTML = '<span class="log-time">[' + time + ']</span> ' + message;
                log.insertBefore(entry, log.firstChild);
                
                // Keep only last MAX_LOG_ENTRIES entries
                while (log.children.length > CONFIG.MAX_LOG_ENTRIES) {
                    log.removeChild(log.lastChild);
                }
            }

            // API call helper
            async function apiCall(endpoint, options = {}) {
                const baseUrl = endpoint.startsWith('/api/') ? CONFIG.API_BASE_URL : CONFIG.PROXY_BASE_URL;
                const url = baseUrl + endpoint;
                
                try {
                    const response = await fetch(url, {
                        headers: {
                            'Content-Type': 'application/json',
                            ...options.headers
                        },
                        credentials: 'include', // Important: include cookies for auth
                        ...options
                    });
                    
                    if (!response.ok) {
                        let errorMessage = 'HTTP ' + response.status + ': ' + response.statusText;
                        
                        // Try to get more detailed error from response
                        try {
                            const errorData = await response.json();
                            if (errorData.error) {
                                errorMessage = errorData.error;
                            }
                        } catch (e) {
                            // Response wasn't JSON, use status text
                        }
                        
                        // Handle specific status codes
                        if (response.status === 401) {
                            errorMessage = 'Authentication required - please log in again';
                            // Optionally redirect to login
                            // window.location.href = '/login';
                        } else if (response.status === 403) {
                            errorMessage = 'Access denied - insufficient permissions';
                        }
                        
                        throw new Error(errorMessage);
                    }
                    
                    return await response.json();
                } catch (error) {
                    console.error('API call failed:', endpoint, error);
                    throw error;
                }
            }

            // Metrics refresh function
            async function refreshMetrics() {
                try {
                    logActivity('Refreshing metrics...', 'info');
                    
                    const metrics = await apiCall('/api/metrics');
                    
                    // Update metric displays
                    const updates = [
                        { id: 'active-connections', value: metrics.active_connections || 0 },
                        { id: 'total-connections', value: metrics.total_connections || 0 },
                        { id: 'bandwidth-metric', value: formatBytes(metrics.bytes_transferred || 0) },
                        { id: 'uptime-metric', value: formatUptime(metrics.uptime || 0) },
                        { id: 'queue-total', value: metrics.queue_total || 0 }
                    ];
                    
                    updates.forEach(update => {
                        const element = document.getElementById(update.id);
                        if (element) {
                            element.textContent = update.value;
                        }
                    });
                    
                    // Update protocol table if protocols data exists
                    if (metrics.protocols) {
                        updateProtocolTable(metrics.protocols);
                    }
                    
                    logActivity('Metrics refreshed successfully', 'success');
                } catch (error) {
                    logActivity('Failed to refresh metrics: ' + error.message, 'error');
                }
            }
            
            function updateProtocolTable(protocols) {
                const tbody = document.getElementById('protocol-table');
                if (!tbody) return;
                
                const rows = Object.entries(protocols).map(([protocol, stats]) => {
                    return '<tr>' +
                        '<td><strong>' + protocol.toUpperCase() + '</strong></td>' +
                        '<td>' + (stats.active || 0) + '</td>' +
                        '<td>' + (stats.total || 0) + '</td>' +
                        '<td>' + formatBytes(stats.bytes || 0) + '</td>' +
                    '</tr>';
                }).join('');
                
                tbody.innerHTML = rows || '<tr><td colspan="4" class="no-data">No protocol data available</td></tr>';
            }

            // Handler functions
            async function addFederationDomain(event) {
                event.preventDefault();
                const domain = document.getElementById('new-domain').value.trim();
                
                if (!domain) return;
                
                try {
                    logActivity('Adding domain ' + domain + '...', 'info');
                    
                    const result = await apiCall('/api/federation/connect', {
                        method: 'POST',
                        body: JSON.stringify({
                            domain: domain,
                            auto_discover: true
                        })
                    });
                    
                    if (result.success) {
                        logActivity('Domain ' + domain + ' added successfully', 'success');
                        document.getElementById('new-domain').value = '';
                        setTimeout(() => location.reload(), 1000);
                    } else {
                        logActivity('Failed to add domain ' + domain + ': ' + (result.error || 'Unknown error'), 'error');
                    }
                } catch (error) {
                    logActivity('Add domain error: ' + error.message, 'error');
                }
            }

            async function testDomain(domain) {
                try {
                    logActivity('Testing connection to ' + domain + '...', 'info');
                    
                    // Try HTTPS first, then HTTP if that fails
                    let testUrl = '/api/federation/test/' + encodeURIComponent(domain);
                    let result;
                    
                    try {
                        result = await apiCall(testUrl);
                    } catch (httpsError) {
                        // If HTTPS fails, log and try HTTP
                        console.log('HTTPS test failed, trying HTTP:', httpsError.message);
                        logActivity('HTTPS test failed, trying HTTP...', 'warning');
                        
                        // You might need a different endpoint for HTTP testing
                        testUrl = '/api/federation/test/' + encodeURIComponent(domain) + '?protocol=http';
                        result = await apiCall(testUrl);
                    }
                    
                    logActivity('Domain test ' + domain + ': ' + (result.status === 'verified' ? 'Success' : 'Failed'), 
                            result.status === 'verified' ? 'success' : 'error');
                } catch (error) {
                    logActivity('Domain test error: ' + error.message, 'error');
                }
            }

            async function removeDomain(domain) {
                if (confirm('Remove federation with ' + domain + '?')) {
                    try {
                        logActivity('Removing domain ' + domain + '...', 'info');
                        // Implement when you have the endpoint
                        const result = await apiCall('/api/federation/remove/' + encodeURIComponent(domain), {
                            method: 'DELETE'
                        });
                        
                        logActivity('Domain ' + domain + ' removed successfully', 'success');
                        setTimeout(() => location.reload(), 1000);
                    } catch (error) {
                        logActivity('Remove domain error: ' + error.message, 'error');
                    }
                }
            }

            // Service test functions
            async function handleTestBlogApi() {
                try {
                    logActivity('Testing Blog API...', 'info');
                    const result = await apiCall('/api/blog/status');
                    logActivity('Blog API test: ' + (result.status === 'running' ? 'Success' : 'Failed'), 
                            result.status === 'running' ? 'success' : 'error');
                } catch (error) {
                    logActivity('Blog API test error: ' + error.message, 'error');
                }
            }

            async function handleTestEmailApi() {
                try {
                    logActivity('Testing Email API...', 'info');
                    const result = await apiCall('/api/email/status');
                    logActivity('Email API test: ' + (result.status === 'running' ? 'Success' : 'Failed'), 
                            result.status === 'running' ? 'success' : 'error');
                } catch (error) {
                    logActivity('Email API test error: ' + error.message, 'error');
                }
            }

            async function handleTestFederation() {
                try {
                    logActivity('Testing Federation...', 'info');
                    const result = await apiCall('/api/federation/status');
                    logActivity('Federation test: ' + (result.status === 'online' ? 'Success' : 'Failed'), 
                            result.status === 'online' ? 'success' : 'error');
                } catch (error) {
                    logActivity('Federation test error: ' + error.message, 'error');
                }
            }

            // Queue and maintenance functions
            async function handleProcessQueue() {
                if (confirm('Process all queued operations now?')) {
                    try {
                        logActivity('Processing queue...', 'info');
                        const result = await apiCall('/api/queue/process', { method: 'POST' });
                        logActivity('Queue processed: ' + (result.processed || 0) + ' items', 'success');
                        setTimeout(() => location.reload(), 1000);
                    } catch (error) {
                        logActivity('Queue processing error: ' + error.message, 'error');
                    }
                }
            }

            async function handleSendTestEmail() {
                const email = prompt('Enter email address for test:');
                if (email && email.includes('@')) {
                    try {
                        logActivity('Sending test email to ' + email + '...', 'info');
                        const result = await apiCall('/api/email/send', {
                            method: 'POST',
                            body: JSON.stringify({ 
                                to: email, 
                                subject: 'Test Email from Deadlight Proxy',
                                body: 'This is a test email sent from the Deadlight proxy dashboard.'
                            })
                        });
                        
                        logActivity('Test email: ' + (result.success ? 'Sent' : 'Failed'), 
                                result.success ? 'success' : 'error');
                    } catch (error) {
                        logActivity('Test email error: ' + error.message, 'error');
                    }
                }
            }

            async function runHealthCheck() {
                try {
                    logActivity('Running health check...', 'info');
                    
                    const tests = [
                        { name: 'Blog API', endpoint: '/api/blog/status' },
                        { name: 'Email API', endpoint: '/api/email/status' },
                        { name: 'Federation API', endpoint: '/api/federation/status' }
                    ];
                    
                    let allPassed = true;
                    for (const test of tests) {
                        try {
                            const response = await fetch(test.endpoint);
                            const result = await response.json();
                            logActivity('Health check ' + test.name + ': OK', 'success');
                        } catch (error) {
                            logActivity('Health check ' + test.name + ': Failed', 'error');
                            allPassed = false;
                        }
                    }
                    
                    logActivity('Health check ' + (allPassed ? 'complete - all services OK' : 'complete - some issues found'), 
                            allPassed ? 'success' : 'warning');
                } catch (error) {
                    logActivity('Health check error: ' + error.message, 'error');
                }
            }

            // Utility functions
            function viewQueueDetails() {
                window.location.href = '/admin/proxy/queue';
            }

            function clearActivityLog() {
                document.getElementById('activity-log').innerHTML = '<p class="no-data">No recent activity</p>';
            }

            async function resetCircuitBreaker() {
                if (confirm('Reset circuit breaker?')) {
                    try {
                        const result = await apiCall('/admin/proxy/reset-circuit', { method: 'POST' });
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
                        const result = await apiCall('/admin/proxy/clear-failed', { method: 'POST' });
                        logActivity('Cleared ' + (result.cleared || 0) + ' failed operations', 'success');
                        setTimeout(() => location.reload(), 1000);
                    } catch (error) {
                        logActivity('Clear failed error: ' + error.message, 'error');
                    }
                }
            }

            // Auto-refresh functionality
            let refreshInterval;

            function startAutoRefresh() {
                refreshInterval = setInterval(refreshMetrics, CONFIG.REFRESH_INTERVAL);
            }

            function stopAutoRefresh() {
                if (refreshInterval) {
                    clearInterval(refreshInterval);
                }
            }

            // Initialize dashboard
            document.addEventListener('DOMContentLoaded', function() {
                // Initial metrics load
                refreshMetrics();
                
                // Start auto-refresh
                startAutoRefresh();
                
                // Stop auto-refresh when page is hidden
                document.addEventListener('visibilitychange', function() {
                    if (document.hidden) {
                        stopAutoRefresh();
                    } else {
                        startAutoRefresh();
                    }
                });
            });
        </script>

        <style>
            .proxy-dashboard {
                max-width: 1200px;
                margin: 0 auto;
                padding: 20px;
            }

            .section {
                background: #fff;
                border: 1px solid #ddd;
                border-radius: 8px;
                padding: 20px;
                margin: 20px 0;
                box-shadow: 0 2px 4px rgba(0,0,0,0.1);
            }

            .section h2 {
                margin: 0 0 20px 0;
                color: #333;
                border-bottom: 2px solid #007cba;
                padding-bottom: 10px;
            }

            .section h3 {
                margin: 20px 0 10px 0;
                color: #555;
            }

            /* Status indicators */
            .status-indicator {
                display: flex;
                align-items: center;
                margin: 15px 0;
                padding: 15px;
                border-radius: 8px;
            }

            .status-indicator.connected {
                background: #e8f5e8;
                border-left: 4px solid #4caf50;
            }

            .status-indicator.disconnected {
                background: #fee;
                border-left: 4px solid #f44336;
            }

            .status-dot {
                width: 12px;
                height: 12px;
                border-radius: 50%;
                margin-right: 10px;
            }

            .connected .status-dot {
                background: #4caf50;
                animation: pulse-green 2s infinite;
            }

            .disconnected .status-dot {
                background: #f44336;
                animation: pulse-red 2s infinite;
            }

            @keyframes pulse-green {
                0% { box-shadow: 0 0 0 0 rgba(76, 175, 80, 0.7); }
                70% { box-shadow: 0 0 0 10px rgba(76, 175, 80, 0); }
                100% { box-shadow: 0 0 0 0 rgba(76, 175, 80, 0); }
            }

            @keyframes pulse-red {
                0% { box-shadow: 0 0 0 0 rgba(244, 67, 54, 0.7); }
                70% { box-shadow: 0 0 0 10px rgba(244, 67, 54, 0); }
                100% { box-shadow: 0 0 0 0 rgba(244, 67, 54, 0); }
            }

            /* Metrics grid */
            .metrics-grid {
                display: grid;
                grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
                gap: 20px;
                margin: 20px 0;
            }
            
            .metric-card {
                background: linear-gradient(135deg, #f5f5f5 0%, #e8e8e8 100%);
                border: 1px solid #ddd;
                border-radius: 12px;
                padding: 25px 20px;
                text-align: center;
                transition: transform 0.2s ease;
            }

            .metric-card:hover {
                transform: translateY(-2px);
                box-shadow: 0 4px 8px rgba(0,0,0,0.15);
            }
            
            .metric-card h3 {
                margin: 0 0 15px 0;
                font-size: 13px;
                color: #666;
                text-transform: uppercase;
                letter-spacing: 1px;
                font-weight: 600;
            }
            
            .metric-value {
                font-size: 28px;
                font-weight: bold;
                color: #333;
                font-family: 'Courier New', monospace;
            }

            /* Status badges */
            .status-badge {
                padding: 4px 8px;
                border-radius: 4px;
                font-size: 12px;
                font-weight: bold;
                text-transform: uppercase;
            }

            .status-badge.online {
                background: #4caf50;
                color: white;
            }

            .status-badge.offline {
                background: #f44336;
                color: white;
            }

            /* Trust levels */
            .trust-level {
                padding: 4px 8px;
                border-radius: 4px;
                font-size: 11px;
                font-weight: bold;
                text-transform: uppercase;
            }

            .trust-level.verified {
                background: #4caf50;
                color: white;
            }

            .trust-level.unknown {
                background: #ff9800;
                color: white;
            }

            /* Tables */
            .table-container {
                overflow-x: auto;
                margin: 15px 0;
            }

            .data-table {
                width: 100%;
                border-collapse: collapse;
                background: white;
                border: 1px solid #ddd;
                border-radius: 8px;
                overflow: hidden;
            }

            .data-table thead {
                background: #f8f9fa;
            }

            .data-table th,
            .data-table td {
                padding: 12px 15px;
                text-align: left;
                border-bottom: 1px solid #eee;
            }

            .data-table th {
                font-weight: 600;
                color: #555;
                text-transform: uppercase;
                font-size: 12px;
                letter-spacing: 0.5px;
            }

            .data-table tr:hover {
                background: #f8f9fa;
            }

            .data-table .no-data {
                text-align: center;
                color: #999;
                font-style: italic;
                padding: 20px;
            }

            /* Queue stats */
            .queue-stats {
                display: flex;
                gap: 30px;
                margin: 15px 0;
                flex-wrap: wrap;
            }

            .queue-stat {
                display: flex;
                flex-direction: column;
                align-items: center;
                padding: 15px;
                background: #f8f9fa;
                border-radius: 8px;
                min-width: 120px;
            }

            .stat-label {
                font-size: 12px;
                color: #666;
                text-transform: uppercase;
                letter-spacing: 0.5px;
                margin-bottom: 5px;
            }

            .stat-value {
                font-size: 24px;
                font-weight: bold;
                color: #333;
                font-family: 'Courier New', monospace;
            }

            /* Federation stats */
            .federation-stats {
                display: grid;
                grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
                gap: 20px;
                margin: 20px 0;
            }

            .stat-item {
                text-align: center;
                padding: 20px;
                background: #f8f9fa;
                border-radius: 8px;
                border: 1px solid #e9ecef;
            }

            .stat-number {
                display: block;
                font-size: 32px;
                font-weight: bold;
                color: #007cba;
                font-family: 'Courier New', monospace;
                margin-bottom: 8px;
            }

            .stat-item .stat-label {
                font-size: 13px;
                color: #666;
                text-transform: uppercase;
                letter-spacing: 0.5px;
            }

            /* Buttons */
            .button {
                background: #007cba;
                color: white;
                border: none;
                padding: 10px 20px;
                border-radius: 6px;
                cursor: pointer;
                font-size: 14px;
                font-weight: 500;
                transition: all 0.2s ease;
                text-decoration: none;
                display: inline-block;
            }

            .button:hover {
                background: #005a8b;
                transform: translateY(-1px);
                box-shadow: 0 2px 4px rgba(0,0,0,0.2);
            }

            .button:active {
                transform: translateY(0);
            }

            .button.secondary {
                background: #6c757d;
            }

            .button.secondary:hover {
                background: #545b62;
            }

            .button.small {
                padding: 6px 12px;
                font-size: 12px;
            }

            .button.delete-button {
                background: #dc3545;
            }

            .button.delete-button:hover {
                background: #c82333;
            }

            .button:disabled {
                background: #ccc;
                cursor: not-allowed;
                transform: none;
            }

            .button:disabled:hover {
                background: #ccc;
                transform: none;
                box-shadow: none;
            }

            .button-group {
                display: flex;
                gap: 10px;
                flex-wrap: wrap;
                margin: 15px 0;
            }

            .button-grid {
                display: grid;
                grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
                gap: 15px;
                margin: 15px 0;
            }

            /* Forms */
            .inline-form {
                display: flex;
                gap: 10px;
                align-items: center;
                margin: 15px 0;
                flex-wrap: wrap;
            }

            .inline-form input[type="text"] {
                padding: 10px 15px;
                border: 1px solid #ddd;
                border-radius: 6px;
                font-size: 14px;
                min-width: 200px;
                flex: 1;
            }

            .inline-form input[type="text"]:focus {
                outline: none;
                border-color: #007cba;
                box-shadow: 0 0 0 2px rgba(0, 124, 186, 0.2);
            }

            /* Activity log */
            .activity-log {
                background: #f8f9fa;
                border: 1px solid #e9ecef;
                border-radius: 8px;
                padding: 15px;
                max-height: 400px;
                overflow-y: auto;
                font-family: 'Courier New', monospace;
                font-size: 13px;
            }

            .log-entry {
                padding: 8px 12px;
                margin: 3px 0;
                border-radius: 4px;
                border-left: 4px solid transparent;
                display: flex;
                align-items: center;
            }

            .log-time {
                color: #666;
                margin-right: 10px;
                font-weight: bold;
            }
            
            .log-info {
                background: #e3f2fd;
                border-left-color: #1976d2;
                color: #1565c0;
            }
            
            .log-success {
                background: #e8f5e8;
                border-left-color: #4caf50;
                color: #2e7d32;
            }
            
            .log-error {
                background: #ffebee;
                border-left-color: #f44336;
                color: #c62828;
            }
            
            .log-warning {
                background: #fff3e0;
                border-left-color: #ff9800;
                color: #ef6c00;
            }

            .no-data {
                color: #999;
                font-style: italic;
                text-align: center;
                padding: 20px;
            }

            .error-message {
                background: #ffebee;
                color: #c62828;
                padding: 15px;
                border-radius: 8px;
                border-left: 4px solid #f44336;
                margin: 15px 0;
            }

            /* Responsive design */
            @media (max-width: 768px) {
                .metrics-grid {
                    grid-template-columns: 1fr 1fr;
                }

                .queue-stats {
                    flex-direction: column;
                    gap: 15px;
                }

                .federation-stats {
                    grid-template-columns: 1fr;
                }

                .button-group {
                    flex-direction: column;
                }

                .button-group .button {
                    width: 100%;
                    text-align: center;
                }

                .inline-form {
                    flex-direction: column;
                    align-items: stretch;
                }

                .inline-form input[type="text"] {
                    min-width: auto;
                    width: 100%;
                }
            }

            @media (max-width: 480px) {
                .metrics-grid {
                    grid-template-columns: 1fr;
                }

                .proxy-dashboard {
                    padding: 10px;
                }

                .section {
                    padding: 15px;
                }
            }
        </style>
    `;

    return renderTemplate('Proxy Server Dashboard', content, user, config);
}