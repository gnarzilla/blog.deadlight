// src/static/admin/proxyDashboard.js - Enhanced with Federation Live Monitoring
(function() {
    'use strict';
    
    console.log('Enhanced Proxy Dashboard with Federation Monitoring initializing...');

    // Enhanced request helper with better error handling
    async function fetchJson(path, options = {}) {
        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), 10000);
        
        try {
            const response = await fetch(path, {
                ...options,
                signal: controller.signal,
                headers: {
                    'Content-Type': 'application/json',
                    ...options.headers
                }
            });
            
            clearTimeout(timeoutId);
            
            if (!response.ok) {
                const errorText = await response.text().catch(() => 'Unknown error');
                throw new Error(`${response.status}: ${errorText}`);
            }
            
            return await response.json();
        } catch (error) {
            clearTimeout(timeoutId);
            if (error.name === 'AbortError') {
                throw new Error('Request timeout - proxy may be slow');
            }
            throw error;
        }
    }

    // Unified action handler with better UX
    async function performAction(path, options = {}, successMessage) {
        showLoading(options.loadingMessage || 'Working...');
        
        try {
            const result = await fetchJson(path, options);
            hideLoading();
            
            if (result.success) {
                showNotification('success', successMessage || result.message || 'Success!');
                
                // Auto-reload after successful operations
                if (options.reloadOnSuccess !== false) {
                    setTimeout(() => location.reload(), 1500);
                }
            } else {
                showNotification('error', result.error || 'Operation failed');
            }
            
            return result;
        } catch (error) {
            hideLoading();
            showNotification('error', error.message);
            throw error;
        }
    }

    // Enhanced notification system
    function showNotification(type, message) {
        const existing = document.querySelector('.notification');
        if (existing) existing.remove();
        
        const notification = document.createElement('div');
        notification.className = `notification notification-${type}`;
        notification.innerHTML = `
            <span>${message}</span>
            <button onclick="this.parentElement.remove()" aria-label="Close">×</button>
        `;
        
        document.body.appendChild(notification);
        
        setTimeout(() => {
            if (notification.parentElement) {
                notification.remove();
            }
        }, 5000);
    }

    function showLoading(message = 'Loading...') {
        let loader = document.getElementById('loading-indicator');
        if (!loader) {
            loader = document.createElement('div');
            loader.id = 'loading-indicator';
            loader.className = 'loading-indicator';
            document.body.appendChild(loader);
        }
        loader.innerHTML = `
            <div class="loading-content">
                <div class="spinner"></div>
                <span>${message}</span>
            </div>
        `;
        loader.style.display = 'flex';
    }

    function hideLoading() {
        const loader = document.getElementById('loading-indicator');
        if (loader) loader.style.display = 'none';
    }

    // Real-time Federation updates with Server-Sent Events
    function initializeRealTimeUpdates() {
        if (typeof EventSource === 'undefined') {
            console.warn('SSE not supported, falling back to polling');
            startPollingUpdates();
            return;
        }

        const eventSource = new EventSource('/admin/proxy/status-stream');
        
        eventSource.onopen = () => {
            console.log('Real-time updates connected');
            updateConnectionStatus(true);
        };
        
        eventSource.onmessage = (event) => {
            try {
                const data = JSON.parse(event.data);
                updateDashboardData(data);
            } catch (error) {
                console.error('Error parsing SSE data:', error);
            }
        };
        
        eventSource.onerror = (error) => {
            console.error('SSE connection error:', error);
            updateConnectionStatus(false);
            
            eventSource.close();
            setTimeout(startPollingUpdates, 5000);
        };
        
        window.addEventListener('beforeunload', () => {
            eventSource.close();
        });
    }

    // Fallback polling for real-time updates
    function startPollingUpdates() {
        const pollInterval = setInterval(async () => {
            try {
                const response = await fetch('/admin/proxy/status', {
                    headers: { 'Accept': 'application/json' }
                });
                
                if (response.ok) {
                    const data = await response.json();
                    updateDashboardData(data.data);
                    updateConnectionStatus(true);
                } else {
                    updateConnectionStatus(false);
                }
            } catch (error) {
                console.error('Polling error:', error);
                updateConnectionStatus(false);
            }
        }, 5000);
        
        window.addEventListener('beforeunload', () => {
            clearInterval(pollInterval);
        });
    }

    // Update dashboard elements with real-time data
    function updateDashboardData(data) {
        // Update status indicators
        const statusIndicator = document.querySelector('.status-indicator');
        if (statusIndicator && data.proxy_connected !== undefined) {
            statusIndicator.className = `status-indicator ${data.proxy_connected ? 'connected' : 'disconnected'}`;
            statusIndicator.textContent = data.proxy_connected ? '🟢 Connected' : '🔴 Disconnected';
        }
        
        // Update service statuses
        updateServiceStatus('blog-api', data.blogApi);
        updateServiceStatus('email-api', data.emailApi);
        
        // Update queue count
        const queueCount = document.querySelector('.queue-count');
        if (queueCount && data.queueCount !== undefined) {
            queueCount.textContent = data.queueCount;
        }
        
        // Update federation activity
        if (data.federation) {
            updateFederationActivity(data.federation);
        }
        
        // Update last check timestamp
        const lastCheck = document.querySelector('.last-check-time');
        if (lastCheck) {
            lastCheck.textContent = new Date().toLocaleTimeString();
        }
    }

    function updateServiceStatus(serviceKey, serviceData) {
        if (!serviceData) return;
        
        const card = document.querySelector(`[data-service="${serviceKey}"]`);
        if (!card) return;
        
        const statusEl = card.querySelector('.service-status');
        if (statusEl) {
            statusEl.className = `service-status ${serviceData.status === 'running' ? 'healthy' : 'error'}`;
            statusEl.textContent = `Status: ${serviceData.status || 'Unknown'}`;
        }
    }

    // NEW: Federation Activity Updates
    function updateFederationActivity(federation) {
        const activityContainer = document.getElementById('federation-activity');
        const trustContainer = document.getElementById('trust-levels');
        
        if (trustContainer && federation.trust_levels) {
            const trustHtml = `
                <div class="trust-stats">
                    ${Object.entries(federation.trust_levels).map(([level, count]) => `
                        <span class="trust-level trust-level-${level}">
                            <strong>${count}</strong> ${level}
                        </span>
                    `).join('')}
                </div>
            `;
            trustContainer.innerHTML = trustHtml;
        }
        
        if (!activityContainer) return;
        
        const html = `
            <div class="federation-stats">
                <span class="stat">
                    <strong>${federation.connected_domains || 0}</strong> Connected Domains
                </span>
                <span class="stat">
                    <strong>${federation.pending_posts || 0}</strong> Pending Posts
                </span>
            </div>
            
            <div class="recent-activity">
                <h4>Recent Activity</h4>
                ${federation.recent_activity && federation.recent_activity.length > 0 ? 
                    federation.recent_activity.map(activity => `
                        <div class="activity-item activity-${activity.type}">
                            <span class="activity-type">${activity.type}</span>
                            <span class="activity-domain">from ${activity.domain}</span>
                            <span class="activity-status status-${activity.status}">${activity.status}</span>
                            <span class="activity-time">${new Date(activity.timestamp).toLocaleTimeString()}</span>
                        </div>
                    `).join('') :
                    '<p class="no-activity">No recent federation activity</p>'
                }
            </div>
            
            ${federation.last_outgoing ? `
                <p class="last-sent">Last sent: "${federation.last_outgoing.title}" at ${new Date(federation.last_outgoing.timestamp).toLocaleTimeString()}</p>
            ` : ''}
            
            ${federation.last_incoming ? `
                <p class="last-received">Last received: "${federation.last_incoming.title}" at ${new Date(federation.last_incoming.timestamp).toLocaleTimeString()}</p>
            ` : ''}
        `;
        
        activityContainer.innerHTML = html;
    }

    function updateConnectionStatus(connected) {
        let indicator = document.querySelector('.connection-indicator');
        if (!indicator) {
            indicator = document.createElement('div');
            indicator.className = 'connection-indicator';
            document.querySelector('.dashboard-header').appendChild(indicator);
        }
        
        indicator.className = `connection-indicator ${connected ? 'connected' : 'disconnected'}`;
        indicator.textContent = connected ? 'Live updates active' : 'Live updates disconnected';
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
            showNotification('error', 'Please enter a valid email address');
            return;
        }
        
        await performAction('/admin/proxy/send-test-email', {
            method: 'POST',
            body: JSON.stringify({ email }),
            loadingMessage: 'Sending test email...'
        }, `Test email sent to ${email}`);
    };

    // NEW: Federation-specific handlers
    window.handleDiscoverDomain = async () => {
        const domain = prompt('Enter domain to discover (e.g., example.deadlight.network):');
        if (!domain) return;
        
        await performAction('/admin/proxy/discover-domain', {
            method: 'POST',
            body: JSON.stringify({ domain }),
            loadingMessage: `Discovering ${domain}...`
        }, `Discovery request sent to ${domain}`);
    };

    // Initialize when DOM is ready
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', initializeRealTimeUpdates);
    } else {
        initializeRealTimeUpdates();
    }

    console.log('Enhanced Proxy Dashboard with Federation Monitoring initialized');
})();