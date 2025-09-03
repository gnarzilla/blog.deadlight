// src/static/admin/proxyDashboard.js
(function() {
  'use strict';

  // Enhanced request helper with better error handling
  async function fetchJson(path, options = {}) {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 10000); // 10s timeout
    
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
    
    // Auto-remove after 5 seconds
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

  // Real-time status updates with Server-Sent Events
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
      
      // Fallback to polling after SSE fails
      eventSource.close();
      setTimeout(startPollingUpdates, 5000);
    };
    
    // Cleanup on page unload
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
          updateDashboardData(data);
          updateConnectionStatus(true);
        } else {
          updateConnectionStatus(false);
        }
      } catch (error) {
        console.error('Polling error:', error);
        updateConnectionStatus(false);
      }
    }, 5000); // Poll every 5 seconds
    
    // Cleanup on page unload
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
      statusIndicator.textContent = data.proxy_connected ? 'Connected' : 'Disconnected';
    }
    
    // Update service statuses
    updateServiceStatus('blog-api', data.blogApi);
    updateServiceStatus('email-api', data.emailApi);
    
    // Update queue count
    const queueCount = document.querySelector('.queue-count');
    if (queueCount && data.queueCount !== undefined) {
      queueCount.textContent = data.queueCount;
    }
    
    // Update last check timestamp
    const lastCheck = document.querySelector('.last-check');
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
    
    // Update service-specific details
    const details = card.querySelector('.service-details');
    if (details && serviceData.details) {
      details.innerHTML = serviceData.details.map(d => `<p>${d}</p>`).join('');
    }
  }

  function updateConnectionStatus(connected) {
    const indicator = document.querySelector('.connection-indicator');
    if (!indicator) {
      const newIndicator = document.createElement('div');
      newIndicator.className = 'connection-indicator';
      document.querySelector('.dashboard-header').appendChild(newIndicator);
    }
    
    const connIndicator = document.querySelector('.connection-indicator');
    connIndicator.className = `connection-indicator ${connected ? 'connected' : 'disconnected'}`;
    connIndicator.textContent = connected ? 'Live updates active' : 'Live updates disconnected';
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

  window.handleFederateTestMessage = async () => {
    const domain = prompt('Enter target domain (e.g., example.com):');
    if (!domain) return;
    
    await performAction('/admin/proxy/test-federation', {
      method: 'POST',
      body: JSON.stringify({ target_domain: domain }),
      loadingMessage: 'Testing federation...'
    }, `Federation test sent to ${domain}`);
  };

  // Initialize when DOM is ready
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', initializeRealTimeUpdates);
  } else {
    initializeRealTimeUpdates();
  }

  console.log('Proxy Dashboard with real-time updates initialized');
})();
