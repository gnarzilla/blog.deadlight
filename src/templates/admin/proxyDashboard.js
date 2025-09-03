// src/templates/admin/proxyDashboard.js - Clean version without emojis
import { renderTemplate } from '../base.js';

export function proxyDashboardTemplate(proxyData, user, config, queuedCount = 0) {
    const { status, blogApi, emailApi, error } = proxyData;
    const proxyConnected = status?.proxy_connected || false;

    const content = `
        <div class="proxy-dashboard">
            <div class="dashboard-header">
                <h2>Proxy Server Management</h2>
                <div class="status-indicator ${proxyConnected ? 'connected' : 'disconnected'}">
                    ${proxyConnected ? '🟢 Connected to Proxy' : '🔴 Proxy Disconnected'}
                </div>
            </div>

            ${error ? `
                <div class="error-banner">
                    <h3>Connection Error</h3>
                    <p>${error}</p>
                    <button onclick="location.reload()" class="button">Retry Connection</button>
                </div>
            ` : ''}

            <div class="queue-status">
                <h3>Outbox Queue</h3>
                <p>${queuedCount} operations pending</p>
                ${proxyConnected ? `
                    <button onclick="handleProcessQueue()" class="button">Process Queue Now</button>
                ` : `
                    <p class="queue-waiting">Waiting for proxy connection...</p>
                `}
            </div>

            <div class="proxy-services-grid">
                <div class="service-card">
                    <h3>Blog API</h3>
                    <div class="service-status ${blogApi?.status === 'running' ? 'healthy' : 'error'}">
                        Status: ${blogApi?.status || 'Unknown'}
                    </div>
                    ${blogApi?.version ? `<p><strong>Version:</strong> ${blogApi.version}</p>` : ''}
                    ${blogApi?.error ? `<p class="error-text">Error: ${blogApi.error}</p>` : ''}
                    <button onclick="handleTestBlogApi()" class="button small-button">Test Blog API</button>
                </div>

                <div class="service-card">
                    <h3>Email API</h3>
                    <div class="service-status ${emailApi?.status === 'running' ? 'healthy' : 'error'}">
                        Status: ${emailApi?.status || 'Unknown'}
                    </div>
                    ${emailApi?.queue_size !== undefined ? `<p><strong>Queue Size:</strong> ${emailApi.queue_size}</p>` : ''}
                    ${emailApi?.last_processed ? `<p><strong>Last Processed:</strong> ${emailApi.last_processed}</p>` : ''}
                    ${emailApi?.error ? `<p class="error-text">Error: ${emailApi.error}</p>` : ''}
                    <button onclick="handleTestEmailApi()" class="button small-button">Test Email API</button>
                </div>

                <div class="service-card">
                    <h3>Email-based Federation</h3>
                    <div class="service-status healthy">Decentralized Social Media</div>
                    <p><strong>Protocol:</strong> Email Bridge</p>
                    <p><strong>Purpose:</strong> Instance-to-instance communication</p>
                    <button onclick="handleTestFederation()" class="button small-button">Test Federation</button>
                </div>

                <div class="service-card">
                    <h3>Configuration</h3>
                    <p><strong>Proxy URL:</strong> ${proxyData.config?.proxyUrl || 'Not configured'}</p>
                    <p><strong>Connection:</strong> ${proxyConnected ? 'Active' : 'Inactive'}</p>
                    ${status?.timestamp ? `<p><strong>Last Check:</strong> ${new Date(status.timestamp).toLocaleString()}</p>` : ''}
                    <button onclick="location.reload()" class="button">Refresh Status</button>
                </div>
            </div>

            <div class="proxy-actions">
                <h3>Quick Actions</h3>
                <div class="action-buttons">
                    <button onclick="handleSendTestEmail()" class="button">Send Test Email</button>
                    <button onclick="handlePublishTestPost()" class="button">Publish Test Post</button>
                    <button onclick="handleFederateTestMessage()" class="button">Test Federation</button>
                    <button onclick="location.reload()" class="button">Refresh All Status</button>
                </div>
            </div>

            <div class="integration-guide">
                <h3>Integration Guide</h3>
                <div class="guide-section">
                    <h4>Email Integration</h4>
                    <p>Your proxy server bridges SMTP protocol to HTTP API calls, enabling your Cloudflare Worker to handle email seamlessly.</p>
                    
                    <h4>Federation Features</h4>
                    <p>Enable decentralized social media by allowing blog instances to communicate via email protocols, avoiding ActivityPub complexity.</p>
                    
                    <h4>SOCKS5 Privacy</h4>
                    <p>Your proxy also provides SOCKS5 capabilities for privacy and bypassing restrictions.</p>
                </div>
            </div>
        </div>

        <script>
        (function() {
            'use strict';
            
            console.log('Proxy Dashboard JavaScript initializing...');

            // Utility functions
            function showLoading(message) {
                let loading = document.getElementById('loading-indicator');
                if (!loading) {
                    loading = document.createElement('div');
                    loading.id = 'loading-indicator';
                    loading.style.cssText = 'position: fixed; top: 20px; right: 20px; background: #333; color: white; padding: 10px 15px; border-radius: 4px; z-index: 1000;';
                    document.body.appendChild(loading);
                }
                loading.textContent = message;
                loading.style.display = 'block';
            }

            function hideLoading() {
                const loading = document.getElementById('loading-indicator');
                if (loading) loading.style.display = 'none';
            }

            // Global functions
            window.handleProcessQueue = async function() {
                console.log('Processing queue...');
                try {
                    showLoading('Processing queue...');
                    const response = await fetch('/admin/process-outbox', { method: 'POST' });
                    const result = await response.json();
                    hideLoading();
                    
                    const message = result.success ? 
                        'Success: ' + result.message : 
                        'Failed: ' + (result.error || 'Unknown error');
                    
                    alert(message);
                    if (result.success) setTimeout(() => location.reload(), 1000);
                } catch (error) {
                    hideLoading();
                    alert('Failed: ' + error.message);
                }
            };

            window.handleTestBlogApi = async function() {
                console.log('Testing Blog API...');
                try {
                    showLoading('Testing Blog API...');
                    const response = await fetch('/admin/proxy/test-blog-api');
                    const result = await response.json();
                    hideLoading();
                    alert('Blog API Test: ' + (result.success ? 'Success!' : 'Failed - ' + result.error));
                } catch (error) {
                    hideLoading();
                    alert('Test failed: ' + error.message);
                }
            };

            window.handleTestEmailApi = async function() {
                console.log('Testing Email API...');
                try {
                    showLoading('Testing Email API...');
                    const response = await fetch('/admin/proxy/test-email-api');
                    const result = await response.json();
                    hideLoading();
                    alert('Email API Test: ' + (result.success ? 'Success!' : 'Failed - ' + result.error));
                } catch (error) {
                    hideLoading();
                    alert('Test failed: ' + error.message);
                }
            };

            window.handleTestFederation = async function() {
                console.log('Testing Federation...');
                try {
                    showLoading('Testing Federation...');
                    const response = await fetch('/admin/proxy/test-federation');
                    const result = await response.json();
                    hideLoading();
                    alert('Federation Test: ' + (result.success ? 'Success!' : 'Failed - ' + result.error));
                } catch (error) {
                    hideLoading();
                    alert('Test failed: ' + error.message);
                }
            };

            window.handleSendTestEmail = async function() {
                console.log('Sending test email...');
                const email = prompt('Enter test email address:');
                if (!email) return;
                
                try {
                    showLoading('Sending test email...');
                    const response = await fetch('/admin/proxy/send-test-email', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({ email })
                    });
                    const result = await response.json();
                    hideLoading();
                    alert('Test email: ' + (result.success ? 'Sent successfully!' : 'Failed - ' + result.error));
                } catch (error) {
                    hideLoading();
                    alert('Failed: ' + error.message);
                }
            };

            window.handlePublishTestPost = async function() {
                console.log('Publishing test post...');
                try {
                    showLoading('Testing post functionality...');
                    hideLoading();
                    alert('Test post functionality - ready for integration');
                } catch (error) {
                    hideLoading();
                    alert('Failed: ' + error.message);
                }
            };

            window.handleFederateTestMessage = async function() {
                console.log('Testing federation message...');
                const domain = prompt('Enter target domain for federation test (e.g., otherblog.com):');
                if (!domain) return;
                
                try {
                    showLoading('Testing federation...');
                    const response = await fetch('/admin/proxy/test-federation', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({ target_domain: domain })
                    });
                    const result = await response.json();
                    hideLoading();
                    alert('Federation test: ' + (result.success ? 'Success!' : 'Failed - ' + result.error));
                } catch (error) {
                    hideLoading();
                    alert('Federation failed: ' + error.message);
                }
            };

            console.log('Proxy Dashboard JavaScript ready');

        
            
        })();
        
        </script>
    `;

    return renderTemplate('Proxy Server Management', content, user, config);
}