// src/services/proxy.js 
export class ProxyService {
    constructor(config) {
        // Change the default from FQDN or hostname to the reliable loopback IP
        this.baseUrl = config.PROXY_URL || 'http://127.0.0.1:8080'; 
        this.timeout = 8000; // Increased for federation operations
        
        // Circuit breaker state
        this.circuitState = {
            failures: 0,
            lastFailure: null,
            state: 'CLOSED', // CLOSED, OPEN, HALF_OPEN
            maxFailures: 3,
            resetTimeout: 30000 // 30 seconds
        };
        
        // Cache for status to avoid hammering proxy when it's down
        this.statusCache = {
            data: null,
            timestamp: null,
            ttl: 5000 // 5 seconds
        };
    }

    // Circuit breaker logic
    isCircuitOpen() {
        if (this.circuitState.state === 'OPEN') {
            const timeSinceFailure = Date.now() - this.circuitState.lastFailure;
            if (timeSinceFailure > this.circuitState.resetTimeout) {
                this.circuitState.state = 'HALF_OPEN';
                return false;
            }
            return true;
        }
        return false;
    }

    recordSuccess() {
        this.circuitState.failures = 0;
        this.circuitState.state = 'CLOSED';
    }

    recordFailure() {
        this.circuitState.failures++;
        this.circuitState.lastFailure = Date.now();
        
        if (this.circuitState.failures >= this.circuitState.maxFailures) {
            this.circuitState.state = 'OPEN';
            console.warn(`Circuit breaker OPEN: ${this.circuitState.failures} consecutive failures`);
        }
    }

    // Enhanced request method with retry and circuit breaker
    async makeRequest(endpoint, options = {}, retries = 2) {
        // Check circuit breaker
        if (this.isCircuitOpen()) {
            throw new Error('Circuit breaker is OPEN - proxy appears to be down');
        }

        const url = `${this.baseUrl}${endpoint}`;
        
        for (let attempt = 0; attempt <= retries; attempt++) {
            try {
                const controller = new AbortController();
                const timeoutId = setTimeout(() => controller.abort(), this.timeout);
                
                const response = await fetch(url, {
                    signal: controller.signal,
                    headers: {
                        'Content-Type': 'application/json',
                        'User-Agent': 'Deadlight-Blog/4.0',
                        'X-Request-ID': crypto.randomUUID(), // For debugging
                    },
                    ...options
                });

                clearTimeout(timeoutId);

                if (!response.ok) {
                    const errorText = await response.text().catch(() => 'Unknown error');
                    throw new Error(`Proxy API error: ${response.status} ${response.statusText} - ${errorText}`);
                }

                // Success - record it
                this.recordSuccess();
                return await response.json();

            } catch (error) {
                console.error(`Proxy API attempt ${attempt + 1} failed: ${error.message}`);
                
                // Don't retry on certain errors
                if (error.name === 'AbortError') {
                    error.message = 'Proxy request timeout';
                } else if (error.message.includes('fetch is not defined')) {
                    error.message = 'Network error - check proxy connectivity';
                }
                
                if (attempt === retries) {
                    this.recordFailure();
                    throw error;
                }
                
                // Exponential backoff
                await new Promise(resolve => setTimeout(resolve, Math.pow(2, attempt) * 1000));
            }
        }
    }

    // Cached health check to prevent excessive calls
    async healthCheck() {
        const now = Date.now();
        
        // Return cached result if still valid
        if (this.statusCache.data && 
            this.statusCache.timestamp && 
            (now - this.statusCache.timestamp) < this.statusCache.ttl) {
            return this.statusCache.data;
        }

        try {
            const [blogStatus, emailStatus] = await Promise.allSettled([
                this.getBlogStatus(),
                this.getEmailStatus()
            ]);
            
            const result = {
                proxy_connected: true,
                blog_api: blogStatus.status === 'fulfilled',
                email_api: emailStatus.status === 'fulfilled',
                timestamp: new Date().toISOString(),
                circuit_state: this.circuitState.state,
                failures: this.circuitState.failures
            };

            // Cache successful result
            this.statusCache = {
                data: result,
                timestamp: now
            };

            return result;
        } catch (error) {
            const result = {
                proxy_connected: false,
                error: error.message,
                timestamp: new Date().toISOString(),
                circuit_state: this.circuitState.state,
                failures: this.circuitState.failures
            };

            // Cache failed result for shorter time
            this.statusCache = {
                data: result,
                timestamp: now,
                ttl: 2000 // Only cache failures for 2 seconds
            };

            return result;
        }
    }

    // Blog API endpoints with better error context
    async getBlogStatus() {
        try {
            return await this.makeRequest('/api/blog/status');
        } catch (error) {
            console.error('Blog status check failed:', error.message);
            throw new Error(`Blog API unavailable: ${error.message}`);
        }
    }

    async publishPost(postData) {
        try {
            return await this.makeRequest('/api/blog/publish', {
                method: 'POST',
                body: JSON.stringify(postData)
            });
        } catch (error) {
            console.error('Blog post publish failed:', error.message);
            throw new Error(`Failed to publish post: ${error.message}`);
        }
    }

    // Email API with queue fallback integration
    async sendEmail(emailData) {
        try {
            return await this.makeRequest('/api/email/send', {
                method: 'POST',
                body: JSON.stringify(emailData)
            });
        } catch (error) {
            console.error('Email send failed, should queue:', error.message);
            // This error will trigger the calling code to queue the email
            throw new Error(`Email proxy unavailable: ${error.message}`);
        }
    }

    // SMS sending through proxy
    async sendSms(smsData) {
        try {
            return await this.makeRequest('/api/sms/send', {
                method: 'POST',
                body: JSON.stringify(smsData)
            });
        } catch (error) {
            console.error('SMS send failed:', error.message);
            throw new Error(`SMS proxy unavailable: ${error.message}`);
        }
    }

    // Federation with retry logic
    async sendFederatedPost(postData) {
        try {
            return await this.makeRequest('/api/federation/send', {
                method: 'POST',
                body: JSON.stringify(postData)
            }, 1); // Only 1 retry for federation to avoid delays
        } catch (error) {
            console.error('Federation send failed:', error.message);
            throw new Error(`Federation unavailable: ${error.message}`);
        }
    }

    // Enhanced federation methods that work with your existing FederationService
    async sendFederationActivity(activityData) {
        try {
            return await this.makeRequest('/api/federation/activity', {
                method: 'POST',
                body: JSON.stringify(activityData)
            });
        } catch (error) {
            console.error('Federation activity send failed:', error.message);
            throw new Error(`Federation activity failed: ${error.message}`);
        }
    }

    // IMAP/SMTP bridge status
    async getEmailServerStatus() {
        try {
            const result = await this.makeRequest('/api/email/server-status');
            return {
                imap_connected: result.imap?.connected || false,
                smtp_connected: result.smtp?.connected || false,
                ...result
            };
        } catch (error) {
            return {
                imap_connected: false,
                smtp_connected: false,
                error: error.message
            };
        }
    }

    // Protocol-specific status checks
    async getProtocolStatus() {
        try {
            return await this.makeRequest('/api/protocols/status');
        } catch (error) {
            return {
                http_proxy: false,
                socks_proxy: false,
                error: error.message
            };
        }
    }

    // Get email status (integrates with your existing outbox)
    async getEmailStatus() {
        try {
            const result = await this.makeRequest('/api/email/status');
            return {
                queue_size: result.queue_size || 0,
                last_processed: result.last_processed,
                server_status: result.server_status || 'unknown',
                ...result
            };
        } catch (error) {
            return {
                queue_size: 0,
                server_status: 'offline',
                error: error.message
            };
        }
    }

    // Utility method to check if proxy is available before queuing operations
    async isProxyAvailable() {
        try {
            const status = await this.healthCheck();
            return status.proxy_connected;
        } catch {
            return false;
        }
    }

    // Method to get current circuit breaker status for debugging
    getCircuitState() {
        return {
            state: this.circuitState.state,
            failures: this.circuitState.failures,
            lastFailure: this.circuitState.lastFailure,
            isOpen: this.isCircuitOpen()
        };
    }

    // Integration with your existing federation trust system
    async verifyFederatedDomain(domain) {
        try {
            return await this.makeRequest('/api/federation/verify', {
                method: 'POST',
                body: JSON.stringify({ domain })
            });
        } catch (error) {
            console.error('Domain verification failed:', error.message);
            return { verified: false, error: error.message };
        }
    }

    // Method to trigger queue processing on the proxy side
    async triggerQueueProcessing() {
        try {
            return await this.makeRequest('/api/queue/process', {
                method: 'POST'
            });
        } catch (error) {
            console.error('Queue processing trigger failed:', error.message);
            throw error;
        }
    }
}