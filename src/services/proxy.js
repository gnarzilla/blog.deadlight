// src/services/proxy.js
export class ProxyService {
    constructor(config) {
        this.baseUrl = config.PROXY_URL || 'http://localhost:8080';  // Your proxy server
        this.timeout = 5000; // 5 second timeout
    }

    async makeRequest(endpoint, options = {}) {
        const url = `${this.baseUrl}${endpoint}`;
        
        try {
            const response = await fetch(url, {
                timeout: this.timeout,
                headers: {
                    'Content-Type': 'application/json',
                    'User-Agent': 'Deadlight-Blog/4.0',
                },
                ...options
            });

            if (!response.ok) {
                throw new Error(`Proxy API error: ${response.status} ${response.statusText}`);
            }

            return await response.json();
        } catch (error) {
            console.error(`Proxy API request failed: ${error.message}`);
            throw error;
        }
    }

    // Blog API endpoints
    async getBlogStatus() {
        return await this.makeRequest('/api/blog/status');
    }

    async getBlogPosts() {
        return await this.makeRequest('/api/blog/posts');
    }

    async publishPost(postData) {
        return await this.makeRequest('/api/blog/publish', {
            method: 'POST',
            body: JSON.stringify(postData)
        });
    }

    // Email API endpoints  
    async getEmailStatus() {
        return await this.makeRequest('/api/email/status');
    }

    async sendEmail(emailData) {
        return await this.makeRequest('/api/email/send', {
            method: 'POST', 
            body: JSON.stringify(emailData)
        });
    }

    // proxy.js
    async sendSms(smsData) {
        return await this.makeRequest('/api/sms/send', {
            method: 'POST',
            body: JSON.stringify(smsData)
        });
    }

    // Federation API endpoints (for decentralized social media)
    async sendFederatedPost(postData) {
        return await this.makeRequest('/api/federation/send', {
            method: 'POST',
            body: JSON.stringify(postData)
        });
    }

    async receiveFederatedPost(postData) {
        return await this.makeRequest('/api/federation/receive', {
            method: 'POST',
            body: JSON.stringify(postData)
        });
    }

    // Health check
    async healthCheck() {
        try {
            const [blogStatus, emailStatus] = await Promise.allSettled([
                this.getBlogStatus(),
                this.getEmailStatus()
            ]);
            
            return {
                proxy_connected: true,
                blog_api: blogStatus.status === 'fulfilled',
                email_api: emailStatus.status === 'fulfilled',
                timestamp: new Date().toISOString()
            };
        } catch (error) {
            return {
                proxy_connected: false,
                error: error.message,
                timestamp: new Date().toISOString()
            };
        }
    }
}
