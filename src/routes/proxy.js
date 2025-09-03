// src/routes/proxy.js 
import { ProxyService } from '../services/proxy.js';
import { EnhancedOutboxService } from '../services/enhanced-outbox.js';
import { FederationService } from '../services/federation.js';
import { proxyDashboardTemplate } from '../templates/admin/proxyDashboard.js';

export async function handleProxyRoutes(request, env, user) {
    try {
        const { configService } = await import('../services/config.js');
        const config = await configService.getConfig(env.DB);

        const proxyUrl = env.PROXY_URL || config.proxyUrl || 'http://localhost:8080';
        const proxyService = new ProxyService({ PROXY_URL: proxyUrl });
        const outboxService = new EnhancedOutboxService(env);
        const federationService = new FederationService(env);

        const [proxyStatus, queueStatus, federationStatus] = await Promise.allSettled([
            proxyService.healthCheck(),
            outboxService.getStatus(),
            federationService.getConnectedDomains()
        ]);

        const shouldProcessQueue = proxyStatus.status === 'fulfilled' && 
                                 proxyStatus.value.proxy_connected &&
                                 queueStatus.status === 'fulfilled' &&
                                 queueStatus.value.queued_operations?.total > 0;

        let queueProcessingResult = null;
        if (shouldProcessQueue) {
            try {
                queueProcessingResult = await outboxService.processQueue();
                console.log('Enhanced queue processing completed:', queueProcessingResult);
            } catch (error) {
                console.error('Enhanced queue processing failed:', error);
            }
        }

        const proxyData = {
            status: proxyStatus.status === 'fulfilled' ? proxyStatus.value : { 
                proxy_connected: false, 
                error: proxyStatus.reason?.message || 'Connection failed',
                circuit_state: 'UNKNOWN'
            },
            queue: {
                status: queueStatus.status === 'fulfilled' ? queueStatus.value : { 
                    queued_operations: { total: 0 },
                    status: 'error'
                },
                lastProcessing: queueProcessingResult
            },
            federation: {
                connected_domains: federationStatus.status === 'fulfilled' ? federationStatus.value : [],
                status: federationStatus.status === 'fulfilled' ? 'online' : 'error'
            },
            config: {
                proxyUrl,
                enabled: true,
                circuitState: proxyService.getCircuitState()
            }
        };

        return new Response(proxyDashboardTemplate(proxyData, user, config), {
            headers: { 'Content-Type': 'text/html' }
        });

    } catch (error) {
        console.error('Proxy dashboard error:', error);
        
        const errorData = { 
            status: { 
                proxy_connected: false,
                error: error.message,
                circuit_state: 'ERROR'
            },
            queue: { 
                status: { queued_operations: { total: 0 }, status: 'error' }
            },
            federation: {
                connected_domains: [],
                status: 'error'
            },
            config: { 
                proxyUrl: env.PROXY_URL || 'http://localhost:8080', 
                enabled: false 
            }
        };
        
        const { configService } = await import('../services/config.js');
        const config = await configService.getConfig(env.DB);
        
        return new Response(proxyDashboardTemplate(errorData, user, config), {
            headers: { 'Content-Type': 'text/html' }
        });
    }
}

export const handleProxyTests = {
    async testBlogApi(request, env) {
        try {
            const proxyService = new ProxyService({ PROXY_URL: env.PROXY_URL || 'http://localhost:8080' });
            const result = await proxyService.getBlogStatus();
            
            return Response.json({ 
                success: true, 
                data: result,
                circuit_state: proxyService.getCircuitState()
            });
        } catch (error) {
            console.error('Blog API test error:', error);
            const proxyService = new ProxyService({ PROXY_URL: env.PROXY_URL || 'http://localhost:8080' });
            return Response.json({ 
                success: false, 
                error: error.message,
                circuit_state: proxyService.getCircuitState()
            });
        }
    },

    async testEmailApi(request, env) {
        try {
            const proxyService = new ProxyService({ PROXY_URL: env.PROXY_URL || 'http://localhost:8080' });
            const result = await proxyService.getEmailStatus();
            
            return Response.json({ 
                success: true, 
                data: result,
                circuit_state: proxyService.getCircuitState()
            });
        } catch (error) {
            console.error('Email API test error:', error);
            const proxyService = new ProxyService({ PROXY_URL: env.PROXY_URL || 'http://localhost:8080' });
            return Response.json({ 
                success: false, 
                error: error.message,
                circuit_state: proxyService.getCircuitState()
            });
        }
    },

    async sendTestEmail(request, env) {
        const proxyService = new ProxyService({ PROXY_URL: env.PROXY_URL || 'http://localhost:8080' });
        const outboxService = new EnhancedOutboxService(env);
        
        try {
            const { email } = await request.json();
            
            const emailData = {
                to: email,
                from: 'noreply@deadlight.boo',
                subject: 'Test Email from Deadlight Proxy',
                body: `Hello!\n\nThis is a test email sent through the enhanced Deadlight Proxy system.\n\nTimestamp: ${new Date().toISOString()}\nCircuit State: ${proxyService.getCircuitState().state}\n\nBest regards,\nDeadlight System`
            };
            
            try {
                const result = await proxyService.sendEmail(emailData);
                return Response.json({ 
                    success: true, 
                    data: result,
                    sent_immediately: true,
                    circuit_state: proxyService.getCircuitState()
                });
            } catch (proxyError) {
                console.log('Proxy unavailable, queuing email via outbox...');
                await outboxService.queueEmailNotification(1, emailData);
                
                return Response.json({ 
                    success: true, 
                    data: { 
                        message: 'Email queued for delivery when proxy comes online',
                        queued_via: 'outbox_service'
                    },
                    queued: true,
                    proxy_error: proxyError.message,
                    circuit_state: proxyService.getCircuitState()
                });
            }
            
        } catch (error) {
            console.error('Test email error:', error);
            return Response.json({ 
                success: false, 
                error: error.message,
                circuit_state: proxyService.getCircuitState()
            });
        }
    },

    async testFederation(request, env) {
        const federationService = new FederationService(env);
        
        try {
            const results = await federationService.testFederation();
            return Response.json({ 
                success: true, 
                data: results,
                sent_immediately: true,
                federation_domains: (await federationService.getConnectedDomains()).length
            });
        } catch (error) {
            console.error('Federation test error:', error);
            return Response.json({ 
                success: false, 
                error: error.message,
                suggestion: 'Check that federation domains are configured and proxy is online'
            });
        }
    },

    async testSms(request, env) {
        const proxyService = new ProxyService({ PROXY_URL: env.PROXY_URL || 'http://localhost:8080' });
        const outboxService = new EnhancedOutboxService(env);
        
        try {
            const { phone } = await request.json();
            
            const smsData = {
                to: phone,
                message: `Test SMS from Deadlight Proxy - ${new Date().toISOString()}`,
                from: 'Deadlight'
            };
            
            try {
                const result = await proxyService.sendSms(smsData);
                return Response.json({ 
                    success: true, 
                    data: result,
                    sent_immediately: true,
                    circuit_state: proxyService.getCircuitState()
                });
            } catch (proxyError) {
                await outboxService.queueSms(1, phone, smsData.message);
                
                return Response.json({ 
                    success: true, 
                    data: { message: 'SMS queued for delivery when proxy comes online' },
                    queued: true,
                    proxy_error: proxyError.message,
                    circuit_state: proxyService.getCircuitState()
                });
            }
            
        } catch (error) {
            console.error('Test SMS error:', error);
            return Response.json({ 
                success: false, 
                error: error.message,
                circuit_state: proxyService.getCircuitState()
            });
        }
    },

    async processQueue(request, env) {
        const proxyService = new ProxyService({ PROXY_URL: env.PROXY_URL || 'http://localhost:8080' });
        const outboxService = new EnhancedOutboxService(env);

        try {
            const isAvailable = await proxyService.isProxyAvailable();
            if (!isAvailable) {
                return Response.json({
                    success: false,
                    error: 'Proxy is not available - cannot process queue',
                    circuit_state: proxyService.getCircuitState()
                });
            }
            
            const result = await outboxService.processQueue();
            return Response.json({
                success: true,
                data: result
            });
            
        } catch (error) {
            console.error('Manual queue processing error:', error);
            return Response.json({
                success: false,
                error: error.message,
                circuit_state: proxyService.getCircuitState()
            });
        }
    },

    async getQueueStatus(request, env) {
        try {
            const outboxService = new EnhancedOutboxService(env);
            const status = await outboxService.getStatus();
            
            return Response.json({
                success: true,
                data: status
            });
        } catch (error) {
            console.error('Queue status error:', error);
            return Response.json({
                success: false,
                error: error.message
            });
        }
    },

    async getFederationStatus(request, env) {
        try {
            const federationService = new FederationService(env);
            const [domains, federatedPosts] = await Promise.allSettled([
                federationService.getConnectedDomains(),
                federationService.getFederatedPosts(10)
            ]);
            
            return Response.json({
                success: true,
                data: {
                    connected_domains: domains.status === 'fulfilled' ? domains.value : [],
                    recent_federated_posts: federatedPosts.status === 'fulfilled' ? federatedPosts.value : [],
                    status: 'online'
                }
            });
        } catch (error) {
            console.error('Federation status error:', error);
            return Response.json({
                success: false,
                error: error.message
            });
        }
    },

    async discoverDomain(request, env) {
        try {
            const { domain } = await request.json();
            const federationService = new FederationService(env);
            
            const result = await federationService.discoverDomain(domain);
            
            return Response.json({
                success: true,
                data: result,
                message: `Discovery request sent to ${domain}`
            });
        } catch (error) {
            console.error('Domain discovery error:', error);
            return Response.json({
                success: false,
                error: error.message
            });
        }
    },

    async getCircuitStatus(request, env) {
        try {
            const proxyService = new ProxyService({ PROXY_URL: env.PROXY_URL || 'http://localhost:8080' });
            const circuitState = proxyService.getCircuitState();
            
            return Response.json({
                success: true,
                data: {
                    circuit_state: circuitState,
                    recommendations: this.getCircuitRecommendations(circuitState)
                }
            });
        } catch (error) {
            const proxyService = new ProxyService({ PROXY_URL: env.PROXY_URL || 'http://localhost:8080' });
            return Response.json({
                success: false,
                error: error.message,
                circuit_state: proxyService.getCircuitState()
            });
        }
    },

    getCircuitRecommendations(circuitState) {
        const recommendations = [];
        
        if (circuitState.state === 'OPEN') {
            recommendations.push('Circuit breaker is OPEN - proxy appears to be down');
            recommendations.push('Check proxy server status and network connectivity');
            recommendations.push('Operations are being queued until proxy recovers');
        } else if (circuitState.state === 'HALF_OPEN') {
            recommendations.push('Circuit breaker is testing connectivity');
            recommendations.push('Next request will determine if circuit closes');
        } else if (circuitState.failures > 0) {
            recommendations.push(`${circuitState.failures} recent failures detected`);
            recommendations.push('Monitor proxy health closely');
        } else {
            recommendations.push('All systems operating normally');
        }
        
        return recommendations;
    }
};
