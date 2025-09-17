// src/routes/proxy.js 
import { ProxyService } from '../services/proxy.js';
import { EnhancedOutboxService } from '../services/enhanced-outbox.js';
import { FederationService } from '../services/federation.js';
import { proxyDashboardTemplate } from '../templates/admin/proxyDashboard.js';
import { checkAuth } from '../../../lib.deadlight/core/src/auth/password.js';
import { configService } from '../services/config.js';

export async function handleProxyRoutes(request, env, user) {
    try {
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
        
        const config = await configService.getConfig(env.DB);
        
        return new Response(proxyDashboardTemplate(errorData, user, config), {
            headers: { 'Content-Type': 'text/html' }
        });
    }
}

export const handleProxyTests = {
    async addFederationDomain(request, env) {
        try {
            const { domain } = await request.json();
            
            if (!domain) {
                return Response.json({ success: false, error: 'Domain is required' });
            }

            const federationService = new FederationService(env);
            
            // First, discover the domain
            const discoveryResult = await federationService.discoverDomain(domain);
            
            // Then add it to the database
            await env.DB.prepare(`
                INSERT INTO federation_domains (domain, trust_level, status, created_at)
                VALUES (?, 'pending', 'active', datetime('now'))
                ON CONFLICT(domain) DO UPDATE SET
                    status = 'active',
                    updated_at = datetime('now')
            `).bind(domain).run();
            
            return Response.json({
                success: true,
                data: discoveryResult,
                message: `Domain ${domain} added and discovery initiated`
            });
        } catch (error) {
            console.error('Add federation domain error:', error);
            return Response.json({
                success: false,
                error: error.message
            });
        }
    },

    async testFederationDomain(request, env) {
        try {
            const { domain } = await request.json();
            
            if (!domain) {
                return Response.json({ success: false, error: 'Domain is required' });
            }

            const federationService = new FederationService(env);
            
            // Test connectivity to the domain
            const testResult = await federationService.testDomain(domain);
            
            return Response.json({
                success: true,
                data: testResult,
                message: `Connection test to ${domain} completed`
            });
        } catch (error) {
            console.error('Test federation domain error:', error);
            return Response.json({
                success: false,
                error: error.message
            });
        }
    },

    async removeFederationDomain(request, env) {
        try {
            const { domain } = await request.json();
            
            if (!domain) {
                return Response.json({ success: false, error: 'Domain is required' });
            }

            // Remove from database
            const result = await env.DB.prepare(`
                UPDATE federation_domains 
                SET status = 'removed', updated_at = datetime('now')
                WHERE domain = ?
            `).bind(domain).run();
            
            if (result.changes === 0) {
                return Response.json({
                    success: false,
                    error: 'Domain not found'
                });
            }
            
            return Response.json({
                success: true,
                message: `Domain ${domain} removed from federation`
            });
        } catch (error) {
            console.error('Remove federation domain error:', error);
            return Response.json({
                success: false,
                error: error.message
            });
        }
    },

    async healthCheck(request, env) {
        try {
            const proxyService = new ProxyService({ PROXY_URL: env.PROXY_URL || 'http://localhost:8080' });
            const outboxService = new EnhancedOutboxService(env);
            const federationService = new FederationService(env);
            
            const [proxyHealth, queueStatus, federationStatus] = await Promise.allSettled([
                proxyService.healthCheck(),
                outboxService.getStatus(),
                federationService.getConnectedDomains()
            ]);
            
            return Response.json({
                success: true,
                data: {
                    proxy: proxyHealth.status === 'fulfilled' ? proxyHealth.value : { error: proxyHealth.reason?.message },
                    queue: queueStatus.status === 'fulfilled' ? queueStatus.value : { error: queueStatus.reason?.message },
                    federation: federationStatus.status === 'fulfilled' ? 
                        { connected_domains: federationStatus.value.length, status: 'healthy' } : 
                        { error: federationStatus.reason?.message },
                    timestamp: new Date().toISOString()
                }
            });
        } catch (error) {
            console.error('Health check error:', error);
            return Response.json({
                success: false,
                error: error.message
            });
        }
    },

    async resetCircuit(request, env) {
        try {
            const proxyService = new ProxyService({ PROXY_URL: env.PROXY_URL || 'http://localhost:8080' });
            
            // Reset the circuit breaker
            proxyService.circuitBreaker.reset();
            
            return Response.json({
                success: true,
                message: 'Circuit breaker reset successfully',
                circuit_state: proxyService.getCircuitState()
            });
        } catch (error) {
            console.error('Reset circuit error:', error);
            return Response.json({
                success: false,
                error: error.message
            });
        }
    },

    async clearFailed(request, env) {
        try {
            const outboxService = new EnhancedOutboxService(env);
            
            // Clear failed operations from the outbox
            const result = await env.DB.prepare(`
                DELETE FROM outbox 
                WHERE status = 'failed' AND operation_type IN ('email', 'federation')
            `).run();
            
            return Response.json({
                success: true,
                cleared: result.changes,
                message: `Cleared ${result.changes} failed operations`
            });
        } catch (error) {
            console.error('Clear failed operations error:', error);
            return Response.json({
                success: false,
                error: error.message
            });
        }
    },

    async viewQueue(request, env) {
        // Redirect to proxy dashboard for now
        return Response.redirect('/admin/proxy', 302);
    },

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

    async statusStream(request, env) {
        const user = await checkAuth(request, env);
        if (!user) {
            return new Response('Unauthorized', { status: 401 });
        }

        // Create SSE stream
        const stream = new ReadableStream({
            async start(controller) {
                const encoder = new TextEncoder();
                
                // Send initial data
                const sendUpdate = async () => {
                    try {
                        const proxyService = new ProxyService({ PROXY_URL: env.PROXY_URL || 'http://localhost:8080' });
                        const outboxService = new EnhancedOutboxService(env);
                        const federationService = new FederationService(env); // Add this
                        
                        const [proxyStatus, queueStatus, federationStatus] = await Promise.allSettled([
                            proxyService.healthCheck(),
                            outboxService.getStatus(),
                            getFederationRealtimeStatus(env) // New function
                        ]);
                        
                        const data = {
                            timestamp: new Date().toISOString(),
                            proxy_connected: proxyStatus.status === 'fulfilled' && proxyStatus.value.proxy_connected,
                            blogApi: proxyStatus.status === 'fulfilled' ? proxyStatus.value.blog_api : null,
                            emailApi: proxyStatus.status === 'fulfilled' ? proxyStatus.value.email_api : null,
                            queueCount: queueStatus.status === 'fulfilled' ? queueStatus.value.queued_operations?.total || 0 : 0,
                            circuitState: proxyService.getCircuitState(),
                            
                            // NEW: Federation real-time status
                            federation: federationStatus.status === 'fulfilled' ? federationStatus.value : {
                                connected_domains: 0,
                                pending_posts: 0,
                                recent_activity: [],
                                trust_relationships: []
                            }
                        };
                        
                        controller.enqueue(encoder.encode(`data: ${JSON.stringify(data)}\n\n`));
                    } catch (error) {
                        console.error('SSE update error:', error);
                        controller.enqueue(encoder.encode(`data: ${JSON.stringify({
                            error: error.message,
                            timestamp: new Date().toISOString(),
                            proxy_connected: false
                        })}\n\n`));
                    }
                };
                
                // Send initial update
                await sendUpdate();
                
                // Set up interval for periodic updates
                const interval = setInterval(sendUpdate, 5000); // Every 5 seconds
                
                // Cleanup when client disconnects
                request.signal?.addEventListener('abort', () => {
                    clearInterval(interval);
                    controller.close();
                });
                
                // Keep connection alive with heartbeat
                const heartbeat = setInterval(() => {
                    try {
                        controller.enqueue(encoder.encode(': heartbeat\n\n'));
                    } catch (error) {
                        clearInterval(heartbeat);
                        clearInterval(interval);
                    }
                }, 30000); // Every 30 seconds
            }
        });

        return new Response(stream, {
            headers: {
                'Content-Type': 'text/event-stream',
                'Cache-Control': 'no-cache',
                'Connection': 'keep-alive',
                'Access-Control-Allow-Origin': '*',
                'Access-Control-Allow-Headers': 'Cache-Control',
            }
        });
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

// New function for real-time federation monitoring
async function getFederationRealtimeStatus(env) {
    const federationService = new FederationService(env);
    
    const [domains, pendingPosts, recentActivity] = await Promise.allSettled([
        federationService.getConnectedDomains(),
        getPendingFederationPosts(env.DB),
        getRecentFederationActivity(env.DB)
    ]);
    
    return {
        connected_domains: domains.status === 'fulfilled' ? domains.value.length : 0,
        trust_levels: domains.status === 'fulfilled' 
            ? domains.value.reduce((acc, d) => { 
                acc[d.trust_level] = (acc[d.trust_level] || 0) + 1; 
                return acc; 
              }, {})
            : {},
        pending_posts: pendingPosts.status === 'fulfilled' ? pendingPosts.value : 0,
        recent_activity: recentActivity.status === 'fulfilled' ? recentActivity.value : [],
        last_outgoing: await getLastFederationSent(env.DB),
        last_incoming: await getLastFederationReceived(env.DB)
    };
}

async function getPendingFederationPosts(db) {
    const result = await db.prepare(`
        SELECT COUNT(*) as count 
        FROM posts 
        WHERE federation_pending = 1
    `).first();
    return result?.count || 0;
}

async function getRecentFederationActivity(db, limit = 5) {
    const result = await db.prepare(`
        SELECT 
            id, title, 
            json_extract(federation_metadata, '$.source_domain') as source_domain,
            json_extract(federation_metadata, '$.received_at') as received_at,
            post_type,
            moderation_status
        FROM posts 
        WHERE post_type IN ('federated', 'comment') 
            AND federation_metadata IS NOT NULL
        ORDER BY created_at DESC 
        LIMIT ?
    `).bind(limit).all();
    
    return (result.results || []).map(row => ({
        type: row.post_type,
        title: row.title,
        domain: row.source_domain,
        timestamp: row.received_at,
        status: row.moderation_status
    }));
}

async function getLastFederationSent(db) {
    const result = await db.prepare(`
        SELECT federation_sent_at, title
        FROM posts 
        WHERE federation_sent_at IS NOT NULL 
        ORDER BY federation_sent_at DESC 
        LIMIT 1
    `).first();
    return result ? { timestamp: result.federation_sent_at, title: result.title } : null;
}

async function getLastFederationReceived(db) {
    const result = await db.prepare(`
        SELECT 
            json_extract(federation_metadata, '$.received_at') as received_at,
            title
        FROM posts 
        WHERE post_type = 'federated' 
            AND federation_metadata IS NOT NULL
        ORDER BY created_at DESC 
        LIMIT 1
    `).first();
    return result ? { timestamp: result.received_at, title: result.title } : null;
}