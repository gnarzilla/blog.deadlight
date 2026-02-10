// src/routes/proxy.js 
import { checkAuth } from '../../../lib.deadlight/core/src/auth/password.js';
import { renderTemplate } from '../templates/base.js'; 
import { proxyDashboardTemplate } from '../templates/admin/proxyDashboard.js';

/* ==============================================================
   MAIN PROXY DASHBOARD HANDLER
   ============================================================== */
export async function handleProxyRoutes(request, env, user) {
    if (request.method !== 'GET') {
        return new Response('Method Not Allowed', { status: 405 });
    }
    
    try {
        // 1. Fetch all status data in parallel
        const [status, queueStatus, domains] = await Promise.all([
            env.services.proxy.healthCheck(),
            env.services.queue.getStatus(),
            env.services.federation.getConnectedDomains(),
        ]);

        // 2. Get configuration
        const dbConfig = await env.services.config.getConfig();
        const siteUrl = dbConfig.siteUrl || env.SITE_URL || new URL(request.url).origin;
        const effectiveProxyUrl = env.PROXY_URL || dbConfig.proxyUrl || '';

        const config = {
            ...dbConfig,
            proxyUrl: effectiveProxyUrl,
            siteUrl: siteUrl 
        };

        // 3. Get circuit state & recommendations
        const circuitState = env.services.proxy.getCircuitState();
        const recommendations = getCircuitRecommendations(circuitState);
        
        // 4. Auto-process queue if proxy is connected and items are waiting
        let lastProcessing = null;
        if (status.proxy_connected && queueStatus.queued?.total > 0) {
            lastProcessing = await env.services.queue.processAll();
        }

        // 5. Get real-time federation stats
        const federationStats = await getFederationRealtimeStatus(env);

        // 6. Assemble data object
        const data = {
            siteUrl, 
            status: { 
                ...status, 
                recommendations, 
                circuit_state: circuitState 
            },
            queue: { 
                status: queueStatus, 
                lastProcessing 
            },
            federation: { 
                connected_domains: domains,  // Array of domain objects
                connected_count: federationStats.connected_domains,  // Count
                pending_posts: federationStats.pending_posts,
                recent_activity: federationStats.recent_activity,
                last_outgoing: federationStats.last_outgoing,
                last_incoming: federationStats.last_incoming
            },
            config: config,
        };

        const responseBody = proxyDashboardTemplate(data, user, config);

        return new Response(
            renderTemplate('Proxy Dashboard', responseBody, user, config),
            { headers: { 'Content-Type': 'text/html' } }
        );

    } catch (error) {
        console.error('Proxy dashboard error:', error);
        
        // Fallback error state
        const dbConfig = await env.services.config.getConfig();
        const config = { ...dbConfig, proxyUrl: env.PROXY_URL || '' };
        
        const errorData = {
            status: { 
                proxy_connected: false, 
                error: error.message, 
                circuit_state: env.services.proxy.getCircuitState(), 
                recommendations: ['Error loading proxy dashboard'] 
            },
            queue: { 
                status: { queued: { total: 0 }, status: 'error' } 
            },
            federation: { 
                connected_domains: [], 
                connected_count: 0,
                pending_posts: 0,
                recent_activity: [] 
            },
            config: config
        };

        const responseBody = proxyDashboardTemplate(errorData, user, config);

        return new Response(
            renderTemplate('Proxy Dashboard', responseBody, user, config),
            { headers: { 'Content-Type': 'text/html' } }
        );
    }
}

/* ==============================================================
   HELPER FUNCTIONS
   ============================================================== */

function getCircuitRecommendations(circuitState) {
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

async function getFederationRealtimeStatus(env) {
    const [domains, pendingPosts, recentActivity, lastSent, lastReceived] = await Promise.allSettled([
        env.services.federation.getConnectedDomains(),
        getPendingFederationPosts(env.DB),
        getRecentFederationActivity(env.DB),
        getLastFederationSent(env.DB),
        getLastFederationReceived(env.DB),
    ]);

    return {
        connected_domains: domains.status === 'fulfilled' ? domains.value.length : 0,
        pending_posts: pendingPosts.status === 'fulfilled' ? pendingPosts.value : 0,
        recent_activity: recentActivity.status === 'fulfilled' ? recentActivity.value : [],
        last_outgoing: lastSent.status === 'fulfilled' ? lastSent.value : null,
        last_incoming: lastReceived.status === 'fulfilled' ? lastReceived.value : null,
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
            id, 
            title, 
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
    
    return result ? { 
        timestamp: result.federation_sent_at, 
        title: result.title 
    } : null;
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
    
    return result ? { 
        timestamp: result.received_at, 
        title: result.title 
    } : null;
}

/* ==============================================================
   API HANDLERS (exported for admin routes)
   ============================================================== */

export const handleProxyTests = {
    
    // POST /api/federation/connect - handled by federation routes now
    // This can be removed if it's already in federationRoutes
    
    async testBlogApi(request, env) {
        try {
            const result = await env.services.proxy.getBlogStatus();
            return Response.json({ 
                success: true, 
                data: result,
                circuit_state: env.services.proxy.getCircuitState()
            });
        } catch (error) {
            return Response.json({ 
                success: false, 
                error: error.message,
                circuit_state: env.services.proxy.getCircuitState()
            });
        }
    },

    async testEmailApi(request, env) {
        try {
            const result = await env.services.proxy.getEmailStatus();
            return Response.json({ 
                success: true, 
                data: result,
                circuit_state: env.services.proxy.getCircuitState()
            });
        } catch (error) {
            return Response.json({ 
                success: false, 
                error: error.message,
                circuit_state: env.services.proxy.getCircuitState()
            });
        }
    },

    async sendTestEmail(request, env) {
        try {
            const { email } = await request.json();
            
            const emailData = {
                to: email,
                from: 'noreply@deadlight.boo',
                subject: 'Test Email from Deadlight Proxy',
                body: `Hello!\n\nThis is a test email sent through the Deadlight Proxy.\n\nTimestamp: ${new Date().toISOString()}\nCircuit State: ${env.services.proxy.getCircuitState().state}\n\nBest regards,\nDeadlight`
            };
            
            try {
                // Try to send immediately
                const result = await env.services.proxy.sendEmail(emailData);
                return Response.json({ 
                    success: true, 
                    data: result,
                    sent_immediately: true,
                    circuit_state: env.services.proxy.getCircuitState()
                });
            } catch (proxyError) {
                // Queue if proxy is down
                await env.services.queue.queueEmailNotification(1, emailData);
                
                return Response.json({ 
                    success: true, 
                    data: { message: 'Email queued for delivery when proxy comes online' },
                    queued: true,
                    circuit_state: env.services.proxy.getCircuitState()
                });
            }
            
        } catch (error) {
            return Response.json({ 
                success: false, 
                error: error.message,
                circuit_state: env.services.proxy.getCircuitState()
            });
        }
    },

    async testFederation(request, env) {
        try {
            const domains = await env.services.federation.getConnectedDomains();
            
            if (domains.length === 0) {
                return Response.json({
                    success: false,
                    error: 'No federation domains configured',
                    suggestion: 'Add a domain in the Federation dashboard first'
                });
            }

            return Response.json({ 
                success: true, 
                data: {
                    domains: domains,
                    count: domains.length,
                    proxy_status: env.services.proxy.getCircuitState()
                }
            });
        } catch (error) {
            return Response.json({ 
                success: false, 
                error: error.message,
                suggestion: 'Check that federation is configured and proxy is online'
            });
        }
    },

    async processQueue(request, env) {
        try {
            const isAvailable = await env.services.proxy.isProxyAvailable();
            
            if (!isAvailable) {
                return Response.json({
                    success: false,
                    error: 'Proxy is not available - cannot process queue',
                    circuit_state: env.services.proxy.getCircuitState()
                });
            }
            
            const result = await env.services.queue.processAll();
            
            return Response.json({
                success: true,
                data: result
            });
            
        } catch (error) {
            return Response.json({
                success: false,
                error: error.message,
                circuit_state: env.services.proxy.getCircuitState()
            });
        }
    },

    async resetCircuit(request, env) {
        try {
            env.services.proxy.circuitBreaker.reset();
            
            return Response.json({
                success: true,
                message: 'Circuit breaker reset successfully',
                circuit_state: env.services.proxy.getCircuitState()
            });
        } catch (error) {
            return Response.json({
                success: false,
                error: error.message
            });
        }
    },

    async getCircuitStatus(request, env) {
        try {
            const circuitState = env.services.proxy.getCircuitState();
            
            return Response.json({
                success: true,
                data: {
                    circuit_state: circuitState,
                    recommendations: getCircuitRecommendations(circuitState)
                }
            });
        } catch (error) {
            return Response.json({
                success: false,
                error: error.message,
                circuit_state: env.services.proxy.getCircuitState()
            });
        }
    },

    async statusStream(request, env) {
        const user = await checkAuth(request, env);
        if (!user) {
            return new Response('Unauthorized', { status: 401 });
        }

        const stream = new ReadableStream({
            async start(controller) {
                const encoder = new TextEncoder();
                
                const sendUpdate = async () => {
                    try {
                        const [proxyStatus, queueStatus, federationStatus] = await Promise.allSettled([
                            env.services.proxy.healthCheck(),
                            env.services.queue.getStatus(),
                            getFederationRealtimeStatus(env)
                        ]);
                        
                        const data = {
                            timestamp: new Date().toISOString(),
                            proxy_connected: proxyStatus.status === 'fulfilled' && proxyStatus.value.proxy_connected,
                            queueCount: queueStatus.status === 'fulfilled' ? queueStatus.value.queued?.total || 0 : 0,
                            circuitState: env.services.proxy.getCircuitState(),
                            federation: federationStatus.status === 'fulfilled' ? federationStatus.value : {
                                connected_domains: 0,
                                pending_posts: 0,
                                recent_activity: []
                            }
                        };
                        
                        controller.enqueue(encoder.encode(`data: ${JSON.stringify(data)}\n\n`));
                    } catch (error) {
                        controller.enqueue(encoder.encode(`data: ${JSON.stringify({
                            error: error.message,
                            timestamp: new Date().toISOString(),
                            proxy_connected: false
                        })}\n\n`));
                    }
                };
                
                await sendUpdate();
                const updateInterval = setInterval(sendUpdate, 5000);
                const heartbeatInterval = setInterval(() => {
                    try {
                        controller.enqueue(encoder.encode(': heartbeat\n\n'));
                    } catch {
                        clearInterval(heartbeatInterval);
                        clearInterval(updateInterval);
                    }
                }, 30000);
                
                request.signal?.addEventListener('abort', () => {
                    clearInterval(updateInterval);
                    clearInterval(heartbeatInterval);
                    controller.close();
                });
            }
        });

        return new Response(stream, {
            headers: {
                'Content-Type': 'text/event-stream',
                'Cache-Control': 'no-cache',
                'Connection': 'keep-alive',
                'Access-Control-Allow-Origin': '*'
            }
        });
    }
};