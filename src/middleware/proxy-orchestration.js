import { Logger } from '../../../lib.deadlight/core/src/logging/logger.js';

const logger = new Logger({ context: 'proxy-orchestration' });

// Cache proxy health for 30s to avoid hammering
let healthCache = { proxy_connected: false, timestamp: 0, circuit_state: 'UNKNOWN' };

export async function proxyOrchestrationMiddleware(request, env, ctx, next) {
  // Check proxy health (cached)
  const proxyHealth = await getCachedHealth(env);
  
  // Enrich context with proxy helpers
  ctx.proxy = {
    // Status info
    available: proxyHealth.proxy_connected,
    circuitState: proxyHealth.circuit_state,
    lastCheck: new Date(proxyHealth.timestamp).toISOString(),
    
    // Smart send: tries direct → falls back to queue
    send: async (actionType, payload) => {
      // Add userId to payload if user is authenticated
      if (ctx.user) {
        payload.userId = ctx.user.id;
      }
      
      // If proxy is offline, queue immediately
      if (!proxyHealth.proxy_connected) {
        logger.info('Proxy offline, queueing action', { actionType });
        return await env.services.queue.queueItem('proxy_action', {
          actionType,
          ...payload
        });
      }
      
      // Try direct send
      try {
        const result = await sendDirectToProxy(env, actionType, payload);
        return { success: true, sent: true, result };
      } catch (error) {
        logger.warn('Direct proxy send failed, queueing', { 
          actionType, 
          error: error.message 
        });
        
        // Fallback to queue
        return await env.services.queue.queueItem('proxy_action', {
          actionType,
          ...payload
        });
      }
    },
    
    // Direct access to ProxyService if needed
    service: env.services.proxy,
    
    // Get current queue status
    getQueueStatus: async () => {
      return await env.services.queue.getStatus();
    }
  };
  
  return next();
}

async function getCachedHealth(env) {
  const now = Date.now();
  
  // Return cached if fresh (< 30s old)
  if (now - healthCache.timestamp < 30000) {
    return healthCache;
  }
  
  // Fetch fresh health
  try {
    const health = await env.services.proxy.healthCheck();
    const circuitState = env.services.proxy.getCircuitState();
    
    healthCache = { 
      proxy_connected: health.proxy_connected,
      circuit_state: circuitState.state,
      timestamp: now 
    };
  } catch (error) {
    logger.error('Health check failed', { error: error.message });
    healthCache = { 
      proxy_connected: false, 
      circuit_state: 'UNKNOWN',
      timestamp: now 
    };
  }
  
  return healthCache;
}

async function sendDirectToProxy(env, actionType, payload) {
  switch (actionType) {
    case 'send_email':
      return await env.services.proxy.sendEmail(payload);
    case 'send_sms':
      return await env.services.proxy.sendSms(payload);
    default:
      throw new Error(`Unknown action type: ${actionType}`);
  }
}
