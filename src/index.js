// src/index.js
import { Router } from './routes/index.js';
import { styleRoutes } from './routes/styles.js';
import { staticRoutes } from './routes/static.js';
import { authRoutes } from './routes/auth.js';
import { adminRoutes } from './routes/admin.js';
import { blogRoutes } from './routes/blog.js';
import { inboxRoutes } from './routes/inbox.js';
import { apiRoutes } from './routes/api.js';
import { userRoutes } from './routes/user.js';
import { federationRoutes } from './routes/federation.js';
import { errorMiddleware, loggingMiddleware } from './middleware/index.js';
import { authMiddleware, apiAuthMiddleware, requireAdminMiddleware } from './middleware/index.js';
import { rateLimitMiddleware, securityHeadersMiddleware } from '../../lib.deadlight/core/src/security/middleware.js';
import { OutboxService } from './services/outbox.js';
import { analyticsMiddleware } from './middleware/analytics.js';
import { handleProxyTests } from './routes/proxy.js';

const router = new Router();

// Global middleware
router.use(errorMiddleware);
router.use(loggingMiddleware);
router.use(analyticsMiddleware);

// Public routes (no auth required)
router.group([], (r) => {
  // Blog routes
  Object.entries(blogRoutes).forEach(([path, handlers]) => {
    r.register(path, handlers);
  });
  
  // Style routes
  Object.entries(styleRoutes).forEach(([path, handlers]) => {
    r.register(path, handlers);
  });
  
  // Static routes
  Object.entries(staticRoutes).forEach(([path, handlers]) => {
    r.register(path, handlers);
  });
  
  // Auth routes (login/logout)
  Object.entries(authRoutes).forEach(([path, handlers]) => {
    r.register(path, handlers);
  });
  
  // Public API endpoints
  r.register('/api/health', apiRoutes['/api/health']);
  r.register('/api/status', apiRoutes['/api/status']);
  r.register('/api/blog/status', apiRoutes['/api/blog/status']);
  r.register('/api/blog/posts', apiRoutes['/api/blog/posts']);
  r.register('/api/metrics', apiRoutes['/api/metrics']);

  // Public federation endpoints
  r.register('/.well-known/deadlight', federationRoutes['/.well-known/deadlight']);
  r.register('/api/federation/outbox', federationRoutes['/api/federation/outbox']);
  // Use proxy.js handlers instead of federation.js
  r.register('/api/federation/connect', { 
    POST: async (req, env) => {
      try {
        return await handleProxyTests.addFederationDomain(req, env);
      } catch (error) {
        console.error('Federation connect error:', error);
        return new Response(JSON.stringify({
          success: false,
          error: error.message,
          stack: error.stack  // Helpful for debugging
        }), {
          status: 500,
          headers: { 'Content-Type': 'application/json' }
        });
      }
    }
  });
  r.register('/api/federation/test/*', federationRoutes['/api/federation/test/*']);
  r.register('/api/federation/remove', { 
    POST: (req, env) => handleProxyTests.removeFederationDomain(req, env) 
  });

});

// Authenticated user routes
router.group([authMiddleware], (r) => {
  // User routes
  Object.entries(userRoutes).forEach(([path, handlers]) => {
    r.register(path, handlers);
  });
  
  // Inbox routes
  Object.entries(inboxRoutes).forEach(([path, handlers]) => {
    r.register(path, handlers);
  });
});

// Admin routes (requires auth + admin role)
router.group([authMiddleware, requireAdminMiddleware], (r) => {
  // Register ALL admin routes from adminRoutes object
  Object.entries(adminRoutes).forEach(([path, handlers]) => {
    r.register(path, handlers);
  });
});

// Protected API routes (requires API key auth)
router.group([apiAuthMiddleware], (r) => {
  // Email API endpoints
  r.register('/api/email/receive', apiRoutes['/api/email/receive']);
  r.register('/api/email/fetch', apiRoutes['/api/email/fetch']);
  r.register('/api/email/pending-replies', apiRoutes['/api/email/pending-replies']);
  
  // Federation inbox
  r.register('/api/federation/inbox', federationRoutes['/api/federation/inbox']);
});

// Log registered routes for debugging
console.log('Routes registered:', Array.from(router.routes.keys()));

// Start queue processor when Worker initializes
let queueProcessorStarted = false;
async function startQueueProcessor(env, intervalMs = 300000) {
  if (!env.ENABLE_QUEUE_PROCESSING) {
    console.log('Queue processing disabled');
    return;
  }
  if (queueProcessorStarted) {
    console.log('Queue processor already started');
    return;
  }
  queueProcessorStarted = true;
  const outbox = new OutboxService(env);
  setInterval(async () => {
    try {
      const result = await outbox.processQueue();
      console.log(`Queue processed: ${result.processed} operations, ${result.queued} remaining`);
    } catch (error) {
      console.error('Queue processing error:', error);
    }
  }, intervalMs);
}

export default {
  async fetch(request, env, ctx) {
    ctx.waitUntil(startQueueProcessor(env));
    
    // Check if rate limiting is enabled
    if (env.DISABLE_RATE_LIMITING === 'true') {
      // Skip rate limiting entirely
      return securityHeadersMiddleware(request, env, ctx, () =>
        router.handle(request, env, ctx)
      );
    }
    
    // Normal flow with rate limiting
    return rateLimitMiddleware(request, env, ctx, () =>
      securityHeadersMiddleware(request, env, ctx, () =>
        router.handle(request, env, ctx)
      )
    );
  }
};