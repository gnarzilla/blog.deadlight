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

const router = new Router();

// Global middleware - analytics should be here
router.use(errorMiddleware);
router.use(loggingMiddleware);
router.use(analyticsMiddleware);

// Public routes (no auth required)
router.group([], (r) => {
  // Blog routes - public
  Object.entries(blogRoutes).forEach(([path, handlers]) => {
    r.register(path, handlers);
  });
  
  // Style routes - public
  Object.entries(styleRoutes).forEach(([path, handlers]) => {
    r.register(path, handlers);
  });
  
  // Static routes - public
  Object.entries(staticRoutes).forEach(([path, handlers]) => {
    r.register(path, handlers);
  });
  
  // Auth routes - public (login/logout)
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
  
  // Federation discovery & public endpoints
  r.register('/.well-known/deadlight', federationRoutes['/.well-known/deadlight']);
  r.register('/api/federation/outbox', federationRoutes['/api/federation/outbox']);
  
  // Keep your existing outbox route as-is for compatibility
  r.register('/federation/outbox', adminRoutes['/federation/outbox']);
});

// Admin routes - require auth + admin
router.group([authMiddleware, requireAdminMiddleware], (r) => {
  Object.entries(adminRoutes).forEach(([path, handlers]) => {
    r.register(path, handlers);
  });

  // federation dashboard
  r.register('/admin/federation', adminRoutes['/admin/federation']);
  
  // federation management endpoints
  r.register('/api/federation/connect', federationRoutes['/api/federation/connect']);
  r.register('/api/federation/queue', federationRoutes['/api/federation/queue']);
  r.register('/api/federation/test', federationRoutes['/api/federation/test']);
  
  // sync and federate-post routes
  r.register('/admin/federation/sync', adminRoutes['/admin/federation/sync']);
  r.register('/admin/federate-post/:id', adminRoutes['/admin/federate-post/(?<id>[^/]+)']);
});

// Authenticated user routes
router.group([authMiddleware], (r) => {
  // User routes - require auth
  Object.entries(userRoutes).forEach(([path, handlers]) => {
    r.register(path, handlers);
  });
  
  // Inbox routes - require auth
  Object.entries(inboxRoutes).forEach(([path, handlers]) => {
    r.register(path, handlers);
  });
});


// Protected API routes - use API auth
router.group([apiAuthMiddleware], (r) => {
  // Email endpoints
  r.register('/api/email/receive', apiRoutes['/api/email/receive']);
  r.register('/api/email/fetch', apiRoutes['/api/email/fetch']);
  r.register('/api/email/pending-replies', apiRoutes['/api/email/pending-replies']);
  
  // Federation inbox (requires API auth for security)
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