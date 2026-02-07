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
import { commentRoutes } from './routes/comments.js';
import { errorMiddleware, loggingMiddleware } from './middleware/index.js';
import { authMiddleware, apiAuthMiddleware, requireAdminMiddleware } from './middleware/index.js';
import { rateLimitMiddleware, securityHeadersMiddleware } from '../../lib.deadlight/core/src/security/middleware.js';
import { analyticsMiddleware } from './middleware/analytics.js';
import { csrfTokenMiddleware, csrfValidateMiddleware } from './middleware/csrf.js';
import { voteRateLimitMiddleware, commentRateLimitMiddleware } from './middleware/rateLimit.js';
import { initServices } from './services/index.js';
import { proxyOrchestrationMiddleware } from './middleware/proxy-orchestration.js';

const router = new Router();

/* ==============================================================
   GLOBAL MIDDLEWARE
   ============================================================== */
router.use(errorMiddleware);
router.use(loggingMiddleware);
router.use(analyticsMiddleware);
router.use(proxyOrchestrationMiddleware);

/* ==============================================================
   PUBLIC ROUTES (with CSRF token generation for forms)
   ============================================================== */
router.group([csrfTokenMiddleware], (r) => {
  // Blog routes (need CSRF token for vote forms)
  Object.entries(blogRoutes).forEach(([p, h]) => r.register(p, h));
  Object.entries(styleRoutes).forEach(([p, h]) => r.register(p, h));
  Object.entries(staticRoutes).forEach(([p, h]) => r.register(p, h));

  // Public API (no CSRF needed - read-only)
  r.register('/api/health', apiRoutes['/api/health']);
  r.register('/api/status', apiRoutes['/api/status']);
  r.register('/api/blog/status', apiRoutes['/api/blog/status']);
  r.register('/api/blog/posts', apiRoutes['/api/blog/posts']);
  r.register('/api/metrics', apiRoutes['/api/metrics']);

  // Public federation endpoints (discovery & outbox)
  r.register('/.well-known/deadlight', federationRoutes['/.well-known/deadlight']);
  r.register('/api/federation/outbox', federationRoutes['/api/federation/outbox']);
  r.register('/api/federation/test/*', federationRoutes['/api/federation/test/*']);
});

/* ==============================================================
   VOTE ENDPOINTS (auth + vote rate limit + CSRF validation)
   ============================================================== */
router.group([authMiddleware, voteRateLimitMiddleware, csrfValidateMiddleware], (r) => {
  r.register('/api/posts/:id/upvote', apiRoutes['/api/posts/:id/upvote']);
  r.register('/api/posts/:id/downvote', apiRoutes['/api/posts/:id/downvote']);
});

/* ==============================================================
   COMMENT ENDPOINTS (auth + comment rate limit + CSRF validation)
   ============================================================== */
router.group([authMiddleware, commentRateLimitMiddleware, csrfValidateMiddleware, csrfTokenMiddleware], (r) => {
  // Blog post comments (inline commenting)
  r.register('/post/:slug/comment', blogRoutes['/post/:slug/comment']);
  
  // Comment management routes
  Object.entries(commentRoutes).forEach(([p, h]) => r.register(p, h));
});

/* ==============================================================
   AUTHENTICATED USER ROUTES (with CSRF token)
   ============================================================== */
router.group([authMiddleware, csrfTokenMiddleware], (r) => {
  Object.entries(userRoutes).forEach(([p, h]) => r.register(p, h));
  Object.entries(inboxRoutes).forEach(([p, h]) => r.register(p, h));
});

/* ==============================================================
   AUTH ROUTES (with CSRF token generation + validation)
   ============================================================== */
router.group([csrfTokenMiddleware, csrfValidateMiddleware], (r) => {
  Object.entries(authRoutes).forEach(([p, h]) => r.register(p, h));
});

/* ==============================================================
   ADMIN ROUTES (auth + admin check + CSRF token)
   ============================================================== */
router.group([authMiddleware, requireAdminMiddleware, csrfTokenMiddleware], (r) => {
  // Core admin routes
  Object.entries(adminRoutes).forEach(([path, handler]) => {
    r.register(path, handler);
  });

  // Federation admin endpoints (require admin auth + CSRF)
  r.register('/api/federation/trust', federationRoutes['/api/federation/trust']);
  r.register('/api/federation/follow', federationRoutes['/api/federation/follow']);
  r.register('/api/federation/connect', federationRoutes['/api/federation/connect']);
  r.register('/api/federation/queue', federationRoutes['/api/federation/queue']);
});

/* ==============================================================
   PROTECTED API (API-key authentication)
   ============================================================== */
router.group([apiAuthMiddleware], (r) => {
  r.register('/api/email/receive', apiRoutes['/api/email/receive']);
  r.register('/api/email/fetch', apiRoutes['/api/email/fetch']);
  r.register('/api/email/pending-replies', apiRoutes['/api/email/pending-replies']);
  r.register('/api/federation/inbox', federationRoutes['/api/federation/inbox']);
});

/* ==============================================================
   DEBUG – list routes (optional)
   ============================================================== */
console.log('Routes registered:', Array.from(router.routes.keys()));

/* ==============================================================
   QUEUE PROCESSOR 
   ============================================================== */
let queueProcessorStarted = false;

async function startQueueProcessor(env, intervalMs = 30_000) { // 30 seconds default
  if (!env.ENABLE_QUEUE_PROCESSING) {
    console.log('Queue processing disabled (ENABLE_QUEUE_PROCESSING not set)');
    return;
  }
  if (queueProcessorStarted) return;
  queueProcessorStarted = true;

  const services = initServices(env);
  env.services = services;

  setInterval(async () => {
    try {
      const result = await services.queue.processAll();
      console.log(`Queue processed: ${result.processed} ops, ${result.queued?.total ?? 0} remaining`);
    } catch (err) {
      console.error('Queue processing error:', err);
    }
  }, intervalMs);
}

/* ==============================================================
   EXPORTED WORKER
   ============================================================== */
export default {
  /** HTTP entry point */
  async fetch(request, env, ctx) {
    // Initialize services once per request (cached internally)
    const services = initServices(env);
    env.services = services;

    // Start background queue processor (fire-and-forget)
    ctx.waitUntil(startQueueProcessor(env));

    // Rate-limiting toggle
    const next = () => router.handle(request, env, ctx);

    if (env.DISABLE_RATE_LIMITING === 'true') {
      return securityHeadersMiddleware(request, env, ctx, next);
    }

    return rateLimitMiddleware(request, env, ctx, () =>
      securityHeadersMiddleware(request, env, ctx, next)
    );
  },

  /** Cron entry point (Cloudflare cron) */
  async scheduled(event, env, ctx) {
    console.log('Cron job started:', new Date().toISOString());
    
    try {
      // Initialize services
      const services = initServices(env);
      env.services = services;
      
      // Process queue
      const result = await services.queue.processAll();
      
      console.log('Queue processing completed:', {
        processed: result.processed,
        status: result.status,
        errors: result.errors || [],
        timestamp: new Date().toISOString()
      });
      
      // If items were processed, log details
      if (result.processed > 0) {
        console.log(`Successfully processed ${result.processed} queued items`);
      }
      
      return result;
      
    } catch (error) {
      console.error('Cron job failed:', {
        error: error.message,
        stack: error.stack,
        timestamp: new Date().toISOString()
      });
      
      // Don't throw - let the job complete
      return { processed: 0, status: 'error', error: error.message };
    }
  }
};