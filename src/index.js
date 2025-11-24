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
import { analyticsMiddleware } from './middleware/analytics.js';
import { handleProxyTests } from './routes/proxy.js';
import { initServices } from './services/index.js';

const router = new Router();

/* ==============================================================
   GLOBAL MIDDLEWARE
   ============================================================== */
router.use(errorMiddleware);
router.use(loggingMiddleware);
router.use(analyticsMiddleware);

/* ==============================================================
   PUBLIC ROUTES
   ============================================================== */
router.group([], (r) => {
  // Blog
  Object.entries(blogRoutes).forEach(([p, h]) => r.register(p, h));
  // Styles
  Object.entries(styleRoutes).forEach(([p, h]) => r.register(p, h));
  // Static assets
  Object.entries(staticRoutes).forEach(([p, h]) => r.register(p, h));
  // Auth (login / logout)
  Object.entries(authRoutes).forEach(([p, h]) => r.register(p, h));

  // Public API
  r.register('/api/health', apiRoutes['/api/health']);
  r.register('/api/status', apiRoutes['/api/status']);
  r.register('/api/blog/status', apiRoutes['/api/blog/status']);
  r.register('/api/blog/posts', apiRoutes['/api/blog/posts']);
  r.register('/api/metrics', apiRoutes['/api/metrics']);

  // Public federation discovery
  r.register('/.well-known/deadlight', federationRoutes['/.well-known/deadlight']);
  r.register('/api/federation/outbox', federationRoutes['/api/federation/outbox']);

  // Proxy-based federation helpers 
  r.register('/api/federation/connect', {
    POST: async (req, env) => {
      try {
        return await handleProxyTests.addFederationDomain(req, env);
      } catch (e) {
        console.error('Federation connect error:', e);
        return new Response(JSON.stringify({ success: false, error: e.message }), {
          status: 500,
          headers: { 'Content-Type': 'application/json' },
        });
      }
    },
  });
  r.register('/api/federation/test/*', federationRoutes['/api/federation/test/*']);
  r.register('/api/federation/remove', {
    POST: (req, env) => handleProxyTests.removeFederationDomain(req, env),
  });
});

/* ==============================================================
   AUTHENTICATED USER ROUTES
   ============================================================== */
router.group([authMiddleware], (r) => {
  Object.entries(userRoutes).forEach(([p, h]) => r.register(p, h));
  Object.entries(inboxRoutes).forEach(([p, h]) => r.register(p, h));
});

/* ==============================================================
   ADMIN ROUTES
   ============================================================== */
router.group([authMiddleware, requireAdminMiddleware], (r) => {
  Object.entries(adminRoutes).forEach(([p, h]) => r.register(p, h));
});

/* ==============================================================
   PROTECTED API (API-key)
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
   QUEUE PROCESSOR (replaces old OutboxService)
   ============================================================== */
let queueProcessorStarted = false;

async function startQueueProcessor(env, intervalMs = 30_000) { // 30 s default
  if (!env.ENABLE_QUEUE_PROCESSING) {
    console.log('Queue processing disabled (ENABLE_QUEUE_PROCESSING not set)');
    return;
  }
  if (queueProcessorStarted) return;
  queueProcessorStarted = true;

  const services = initServices(env);
  env.services = services;               // make it globally reachable for route handlers

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
    // Initialise services **once** per request (cheap because they are cached inside)
    const services = initServices(env);
    env.services = services;               // expose to all route handlers

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

  /** Cron entry point (optional – Cloudflare cron) */
  async scheduled(controller, env, ctx) {
    const services = initServices(env);
    await services.queue.processAll();
  },
};