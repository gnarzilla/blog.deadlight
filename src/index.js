import { Router } from './routes/index.js';
import { styleRoutes } from './routes/styles.js';
import { staticRoutes } from './routes/static.js';
import { authRoutes } from './routes/auth.js';
import { adminRoutes } from './routes/admin.js';
import { blogRoutes } from './routes/blog.js';
import { inboxRoutes } from './routes/inbox.js';
import { userRoutes } from './routes/user.js';
import { errorMiddleware } from './middleware/error.js';
import { loggingMiddleware } from './middleware/logging.js';
import { rateLimitMiddleware, securityHeadersMiddleware } from '../../lib.deadlight/core/src/security/middleware.js';
import { OutboxService } from './services/outbox.js';

const router = new Router();

// Add middleware
router.use(errorMiddleware);
router.use(loggingMiddleware);

// Register routes
[
  { name: 'blog', routes: blogRoutes },
  { name: 'user', routes: userRoutes },
  { name: 'style', routes: styleRoutes },
  { name: 'static', routes: staticRoutes },
  { name: 'auth', routes: authRoutes },
  { name: 'admin', routes: adminRoutes },
  { name: 'inbox', routes: inboxRoutes }
].forEach(({ name, routes }) => {
  console.log(`Registering ${name} routes:`, Object.keys(routes));
  Object.entries(routes).forEach(([path, handlers]) => {
    router.register(path, handlers);
  });
});

// Start queue processor when Worker initializes
let queueProcessorStarted = false;
async function startQueueProcessor(env, intervalMs = 300000) { // 5 minutes
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
    // Start queue processor on first request
    ctx.waitUntil(startQueueProcessor(env));
    // Apply security middleware
    return rateLimitMiddleware(request, env, ctx, () =>
      securityHeadersMiddleware(request, env, ctx, () =>
        router.handle(request, env, ctx)
      )
    );
  }
};