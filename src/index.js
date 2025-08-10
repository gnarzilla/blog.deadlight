// src/index.js
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

const router = new Router();

// Add middleware in order (error handling should be first to catch all errors)
router.use(errorMiddleware);
router.use(loggingMiddleware);

// Debug log
console.log('Registering routes...');

// Register all routes
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

export default {
  async fetch(request, env, ctx) {
    // Apply security middleware
    return rateLimitMiddleware(request, env, ctx, () =>
      securityHeadersMiddleware(request, env, ctx, () =>
        router.handle(request, env, ctx)
      )
    );
  }
};
