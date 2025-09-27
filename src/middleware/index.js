// src/middleware/index.js - Simplified
export { errorMiddleware } from './error.js';
export { loggingMiddleware } from './logging.js';
export { analyticsMiddleware } from './analytics.js';
export { authMiddleware, apiAuthMiddleware } from './auth.js';

// Admin middleware
export const requireAdminMiddleware = async (request, env, ctx, next) => {
  // Check both possible admin indicators
  const isAdmin = request.user?.isAdmin || request.user?.role === 'admin';
  
  if (!request.user || !isAdmin) {
    const isApiRoute = request.url.includes('/api/');
    if (isApiRoute) {
      return new Response(JSON.stringify({ error: 'Forbidden' }), {
        status: 403,
        headers: { 'Content-Type': 'application/json' }
      });
    }
    return new Response('Forbidden', { status: 403 });
  }
  return next();
};