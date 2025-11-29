// src/middleware/index.js
export { errorMiddleware } from './error.js';
export { loggingMiddleware } from './logging.js';
export { analyticsMiddleware } from './analytics.js';
export { authMiddleware, apiAuthMiddleware } from './auth.js';

export const requireAdminMiddleware = async (request, env, ctx, next) => {
  const user = ctx?.user || request?.user;
  
  const isAdmin = user?.isAdmin || user?.role === 'admin';
  
  if (!user || !isAdmin) {
    console.log('Admin check failed:', { user, isAdmin });
    const isApiRoute = request.url.includes('/api/');
    if (isApiRoute) {
      return new Response(JSON.stringify({ error: 'Forbidden' }), {
        status: 403,
        headers: { 'Content-Type': 'application/json' }
      });
    }
    return new Response('Forbidden', { status: 403 });
  }
  
  console.log('Admin check passed');
  return next();
};