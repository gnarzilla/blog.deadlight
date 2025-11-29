// src/middleware/ratelimit.js
import { voteLimiter, commentLimiter } from '../../../lib.deadlight/core/src/security/ratelimit.js';

export async function voteRateLimitMiddleware(request, env, ctx, next) {
  // Skip if proxy is handling rate limiting
  if (env.DISABLE_RATE_LIMITING === 'true') {
    return next();
  }
  
  const user = ctx.user || request.user;
  const ip = request.headers.get('CF-Connecting-IP');
  
  // Use user ID if authenticated, otherwise IP
  const identifier = user ? `user:${user.id}` : `ip:${ip}`;
  
  const result = await voteLimiter.isAllowed(request, env, identifier);
  
  if (!result.allowed) {
    return new Response('Too many votes. Please wait before voting again.', {
      status: 429,
      headers: {
        'Retry-After': Math.ceil((result.resetAt - Date.now()) / 1000).toString(),
        'X-RateLimit-Limit': voteLimiter.maxRequests.toString(),
        'X-RateLimit-Remaining': '0',
        'X-RateLimit-Reset': result.resetAt.toISOString()
      }
    });
  }
  
  return next();
}

export async function commentRateLimitMiddleware(request, env, ctx, next) {
  if (env.DISABLE_RATE_LIMITING === 'true') {
    return next();
  }
  
  const user = ctx.user || request.user;
  const ip = request.headers.get('CF-Connecting-IP');
  const identifier = user ? `user:${user.id}` : `ip:${ip}`;
  
  const result = await commentLimiter.isAllowed(request, env, identifier);
  
  if (!result.allowed) {
    return new Response('Too many comments. Please wait.', {
      status: 429,
      headers: {
        'Retry-After': Math.ceil((result.resetAt - Date.now()) / 1000).toString(),
        'X-RateLimit-Limit': commentLimiter.maxRequests.toString(),
        'X-RateLimit-Remaining': '0',
        'X-RateLimit-Reset': result.resetAt.toISOString()
      }
    });
  }
  
  return next();
}
