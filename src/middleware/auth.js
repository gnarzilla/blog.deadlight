// src/middleware/auth.js
import { parseCookies } from '../utils/utils.js';
import { verifyJWT } from '../../../lib.deadlight/core/src/auth/jwt.js';

export async function checkAuth(request, env) {
  // Check API authentication first (for API routes)
  if (request.url.includes('/api/')) {
    return checkApiAuth(request, env);
  }
  
  const cookies = parseCookies(request);
  const token = cookies.token || getTokenFromHeader(request);
  
  if (!token) return null;

  if (env.USE_PROXY_AUTH) {
    try {
     
      const verification = await env.services.proxy.verify(token);
      if (verification.valid) {
        return {
          id: verification.userId,
          username: verification.username,
          userId: verification.userId,
          isAdmin: verification.isAdmin || false
        };
      }
    } catch (error) {
      console.error('Proxy auth failed, falling back to local:', error);
    }
  }

  // Fallback to local JWT
  try {
    const user = await verifyJWT(token, env.JWT_SECRET);
    return user;
  } catch {
    return null;
  }
}

async function checkApiAuth(request, env) {
  const authHeader = request.headers.get('Authorization');
  if (authHeader?.startsWith('Bearer ')) {
    const token = authHeader.substring(7);
    const expectedToken = env.DEADLIGHT_API_TOKEN || env.API_KEY;
    if (token === expectedToken) {
      return { id: 'api', username: 'api', isAdmin: true };
    }
  }
  
  const apiKey = request.headers.get('X-API-Key');
  if (apiKey) {
    const expectedKey = env.X_API_KEY || env.API_KEY;
    if (apiKey === expectedKey) {
      return { id: 'api', username: 'api', isAdmin: true };
    }
  }
  
  const origin = request.headers.get('Origin') || '';
  if (env.ALLOW_LOCALHOST && (origin.includes('localhost') || origin.includes('127.0.0.1'))) {
    return { id: 'localhost', username: 'localhost', isAdmin: true };
  }
  
  return null;
}

export async function authMiddleware(request, env, ctx, next) {
  console.log('authMiddleware CALLED for:', request.url);
  
  // Check if cookie exists
  const cookies = request.headers.get('Cookie') || '';
  console.log('Cookies received:', cookies);
  
  const user = await checkAuth(request, env);
  
  console.log('authMiddleware debug:', {
    hasUser: !!user,
    username: user?.username,
    role: user?.role,
    isAdmin: user?.isAdmin
  });
  
  if (!user) {
    if (request.url.includes('/api/')) {
      return new Response(JSON.stringify({ error: 'Unauthorized' }), {
        status: 401,
        headers: { 'Content-Type': 'application/json' }
      });
    }
    return Response.redirect(new URL('/login', request.url).toString(), 302);
  }
  
  request.user = user;
  ctx.user = user;      
  
  return next();       
}
export async function optionalAuthMiddleware(request, env, ctx, next) {
  const user = await checkAuth(request, env);
  if (user) {
    request.user = user;
    ctx.user = user;
  }
  return next();
}

// API-specific auth middleware
export async function apiAuthMiddleware(request, env, ctx, next) {
  const authHeader = request.headers.get('Authorization');
  const apiKey = request.headers.get('X-API-Key');
  
  const validToken = authHeader?.startsWith('Bearer ') && 
                     authHeader.substring(7) === (env.DEADLIGHT_API_TOKEN || env.API_KEY);
  const validKey = apiKey === (env.X_API_KEY || env.API_KEY);
  
  const origin = request.headers.get('Origin') || '';
  const allowLocalhost = env.ALLOW_LOCALHOST && 
                        (origin.includes('localhost') || origin.includes('127.0.0.1'));
  
  if (!validToken && !validKey && !allowLocalhost) {
    return new Response(JSON.stringify({ error: 'Invalid API credentials' }), {
      status: 401,
      headers: { 'Content-Type': 'application/json' }
    });
  }
  
  request.user = { id: 'api', username: 'api', isAdmin: true };
  ctx.user = apiUser
  return next();
}

export const requireAuth = (handler) => async (request, env, ctx) => {
  const user = await checkAuth(request, env);
  if (!user) {
    return request.url.includes('/api/')
      ? Response.json({ error: 'Unauthorized' }, { status: 401 })
      : Response.redirect(new URL('/login', request.url).toString(), 302);
  }
  request.user = user;
  ctx.user = user;
  return handler(request, env, ctx);
};

function getTokenFromHeader(request) {
  const authHeader = request.headers.get('Authorization');
  if (authHeader?.startsWith('Bearer ')) {
    return authHeader.substring(7);
  }
  return null;
}