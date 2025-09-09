// blog.deadlight/src/middleware/auth.js
import { parseCookies } from '../utils.js';
import { verifyJWT } from '../../lib.deadlight/src/core/auth/jwt.js';
import { authService } from '../services/auth-proxy.js';

export const authMiddleware = async (request, env) => {
  const cookies = parseCookies(request);
  const token = cookies.token || getTokenFromHeader(request);
  
  if (!token) {
    throw new Error('Unauthorized');
  }

  // Try proxy auth first if enabled
  if (env.USE_PROXY_AUTH) {
    try {
      const verification = await authService.verify(token);
      if (verification.valid) {
        request.user = {
          id: verification.userId,
          username: verification.username,
          // Map to your existing user structure
          userId: verification.userId
        };
        return request;
      }
    } catch (error) {
      console.error('Proxy auth failed, falling back to local:', error);
    }
  }

  // Fallback to local JWT verification
  const user = await verifyJWT(token, env.JWT_SECRET);
  if (!user) {
    throw new Error('Unauthorized');
  }

  request.user = user;
  return request;
};

function getTokenFromHeader(request) {
  const authHeader = request.headers.get('Authorization');
  if (authHeader && authHeader.startsWith('Bearer ')) {
    return authHeader.substring(7);
  }
  return null;
}

export const protected_routes = (handler) => {
  return async (request, env) => {
    await authMiddleware(request, env);
    return handler(request, env);
  };
};