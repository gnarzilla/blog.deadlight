import { parseCookies } from '../utils.js';
import { verifyJWT } from '../../lib.deadlight/src/core/auth/jwt.js';

export const authMiddleware = async (request, env) => {
  const cookies = parseCookies(request);
  const token = cookies.token;
  
  if (!token) {
    throw new Error('Unauthorized');
  }

  const user = await verifyJWT(token, env.JWT_SECRET);
  if (!user) {
    throw new Error('Unauthorized');
  }

  // Attach user to request object for use in handlers
  request.user = user;
  return request;
};

// Helper for protected routes
export const protected_routes = (handler) => {
  return async (request, env) => {
    await authMiddleware(request, env);
    return handler(request, env);
  };
};