// src/middleware/api-auth.js
export async function checkApiAuth(request, env) {
  // Check Bearer token
  const authHeader = request.headers.get('Authorization');
  if (authHeader && authHeader.startsWith('Bearer ')) {
    const token = authHeader.substring(7);
    const expectedToken = env.DEADLIGHT_API_TOKEN || env.API_KEY;
    return token === expectedToken;
  }
  
  // Check X-API-Key header
  const apiKey = request.headers.get('X-API-Key');
  if (apiKey) {
    const expectedKey = env.X_API_KEY || env.API_KEY;
    return apiKey === expectedKey;
  }
  
  // Allow localhost for development
  const origin = request.headers.get('Origin') || '';
  if (env.ALLOW_LOCALHOST && (origin.includes('localhost') || origin.includes('127.0.0.1'))) {
    return true;
  }
  
  return false;
}