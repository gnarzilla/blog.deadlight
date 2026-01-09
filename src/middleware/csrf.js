// src/middleware/csrf.js 

import { CSRFProtection } from '../../../lib.deadlight/core/src/security/validation.js';

/**
 * Middleware to generate CSRF token and attach to context
 * Use this on GET requests to provide token to forms
 */
export async function csrfTokenMiddleware(request, env, ctx, next) {
  // Check if token exists in cookie
  let csrfToken = CSRFProtection.getTokenFromCookie(request);
  
  // If not, generate new token
  if (!csrfToken) {
    csrfToken = CSRFProtection.generateToken();
  }
  
  // Attach to context for use in templates
  ctx.csrfToken = csrfToken;
  
  // Get response from next middleware
  const response = await next();
  
  // Clone response and add Set-Cookie header
  const newResponse = new Response(response.body, {
    status: response.status,
    statusText: response.statusText,
    headers: new Headers(response.headers)
  });
  
  // Set cookie on the NEW response
  const cookie = `csrf_token=${csrfToken}; Path=/; HttpOnly; SameSite=Strict; Max-Age=3600`;
  newResponse.headers.append('Set-Cookie', cookie);
  
  return newResponse;
}

/**
 * Middleware to validate CSRF token on mutating requests
 * Use this on POST/PUT/DELETE/PATCH endpoints
 */
export async function csrfValidateMiddleware(request, env, ctx, next) {
  if (!['POST', 'PUT', 'DELETE', 'PATCH'].includes(request.method)) {
    return next();
  }
  
  const cookieToken = CSRFProtection.getTokenFromCookie(request);
  
  let submittedToken;
  try {
    const clonedRequest = request.clone();
    const formData = await clonedRequest.formData();
    submittedToken = formData.get('csrf_token');
  } catch (e) {
    console.error('Failed to read form data:', e);
  }
  
  const valid = cookieToken && submittedToken && cookieToken === submittedToken;
  
  if (!valid) {
    console.log('CSRF validation failed', {
      cookieToken: cookieToken ? 'present' : 'missing',
      submittedToken: submittedToken ? 'present' : 'missing',
      match: cookieToken === submittedToken
    });
    return new Response('Invalid CSRF token. Please refresh and try again.', { 
      status: 403,
      headers: { 'Content-Type': 'text/plain' }
    });
  }
  
  console.log('CSRF validation passed');
  return next();
}