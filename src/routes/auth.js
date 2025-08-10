// src/routes/auth.js - Updated with better rate limiting
import { renderLoginForm } from '../templates/auth/index.js';
import { hashPassword, verifyPassword } from '../../../lib.deadlight/core/src/auth/password.js';
import { createJWT } from '../../../lib.deadlight/core/src/auth/jwt.js';
import { UserModel } from '../../../lib.deadlight/core/src/db/models/user.js';
import { Logger } from '../../../lib.deadlight/core/src/logging/logger.js';
import { Validator, FormValidator, CSRFProtection } from '../../../lib.deadlight/core/src/security/validation.js';
import { authLimiter } from '../../../lib.deadlight/core/src/security/ratelimit.js';

export const authRoutes = {
  '/login': {
    GET: async (request, env) => {
      // Generate simple CSRF token
      const csrfToken = CSRFProtection.generateToken();
      
      // Set CSRF cookie
      const headers = new Headers({
        'Content-Type': 'text/html',
        'Set-Cookie': `csrf_token=${csrfToken}; HttpOnly; SameSite=Strict; Path=/`
      });
      
      return new Response(renderLoginForm({ csrfToken }), { headers });
    },

    POST: async (request, env) => {
      const userModel = new UserModel(env.DB);
      const logger = new Logger({ context: 'auth' });
      
      // Check rate limit first
      const rateLimitResult = await authLimiter.isAllowed(request, env);
      if (!rateLimitResult.allowed) {
        const retryAfter = Math.ceil((rateLimitResult.resetAt - Date.now()) / 1000);
        logger.warn('Login rate limit exceeded');
        
        return new Response(renderLoginForm({ 
          error: `Too many login attempts. Please try again in ${Math.ceil(retryAfter / 60)} minutes.`
        }), {
          status: 429,
          headers: { 
            'Content-Type': 'text/html',
            'Retry-After': retryAfter.toString()
          }
        });
      }
      
      try {
        const formDataRequest = new Request(request.url, {
          method: request.method,
          headers: request.headers,
          body: request.body
        });

        const formData = await formDataRequest.formData();
        
        // Get CSRF tokens
        const cookieToken = CSRFProtection.getTokenFromCookie(request);
        const formToken = formData.get('csrf_token');
        
        // Simple CSRF validation - just check they match
        if (!cookieToken || !formToken || cookieToken !== formToken) {
          logger.warn('Invalid CSRF token in login attempt', { 
            hasCookie: !!cookieToken, 
            hasForm: !!formToken,
            match: cookieToken === formToken 
          });
          
          // Generate new token
          const newToken = CSRFProtection.generateToken();
          const headers = new Headers({
            'Content-Type': 'text/html',
            'Set-Cookie': `csrf_token=${newToken}; HttpOnly; SameSite=Strict; Path=/`
          });
          
          return new Response(renderLoginForm({ 
            error: 'Session expired. Please try again.',
            csrfToken: newToken
          }), {
            status: 400,
            headers
          });
        }
        
        // Validate form inputs
        const validation = await FormValidator.validateFormData(formData, {
          username: Validator.username,
          password: Validator.password
        });
        
        if (!validation.success) {
          logger.info('Login validation failed', { errors: validation.errors });
          
          return new Response(renderLoginForm({
            error: 'Please correct the following errors',
            validationErrors: validation.errors,
            username: Validator.escapeHTML(formData.get('username') || ''),
            csrfToken: cookieToken // Keep same token
          }), {
            status: 400,
            headers: { 'Content-Type': 'text/html' }
          });
        }
        
        const { username, password } = validation.data;
        logger.info('Login attempt', { username, passwordLength: password?.length });

        // Authenticate user
        const authResult = await userModel.authenticate(username, password);
        
        if (!authResult.success) {
          logger.warn('Failed login attempt', { username, reason: authResult.error });
          
          return new Response(renderLoginForm({
            error: 'Invalid username or password',
            username: Validator.escapeHTML(username),
            csrfToken: cookieToken // Keep same token
          }), {
            status: 401,
            headers: { 'Content-Type': 'text/html' }
          });
        }

        // SUCCESS - Clear rate limit
        const identifier = request.headers.get('CF-Connecting-IP') || 
                          request.headers.get('X-Forwarded-For') || 
                          'unknown';
        const rateLimitKey = `rl:auth:${identifier}`;
        await env.RATE_LIMIT.delete(rateLimitKey);
        logger.info('Cleared rate limit after successful login', { identifier });

        const { user } = authResult;
        await userModel.updateLastLogin(user.id);

        const token = await createJWT(
          { id: user.id, username: user.username, role: user.role || 'user' },
          env.JWT_SECRET
        );

        const url = new URL(request.url);
        const isSecure = url.protocol === 'https:';
        
        // Clear CSRF and set auth token
        const headers = new Headers({
          'Location': url.origin + '/'
        });
        
        headers.append('Set-Cookie', `token=${token}; HttpOnly; ${isSecure ? 'Secure; ' : ''}SameSite=Strict; Path=/`);
        headers.append('Set-Cookie', `csrf_token=; Path=/; Max-Age=0`);

        logger.info('Successful login', { 
          userId: user.id, 
          username: user.username
        });

        return new Response(null, { status: 303, headers });
        
      } catch (error) {
        logger.error('Login error', { error: error.message, stack: error.stack });
        
        // Generate new token for error
        const newToken = CSRFProtection.generateToken();
        const headers = new Headers({
          'Content-Type': 'text/html',
          'Set-Cookie': `csrf_token=${newToken}; HttpOnly; SameSite=Strict; Path=/`
        });
        
        return new Response(renderLoginForm({
          error: 'An error occurred. Please try again.',
          csrfToken: newToken
        }), {
          status: 500,
          headers
        });
      }
    }
  },

  '/logout': {
    GET: async (request, env) => {
      return new Response(null, {
        status: 302,
        headers: {
          'Location': '/',
          'Set-Cookie': `token=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0`
        }
      });
    },
    POST: async (request, env) => {
      return new Response(null, {
        status: 302,
        headers: {
          'Location': '/',
          'Set-Cookie': `token=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0`
        }
      });
    }
  },

  // Remove these temporary routes in production
  '/check-users': {
    GET: async (request, env) => {
      const result = await env.DB.prepare('SELECT id, username, role FROM users').all();
      return new Response(JSON.stringify(result.results, null, 2), {
        headers: { 'Content-Type': 'application/json' }
      });
    }
  },
  '/generate-admin': {
    GET: async (request, env) => {
      const { hashPassword } = await import('../../../lib.deadlight/core/src/auth/password.js');
      
      const password = 'gross-gnar';
      const { hash, salt } = await hashPassword(password);
      
      const html = `
        <h1>Admin User Creation</h1>
        <p>Password: ${password}</p>
        <p>Hash: ${hash}</p>
        <p>Salt: ${salt}</p>
        <h2>Run this command:</h2>
        <pre>wrangler d1 execute blog_content_v3 --local --command "INSERT INTO users (username, password, salt, role) VALUES ('admin', '${hash}', '${salt}', 'admin')"</pre>
      `;
      
      return new Response(html, {
        headers: { 'Content-Type': 'text/html' }
      });
    }
  },

  '/clear-login-limit': {
    GET: async (request, env) => {
      const identifier = request.headers.get('CF-Connecting-IP') || 
                        request.headers.get('X-Forwarded-For') || 
                        'unknown';
      const key = `rl:auth:${identifier}`;
      await env.RATE_LIMIT.delete(key);
      return new Response('Login rate limit cleared. <a href="/login">Try login again</a>', {
        status: 200,
        headers: { 'Content-Type': 'text/html' }
      });
    }
  }
};
