// src/routes/auth.js - Enhanced with proxy auth integration
import { renderLoginForm } from '../templates/auth/index.js';
import { hashPassword, verifyPassword } from '../../../lib.deadlight/core/src/auth/password.js';
import { createJWT, verifyJWT } from '../../../lib.deadlight/core/src/auth/jwt.js';
import { UserModel } from '../../../lib.deadlight/core/src/db/models/user.js';
import { Logger } from '../../../lib.deadlight/core/src/logging/logger.js';
import { Validator, FormValidator, CSRFProtection } from '../../../lib.deadlight/core/src/security/validation.js';
import { authLimiter } from '../../../lib.deadlight/core/src/security/ratelimit.js';
import { ProxyService } from '../services/proxy.js';
import { ConfigService } from '../services/config.js';
import { checkAuth } from '../../../lib.deadlight/core/src/auth/password.js';
import { renderRegistrationForm } from '../templates/auth/register.js';

export const authRoutes = {
  '/login': {
    GET: async (request, env) => {
      // Check if already logged in
      const existingToken = request.headers.get('Cookie')?.match(/token=([^;]+)/)?.[1];
      if (existingToken) {
        try {
          // Verify with proxy if enabled
          if (env.USE_PROXY_AUTH) {
            const verification = await ProxyService.verify(existingToken);
            if (verification.valid) {
              return new Response(null, {
                status: 302,
                headers: { 'Location': '/' }
              });
            }
          } else {
            // Fallback to local verification
            const user = await verifyJWT(existingToken, env.JWT_SECRET);
            if (user) {
              return new Response(null, {
                status: 302,
                headers: { 'Location': '/' }
              });
            }
          }
        } catch (error) {
          // Invalid token, continue to login page
        }
      }
      
      // Generate CSRF token as before
      const csrfToken = CSRFProtection.generateToken();
      
      const headers = new Headers({
        'Content-Type': 'text/html',
        'Set-Cookie': `csrf_token=${csrfToken}; HttpOnly; SameSite=Strict; Path=/`
      });
      
      return new Response(renderLoginForm({ 
        csrfToken,
        useProxyAuth: env.USE_PROXY_AUTH 
      }), { headers });
    },

    POST: async (request, env) => {
      const userModel = new UserModel(env.DB);
      const logger = new Logger({ context: 'auth' });
      
      // Add debug logging BEFORE formData usage
      logger.info('Login POST request', { 
        useProxyAuth: env.USE_PROXY_AUTH,
        hasBody: request.body !== null
      });
      
      // For proxy auth, rate limiting is handled by the proxy
      if (!env.USE_PROXY_AUTH) {
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
      }
      
      try {
        const formDataRequest = new Request(request.url, {
          method: request.method,
          headers: request.headers,
          body: request.body
        });

        const formData = await formDataRequest.formData();
        
        // NOW we can log formData info
        logger.info('Login form data received', { 
          hasUsername: !!formData.get('username'),
          hasPassword: !!formData.get('password')
        });
        
        // CSRF validation...
        const cookieToken = CSRFProtection.getTokenFromCookie(request);
        const formToken = formData.get('csrf_token');
        
        if (!cookieToken || !formToken || cookieToken !== formToken) {
          logger.warn('Invalid CSRF token in login attempt');
          
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
        
        // Now fix the validation to work with your Validator class
        const usernameValidation = Validator.username(formData.get('username'));
        const passwordValidation = Validator.password(formData.get('password'));
        
        const errors = {};
        if (!usernameValidation.valid) {
          errors.username = usernameValidation.error;
        }
        if (!passwordValidation.valid) {
          errors.password = passwordValidation.error;
        }
        
        if (Object.keys(errors).length > 0) {
          logger.info('Login validation failed', { errors });
          
          return new Response(renderLoginForm({
            error: 'Please correct the following errors',
            validationErrors: errors,
            username: Validator.escapeHTML(formData.get('username') || ''),
            csrfToken: cookieToken
          }), {
            status: 400,
            headers: { 'Content-Type': 'text/html' }
          });
        }
        
        const username = formData.get('username');
        const password = formData.get('password');
        
        logger.info('Login attempt', { username, passwordLength: password?.length });

        // Authenticate user
        const authResult = await userModel.authenticate(username, password);
        
        if (!authResult.success) {
          logger.warn('Failed login attempt', { username, reason: authResult.error });
          
          return new Response(renderLoginForm({
            error: 'Invalid username or password',
            username: Validator.escapeHTML(username),
            csrfToken: cookieToken
          }), {
            status: 401,
            headers: { 'Content-Type': 'text/html' }
          });
        }

        // SUCCESS - rest of your code...
        const identifier = request.headers.get('CF-Connecting-IP') || 
                          request.headers.get('X-Forwarded-For') || 
                          'unknown';
        const rateLimitKey = `rl:auth:${identifier}`;

        if (env.DISABLE_RATE_LIMITING !== 'true' && env.RATE_LIMIT) {
          await env.RATE_LIMIT.delete(rateLimitKey);
        }
        logger.info('Cleared rate limit after successful login', { identifier });

        const { user } = authResult;
        await userModel.updateLastLogin(user.id);

        const token = await createJWT(
          { id: user.id, username: user.username, role: user.role || 'user' },
          env.JWT_SECRET
        );

        const url = new URL(request.url);
        const isSecure = url.protocol === 'https:';
        
        const headers = new Headers({
          'Location': user.role === 'admin' ? '/admin' : '/'
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

  '/register': {
    GET: async (request, env, ctx) => {
      // Check if registration is enabled
      const config = await env.services.config.getConfig();
      if (!config.enableRegistration) {
        return new Response('Registration is currently disabled', { status: 403 });
      }
      
      // Check if user is already logged in
      const existingUser = await checkAuth(request, env);
      if (existingUser) {
        const redirectPath = existingUser.role === 'admin' ? '/admin' : `/user/${existingUser.username}`;
        return new Response(null, {
          status: 302,
          headers: {
            'Location': redirectPath
          }
        });
      }
      
      return new Response(renderRegistrationForm(config), {
        headers: { 'Content-Type': 'text/html' }
      });
    },
    POST: async (request, env, ctx) => {
      const config = await env.services.config.getConfig();
      if (!config.enableRegistration) {
        return new Response('Registration is currently disabled', { status: 403 });
      }
      
      try {
        const formData = await request.formData();
        const username = formData.get('username');
        const password = formData.get('password');
        const confirmPassword = formData.get('confirmPassword');
        const email = formData.get('email');
        
        // Check registration rate limit by IP
        const clientIp = request.headers.get('cf-connecting-ip') || 'unknown';
        
        // Store recent registrations in a simple way
        const recentAttempts = await env.DB.prepare(`
          SELECT COUNT(*) as count 
          FROM users 
          WHERE created_at > datetime('now', '-1 hour')
        `).first();
        
        // For now, just limit total registrations per hour (not per IP)
        if (recentAttempts.count >= 10) {
          throw new Error('Registration temporarily limited. Please try again later.');
        }
        
        // Alternative: Use request_logs table to check IP-based limits
        const ipAttempts = await env.DB.prepare(`
          SELECT COUNT(DISTINCT path) as count 
          FROM request_logs 
          WHERE ip = ? 
            AND path = '/register'
            AND method = 'POST'
            AND timestamp > datetime('now', '-1 hour')
        `).bind(clientIp).first();
        
        if (ipAttempts.count >= 3) {
          throw new Error('Too many registration attempts from your IP. Please try again later.');
        }
        
        // Verify captcha
        const captchaAnswer = formData.get('captcha');
        const captchaHash = formData.get('captcha_hash');
        if (!captchaAnswer || !captchaHash || btoa(captchaAnswer) !== captchaHash) {
          throw new Error('Incorrect security answer');
        }
        
        // Enhanced username validation
        if (!username || !password) {
          throw new Error('Username and password are required');
        }
        
        // Block suspicious usernames
        const suspiciousPatterns = [
          /https?:\/\//i,              // URLs
          /\.com|\.org|\.net/i,        // Domain extensions
          /bitcoin|btc|crypto|eth/i,   // Crypto terms
          /exclusive.*deal/i,          // Spam phrases
          /\d{10,}/,                   // Long number sequences
          /.{50,}/                     // Too long
        ];
        
        if (suspiciousPatterns.some(pattern => pattern.test(username))) {
          throw new Error('Invalid username format');
        }
        
        // Reasonable username constraints
        if (username.length < 3 || username.length > 20) {
          throw new Error('Username must be 3-20 characters');
        }
        
        if (!/^[a-zA-Z0-9_-]+$/.test(username)) {
          throw new Error('Username can only contain letters, numbers, underscore, and hyphen');
        }
        
        if (password !== confirmPassword) {
          throw new Error('Passwords do not match');
        }
        
        if (password.length < 8) {
          throw new Error('Password must be at least 8 characters');
        }
        
        // Check if username exists
        const userModel = new UserModel(env.DB);
        const existing = await userModel.getByUsername(username);
        if (existing) {
          throw new Error('Username already taken');
        }
        
        // Create user (non-admin by default)
        const newUser = await userModel.create({
          username,
          password,
          email,
          role: 'user'
        });
        
        // Log them in automatically
        const token = await createJWT({
          id: newUser.id,
          username: newUser.username,
          role: newUser.role
        }, env.JWT_SECRET);
        
        // Create redirect URL
        const redirectUrl = new URL(`/user/${newUser.username}`, request.url).toString();
        
        // Create response with both redirect and cookie
        return new Response(null, {
          status: 302,
          headers: {
            'Location': redirectUrl,
            'Set-Cookie': `token=${token}; HttpOnly; Secure; SameSite=Strict; Path=/`
          }
        });
        
      } catch (error) {
        // Pass the error back to show in the form
        return new Response(renderRegistrationForm(config, error.message), {
          status: 400,
          headers: { 'Content-Type': 'text/html' }
        });
      }
    }
  },

  '/auth/refresh': {
    POST: async (request, env) => {
      if (!env.USE_PROXY_AUTH) {
        return new Response('Not available', { status: 404 });
      }
      
      const logger = new Logger({ context: 'auth-refresh' });
      
      try {
        // Get refresh token from cookie
        const refreshToken = request.headers.get('Cookie')?.match(/refresh_token=([^;]+)/)?.[1];
        
        if (!refreshToken) {
          return new Response(JSON.stringify({ error: 'No refresh token' }), {
            status: 401,
            headers: { 'Content-Type': 'application/json' }
          });
        }
        
        // Call proxy refresh endpoint
        const result = await ProxyService.refresh(refreshToken);
        
        // Return new tokens
        const headers = new Headers({ 'Content-Type': 'application/json' });
        
        // Update access token cookie
        headers.append('Set-Cookie', 
          `token=${result.accessToken}; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=3600`
        );
        
        // Update refresh token cookie if provided
        if (result.refreshToken) {
          headers.append('Set-Cookie', 
            `refresh_token=${result.refreshToken}; HttpOnly; Secure; SameSite=Strict; Path=/auth/refresh; Max-Age=${30 * 24 * 60 * 60}`
          );
        }
        
        return new Response(JSON.stringify({
          access_token: result.accessToken,
          expires_in: 3600
        }), { headers });
        
      } catch (error) {
        logger.error('Refresh token error', { error: error.message });
        
        return new Response(JSON.stringify({ error: 'Invalid refresh token' }), {
          status: 401,
          headers: { 'Content-Type': 'application/json' }
        });
      }
    }
  },

  '/logout': {
    GET: async (request, env, ctx) => {
      return authRoutes['/logout'].POST(request, env, ctx); // Add ctx parameter
    },
    
    POST: async (request, env, ctx) => {
      const logger = new Logger({ context: 'auth-logout' });
      
      // If using proxy auth, notify it
      if (env.USE_PROXY_AUTH === 'true') { // Check string value
        const token = request.headers.get('Cookie')?.match(/token=([^;]+)/)?.[1];
        if (token) {
          try {
            // If authService uses browser APIs, skip it in Worker environment
            if (typeof document === 'undefined') {
              // We're in a Worker, make a direct HTTP call to proxy instead
              await fetch(`${env.PROXY_URL}/api/auth/logout`, {
                method: 'POST',
                headers: {
                  'Authorization': `Bearer ${token}`,
                  'Content-Type': 'application/json'
                }
              });
            } else {
              // Browser environment (shouldn't happen in Worker)
              await ProxyService.logout(token);
            }
          } catch (error) {
            logger.warn('Proxy logout failed', { error: error.message });
            // Don't throw - continue with local logout even if proxy fails
          }
        }
      }
      
      // Clear all auth cookies
      const headers = new Headers({ 'Location': '/' });
      headers.append('Set-Cookie', `token=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0`);
      headers.append('Set-Cookie', `refresh_token=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0`);
      
      return new Response(null, { status: 302, headers });
    }
  },

  // Remove these temporary routes in production
  //'/check-users': {
  //  GET: async (request, env) => {
  //    const result = await env.DB.prepare('SELECT id, username, role FROM users').all();
  //    return new Response(JSON.stringify(result.results, null, 2), {
  //      headers: { 'Content-Type': 'application/json' }
  //    });
  //  }
  // },

  '/generate-admin': {
    GET: async (request, env) => {
      
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
}

