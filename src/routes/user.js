// src/routes/user.js
import { checkAuth } from '../../../lib.deadlight/core/src/auth/password.js';

// Username validation (reusing your slug pattern)
function validateUsername(username) {
  const RESERVED_SUBDOMAINS = [
    'www', 'api', 'blog', 'proxy', 'comm', 'email', 'lib', 'admin', 'root',
    'help', 'support', 'popular', 'trending', 'feed', 'deadlight', 'official',
    'staff', 'team', 'system', 'config', 'manage', 'test', 'demo'
  ];
  
  const errors = [];
  
  if (username.length < 3) errors.push('Too short (min 3 chars)');
  if (username.length > 20) errors.push('Too long (max 20 chars)');
  
  if (RESERVED_SUBDOMAINS.includes(username.toLowerCase())) {
    errors.push('Username not available');
  }
  
  // Same pattern as your slugs: [a-z0-9-]+, but can't start/end with hyphen
  if (!/^[a-z0-9][a-z0-9-]*[a-z0-9]$/.test(username.toLowerCase()) && username.length > 1) {
    errors.push('Invalid format (letters, numbers, hyphens only; no leading/trailing hyphens)');
  }
  
  return {
    valid: errors.length === 0,
    errors
  };
}

export const userRoutes = {
  '/user/:username': {
    GET: async (request, env) => {
      try {
        const username = request.params.username.toLowerCase();
        const currentUser = await checkAuth(request, env);
        
        // Get dynamic config
        const { configService } = await import('../services/config.js');
        const config = await configService.getConfig(env.DB);
        
        // Find user by subdomain (which should match username)
        const user = await env.DB.prepare(`
          SELECT u.*, 
                 COUNT(p.id) as post_count,
                 MAX(p.created_at) as last_post_date
          FROM users u
          LEFT JOIN posts p ON u.id = p.author_id 
            AND p.published = 1 
            AND (p.is_email = 0 OR p.is_email IS NULL)
          WHERE LOWER(u.subdomain) = ? OR LOWER(u.username) = ?
          GROUP BY u.id
        `).bind(username, username).first();
        
        if (!user) {
          return new Response('User not found', { status: 404 });
        }
        
        // Get user's recent posts (paginated)
        const url = new URL(request.url);
        const page = parseInt(url.searchParams.get('page') || '1');
        const postsPerPage = 10;
        const offset = (page - 1) * postsPerPage;
        
        const posts = await env.DB.prepare(`
          SELECT id, title, slug, content, excerpt, created_at, updated_at, published
          FROM posts 
          WHERE author_id = ? 
            AND published = 1 
            AND (is_email = 0 OR is_email IS NULL)
          ORDER BY created_at DESC
          LIMIT ? OFFSET ?
        `).bind(user.id, postsPerPage, offset).all();
        
        // Get total post count for pagination
        const totalResult = await env.DB.prepare(`
          SELECT COUNT(*) as total 
          FROM posts 
          WHERE author_id = ? 
            AND published = 1 
            AND (is_email = 0 OR is_email IS NULL)
        `).bind(user.id).first();
        
        const totalPosts = totalResult.total;
        const totalPages = Math.ceil(totalPosts / postsPerPage);
        
        const pagination = {
          currentPage: page,
          totalPages,
          totalPosts,
          hasNext: page < totalPages,
          hasPrevious: page > 1,
          nextPage: page + 1,
          previousPage: page - 1
        };
        
        // Create user profile template
        const { renderUserProfile } = await import('../templates/user/profile.js');
        return new Response(renderUserProfile(user, posts.results, currentUser, config, pagination), {
          headers: { 'Content-Type': 'text/html' }
        });
        
      } catch (error) {
        console.error('User profile error:', error);
        return new Response('Internal server error', { status: 500 });
      }
    }
  }
};
