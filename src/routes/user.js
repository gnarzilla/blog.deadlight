// src/routes/user.js
import { checkAuth } from '../../../lib.deadlight/core/src/auth/password.js';
import { renderUserProfile } from '../templates/user/profile.js';
import { configService } from '../services/config.js';
import { renderUserPostForm } from '../templates/admin/addPost.js'
import { UserModel, PostModel } from '../../../lib.deadlight/core/src/db/models/index.js'
import { renderUserSettings } from '../templates/user/settings.js';

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
    GET: async (request, env, ctx) => {
      try {
        const username = request.params.username.toLowerCase();
        const currentUser = await checkAuth(request, env);
        
        // Get dynamic config
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
        
        return new Response(renderUserProfile(user, posts.results, currentUser, config, pagination), {
          headers: { 'Content-Type': 'text/html' }
        });
        
      } catch (error) {
        console.error('User profile error:', error);
        return new Response('Internal server error', { status: 500 });
      }
    }
  },

  '/user/:username/settings': {
    GET: async (request, env, ctx) => {
      const currentUser = await checkAuth(request, env);
      const username = request.params.username;
      
      // Users can only edit their own settings
      if (!currentUser || currentUser.username !== username) {
        return Response.redirect(new URL('/login', request.url).toString(), 302);
      }
      
      // Get user's current settings
      const user = await env.DB.prepare(`
        SELECT * FROM users WHERE id = ?
      `).bind(currentUser.id).first();
      
      // Get any additional settings from user_settings table
      const additionalSettings = await env.DB.prepare(`
        SELECT key, value FROM user_settings WHERE user_id = ?
      `).bind(currentUser.id).all();
      
      const config = await configService.getConfig(env.DB);
      
      const { renderUserSettings } = await import('../templates/user/settings.js');
      return new Response(renderUserSettings(user, additionalSettings.results || [], config), {
        headers: { 'Content-Type': 'text/html' }
      });
    },
    
    POST: async (request, env, ctx) => {
      const currentUser = await checkAuth(request, env);
      const username = request.params.username;
      
      if (!currentUser || currentUser.username !== username) {
        return new Response('Unauthorized', { status: 403 });
      }
      
      try {
        const formData = await request.formData();
        
        // Update main user fields
        await env.DB.prepare(`
          UPDATE users SET 
            email = ?,
            profile_title = ?,
            profile_description = ?,
            updated_at = CURRENT_TIMESTAMP
          WHERE id = ?
        `).bind(
          formData.get('email') || null,
          formData.get('profile_title') || null,
          formData.get('profile_description') || null,
          currentUser.id
        ).run();
        
        // Handle password change if provided
        const newPassword = formData.get('new_password');
        const confirmPassword = formData.get('confirm_password');
        
        if (newPassword) {
          if (newPassword !== confirmPassword) {
            throw new Error('Passwords do not match');
          }
          
          if (newPassword.length < 8) {
            throw new Error('Password must be at least 8 characters');
          }
          
          // Use your existing password hashing
          const { hashPassword } = await import('../../../lib.deadlight/core/src/auth/password.js');
          const { hash, salt } = await hashPassword(newPassword);
          
          await env.DB.prepare(`
            UPDATE users SET password = ?, salt = ? WHERE id = ?
          `).bind(hash, salt, currentUser.id).run();
        }
        
        // Redirect back to profile
        const redirectUrl = new URL(`/user/${username}`, request.url).toString();
        return Response.redirect(redirectUrl, 302);
        
      } catch (error) {
        // Re-fetch data and show form with error
        const user = await env.DB.prepare(`
          SELECT * FROM users WHERE id = ?
        `).bind(currentUser.id).first();
        
        const { configService } = await import('../services/config.js');
        const config = await configService.getConfig(env.DB);
        
        const { renderUserSettings } = await import('../templates/user/settings.js');
        return new Response(renderUserSettings(user, [], config, error.message), {
          status: 400,
          headers: { 'Content-Type': 'text/html' }
        });
      }
    }
  },
  // Add new post creation route
  '/user/:username/new-post': {
    GET: async (request, env, ctx) => {
      const currentUser = await checkAuth(request, env);
      const username = request.params.username;
      
      if (!currentUser || currentUser.username !== username) {
        return Response.redirect(new URL('/login', request.url).toString(), 302);
      }
      
      const config = await configService.getConfig(env.DB);
      
      return new Response(renderUserPostForm(currentUser, config), {
        headers: { 'Content-Type': 'text/html' }
      });
    },
    
    POST: async (request, env, ctx) => {
      const currentUser = await checkAuth(request, env);
      const username = request.params.username;
      
      if (!currentUser || currentUser.username !== username) {
        return new Response('Unauthorized', { status: 403 });
      }
      
      try {
        const formData = await request.formData();
        const postModel = new PostModel(env.DB);
        
        // Auto-generate slug from title for regular users
        const postTitle = formData.get('title');
        const postSlug = postModel.generateSlug(postTitle);
        
        const post = await postModel.create({
          title: postTitle,
          content: formData.get('content'),
          slug: postSlug,  // Auto-generated
          excerpt: '',     // No excerpt for simplified form
          author_id: currentUser.id,
          published: formData.get('publish') === 'true'
        });
        
        // Fix: Construct full URL for redirect
        const redirectUrl = new URL(`/user/${username}`, request.url).toString();
        return Response.redirect(redirectUrl, 302);
        
      } catch (error) {
        const config = await configService.getConfig(env.DB);
        return new Response(renderUserPostForm(currentUser, config, error.message), {
          status: 400,
          headers: { 'Content-Type': 'text/html' }
        });
      }
    }
  },

  // Edit post route
  '/user/:username/edit/:postId': {
    GET: async (request, env, ctx) => {
      const currentUser = await checkAuth(request, env);
      const username = request.params.username;
      const postId = request.params.postId;
      
      if (!currentUser || currentUser.username !== username) {
        return Response.redirect('/login', 302);
      }
      
      const postModel = new PostModel(env.DB);
      const post = await postModel.getById(postId);
      
      // Verify ownership
      if (!post || post.author_id !== currentUser.id) {
        return new Response('Not found', { status: 404 });
      }
      
      const config = await configService.getConfig(env.DB);
      
      return new Response(renderUserPostForm(currentUser, config, null, post), {
        headers: { 'Content-Type': 'text/html' }
      });
    },
    
    POST: async (request, env, ctx) => {
      const currentUser = await checkAuth(request, env);
      const username = request.params.username;
      const postId = request.params.postId;
      
      if (!currentUser || currentUser.username !== username) {
        return new Response('Unauthorized', { status: 403 });
      }
      
      const postModel = new PostModel(env.DB);
      const post = await postModel.getById(postId);
      
      if (!post || post.author_id !== currentUser.id) {
        return new Response('Not found', { status: 404 });
      }
      
      const formData = await request.formData();
      await postModel.update(postId, {
        title: formData.get('title'),
        content: formData.get('content'),
        slug: formData.get('slug'),
        excerpt: formData.get('excerpt'),
        published: formData.get('publish') === 'true'
      });
      
      return Response.redirect(`/user/${username}`, 302);
    }
  },

  // Quick publish route for drafts
  '/user/:username/publish/:postId': {
    POST: async (request, env, ctx) => {
      const currentUser = await checkAuth(request, env);
      const username = request.params.username;
      const postId = request.params.postId;
      
      if (!currentUser || currentUser.username !== username) {
        return new Response('Unauthorized', { status: 403 });
      }
      
      const postModel = new PostModel(env.DB);
      const post = await postModel.getById(postId);
      
      if (!post || post.author_id !== currentUser.id) {
        return new Response('Not found', { status: 404 });
      }
      
      await postModel.togglePublished(postId);
      return Response.redirect(`/user/${username}`, 302);
    }
  }
};
