// src/routes/admin.js - Refactored to use deadlight-lib
import { 
  renderAddPostForm, 
  renderEditPostForm, 
  renderAddUserForm, 
  renderDeleteConfirmation
} from '../../../lib.deadlight/core/src/components/admin/index.js';
import { federationDashboard } from '../templates/admin/federationDashboard.js';
import { FederationService }     from '../services/federation.js';
import { requireAdminMiddleware } from '../middleware/index.js';
import { handleProxyRoutes, handleProxyTests } from './proxy.js';
import { checkAuth } from '../../../lib.deadlight/core/src/auth/password.js';
import { renderTemplate } from '../templates/base.js';
import { UserModel, PostModel } from '../../../lib.deadlight/core/src/db/models/index.js';
import { Logger } from '../../../lib.deadlight/core/src/logging/logger.js';
import { DatabaseError } from '../../../lib.deadlight/core/src/db/base.js';
import { getAnalyticsSummary, getTopPaths, getCountryStats, getHourlyTraffic } from '../middleware/analytics.js';
import { ProxyService } from '../services/proxy.js';
import { QueueService } from '../services/queue.js';
import { renderAdminDashboard } from '../templates/admin/index.js';
import { SettingsModel } from '../../../lib.deadlight/core/src/db/models/index.js';        
import { renderSettings } from '../templates/admin/settings.js';
import { renderAnalyticsTemplate } from '../templates/admin/analytics.js';

export const adminRoutes = {
  '/admin': {
    GET: async (request, env, ctx) => {
      const user = await checkAuth(request, env, ctx);
      if (!user) {
        return Response.redirect(`${new URL(request.url).origin}/login`);
      }

      try {
        const config = await env.services.config.getConfig();
        const postModel = new PostModel(env.DB);
        const userModel = new UserModel(env.DB);
        
        // Get recent posts using getPaginated
        const recentPostsResult = await postModel.getPaginated({ 
          limit: 5, 
          page: 1, 
          includeAuthor: true,
          orderBy: 'created_at',
          orderDirection: 'DESC',
          publishedOnly: false,
          visibility: null
        });
        
        // Get basic stats
        const [totalPosts, publishedPosts, totalUsers] = await Promise.all([
          postModel.count(false),
          postModel.count(true),
          userModel.count()
        ]);
        
        // Get posts created today
        const postsTodayResult = await env.DB.prepare(`
          SELECT COUNT(*) as count 
          FROM posts 
          WHERE date(created_at) = date('now')
        `).first();
        
        // Get analytics data
        let requestStats = [];
        let browserStats = [];
        let activeVisitors = 0;
        
        try {
          // Get request stats for chart
          const analyticsData = await env.DB.prepare(`
            SELECT 
              date(timestamp) as day,
              COUNT(*) as requests,
              COUNT(DISTINCT ip) as unique_visitors
            FROM request_logs
            WHERE timestamp >= date('now', '-7 days')
            GROUP BY date(timestamp)
            ORDER BY day DESC
          `).all();
          requestStats = analyticsData.results || [];
          
          // Get browser stats
          const browserData = await env.DB.prepare(`
            SELECT 
              CASE 
                WHEN user_agent LIKE '%Chrome%' THEN 'Chrome'
                WHEN user_agent LIKE '%Safari%' THEN 'Safari'
                WHEN user_agent LIKE '%Firefox%' THEN 'Firefox'
                ELSE 'Other'
              END as browser,
              COUNT(*) as count
            FROM analytics
            WHERE timestamp >= datetime('now', '-7 days')
            GROUP BY browser
            ORDER BY count DESC
          `).all();
          browserStats = browserData.results || [];
          
          // Get active visitors
          const activeVisitorsResult = await env.DB.prepare(`
            SELECT COUNT(DISTINCT ip) as active
            FROM analytics
            WHERE timestamp >= datetime('now', '-5 minutes')
          `).first();
          activeVisitors = activeVisitorsResult.active || 0;
          
        } catch (analyticsError) {
          console.error('Analytics query failed:', analyticsError);
        }
        
        const stats = {
          totalPosts,
          publishedPosts,
          postsToday: postsTodayResult.count || 0,
          totalUsers,
          activeVisitors, // Add this to stats
          browserStats   // Add this to stats
        };
        
        const recentPosts = recentPostsResult.posts;
        
        return new Response(
          renderAdminDashboard(stats, recentPosts, requestStats, request.user, config),
          { headers: { 'Content-Type': 'text/html' } }
        );
      } catch (templateError) {
        console.error('Dashboard error:', templateError);
        return new Response(`
          <h1>Admin Dashboard</h1>
          <p>Dashboard temporarily unavailable. <a href="/admin/add">Add Post</a> | <a href="/admin/users">Manage Users</a></p>
          <p>Error: ${templateError.message}</p>
        `, {
          headers: { 'Content-Type': 'text/html' }
        });
      }
    }
  },

  '/admin/edit/:id': {
    GET: async (request, env, ctx) => {
      const postModel = new PostModel(env.DB);
      const user = await checkAuth(request, env, ctx);
      
      if (!user) {
        return Response.redirect(`${new URL(request.url).origin}/login`);
      }

      try {
        const config = await env.services.config.getConfig();
        
        const postId = request.params.id;
        const post = await postModel.getById(postId);

        if (!post) {
          return new Response('Post not found', { status: 404 });
        }

        return new Response(renderEditPostForm(post, user, config), {
          headers: { 'Content-Type': 'text/html' }
        });
      } catch (error) {
        console.error('Error loading post for edit:', error);
        return new Response('Internal server error', { status: 500 });
      }
    },

    // Combined POST handler for /admin/edit/:id
    POST: async (request, env, ctx) => {
      const postModel = new PostModel(env.DB);
      const logger = new Logger({ context: 'admin' });
      const user = await checkAuth(request, env, ctx);
      
      if (!user) {
        return Response.redirect(`${new URL(request.url).origin}/login`);
      }

      try {
        const postId = request.params.id;
        
        // Get the existing post first
        const existingPost = await postModel.getById(postId);
        if (!existingPost) {
          return new Response('Post not found', { status: 404 });
        }
        
        const formData = await request.formData();
        const title = formData.get('title');
        const content = formData.get('content');
        const slug = formData.get('slug') || '';
        const excerpt = formData.get('excerpt') || '';
        const published = formData.has('published');
        const visibility = formData.has('private_visibility') ? 'private' : 'public';
        const comments_enabled = formData.has('comments_enabled');
        if (!title || !content) {
          return new Response('Title and content are required', { status: 400 });
        }
        
        // Only update slug if it changed and is not empty
        const updatedSlug = slug && slug !== existingPost.slug 
          ? slug 
          : existingPost.slug;
        
        // Update post using model
        const updatedPost = await postModel.update(postId, { 
          title, 
          content,
          slug: updatedSlug,
          excerpt,
          published,
          visibility,
          comments_enabled
        });

        logger.info('Post updated successfully', { 
          postId, 
          title,
          slug: updatedPost.slug,
          published: updatedPost.published,
          visibility: updatedPost.visibility
        });

        return Response.redirect(`${new URL(request.url).origin}/`);
      } catch (error) {
        logger.error('Error updating post', { postId: request.params.id, error: error.message });
        
        if (error instanceof DatabaseError && error.code === 'NOT_FOUND') {
          return new Response('Post not found', { status: 404 });
        }
        
        return new Response(`Failed to update post: ${error.message}`, { status: 500 });
      }
    }
  },

  '/admin/settings': {
    GET: async (request, env, ctx) => {
      const user = await checkAuth(request, env, ctx);
      if (!user) {
        return Response.redirect(`${new URL(request.url).origin}/login`);
      }

      try {

        const settingsModel = new SettingsModel(env.DB);
        const settings = await settingsModel.getAll();

        return new Response(renderSettings(settings, user), {
          headers: { 'Content-Type': 'text/html' }
        });
      } catch (error) {
        console.error('Settings error:', error);
        return new Response('Internal server error', { status: 500 });
      }
    },

    POST: async (request, env, ctx) => {
      const user = await checkAuth(request, env, ctx);
      if (!user) {
        return Response.redirect(`${new URL(request.url).origin}/login`);
      }

      try {
        const formData = await request.formData();
        const { SettingsModel } = await import('../../../lib.deadlight/core/src/db/models/index.js');
        const settingsModel = new SettingsModel(env.DB);
        
        // Update text/number settings
        await settingsModel.set('site_title', formData.get('site_title') || '', 'string');
        await settingsModel.set('site_description', formData.get('site_description') || '', 'string');
        await settingsModel.set('posts_per_page', formData.get('posts_per_page') || '10', 'number');
        await settingsModel.set('date_format', formData.get('date_format') || 'M/D/YYYY', 'string');
        await settingsModel.set('timezone', formData.get('timezone') || 'UTC', 'string');
        await settingsModel.set('accent_color', formData.get('accent_color') || '#8ba3c7', 'string');
        
        // Update boolean settings (checkboxes)
        await settingsModel.set('enable_registration', formData.has('enable_registration'), 'boolean');
        await settingsModel.set('require_login_to_read', formData.has('require_login_to_read'), 'boolean');
        await settingsModel.set('maintenance_mode', formData.has('maintenance_mode'), 'boolean');

        // Clear config cache so changes take effect immediately
        env.services.config.clearCache();  // Change to this (instance method call)

        return Response.redirect(`${new URL(request.url).origin}/admin`);
      } catch (error) {
        console.error('Settings update error:', error);
        return new Response('Failed to update settings', { status: 500 });
      }
    }
  },

  // Add Post Handler
  '/admin/add': {
    GET: async (request, env, ctx) => {
      const user = await checkAuth(request, env, ctx);
      if (!user) {
        return Response.redirect(`${new URL(request.url).origin}/login`);
      }

      const config = await env.services.config.getConfig();

      return new Response(renderAddPostForm(user, config), {
        headers: { 'Content-Type': 'text/html' }
      });
    },

    POST: async (request, env, ctx) => {
      const postModel = new PostModel(env.DB);
      const logger = new Logger({ context: 'admin' });
      const user = await checkAuth(request, env, ctx);
      
      if (!user) {
        return Response.redirect(`${new URL(request.url).origin}/login`);
      }

      try {
        const formData = await request.formData();
        const title = formData.get('title');
        const content = formData.get('content');
        const slug = formData.get('slug') || '';
        const excerpt = formData.get('excerpt') || '';
        const published = formData.has('published');
        const visibility = formData.has('private_visibility') ? 'private' : 'public';
        const comments_enabled = formData.has('comments_enabled');
        logger.info('Adding post', { 
          title, 
          contentLength: content?.length,
          published,
          visibility
        });

        if (!title || !content) {
          return new Response('Title and content are required', { status: 400 });
        }

        // Create post using model with all required fields
        const newPost = await postModel.create({
          title,
          content,
          slug: slug || postModel.generateSlug(title),
          excerpt,
          author_id: user.id,
          published,
          visibility,
          comments_enabled
        });

        logger.info('Post created successfully', { 
          postId: newPost.id, 
          title,
          published: newPost.published,
          visibility: newPost.visibility
        });

        return Response.redirect(`${new URL(request.url).origin}/`);
      } catch (error) {
        logger.error('Error adding post', { error: error.message });
        
        if (error instanceof DatabaseError) {
          return new Response(`Database error: ${error.message}`, { status: 500 });
        }
        
        return new Response('Failed to add post', { status: 500 });
      }
    }
  },

  '/admin/delete/:id': {
    GET: async (request, env, ctx) => {
      const postModel = new PostModel(env.DB);
      const postId = request.params?.id || ctx.params?.id;
      
      const post = await postModel.getById(postId);
      if (!post) {
        return new Response('Post not found', { status: 404 });
      }
      
      const config = await env.services.config.getConfig();
      const csrfToken = ctx.csrfToken; 
      
      return new Response(
        renderDeleteConfirmation(post, ctx.user, config, csrfToken), 
        { headers: { 'Content-Type': 'text/html' } }
      );
    },
    
    POST: async (request, env, ctx) => { 
      const postModel = new PostModel(env.DB);
      const logger = new Logger({ context: 'admin' });
      
      const user = ctx.user;

      try {
        const postId = request.params?.id || ctx.params?.id;
        
        // Delete post using model
        await postModel.delete(postId);

        logger.info('Post deleted successfully', { postId, userId: user.id });

        return Response.redirect(`${new URL(request.url).origin}/`, 303); 
      } catch (error) {
        logger.error('Error deleting post', { postId: ctx.params.id, error: error.message });
        
        if (error instanceof DatabaseError && error.code === 'NOT_FOUND') {
          return new Response('Post not found', { status: 404 });
        }
        
        return new Response('Failed to delete post', { status: 500 });
      }
    }
  },

  '/admin/comments/:postId': {
    GET: async (request, env, ctx) => {
      const user = await checkAuth(request, env, ctx);
      if (!user) return Response.redirect(`${new URL(request.url).origin}/login`);
      const postId = request.params.postId;
      const fedSvc = new FederationService(env);
      const comments = await fedSvc.getThreadedComments(postId);
      const config = await env.services.config.getConfig();
      const { renderCommentList } = await import('../templates/admin/comments.js');
      return new Response(renderCommentList(comments, postId, user, config), {
        headers: { 'Content-Type': 'text/html' }
      });
    }
  },

  '/admin/add-comment/:postId': {
    GET: async (request, env, ctx) => {
      const user = await checkAuth(request, env, ctx);
      if (!user) return Response.redirect(`${new URL(request.url).origin}/login`);
      const postId = request.params.postId;
      const { renderAddCommentForm } = await import('../templates/admin/comments.js');
      return new Response(renderAddCommentForm(postId, user), {
        headers: { 'Content-Type': 'text/html' }
      });
    },
    POST: async (request, env, ctx) => {
      const user = await checkAuth(request, env, ctx);
      if (!user) return Response.redirect(`${new URL(request.url).origin}/login`);
      const postId = request.params.postId;

      const clonedRequest = request.clone();
      const formData = await clonedRequest.formData();
      const content = formData.get('content');

      if (!content) {
        return new Response('Content is required', { status: 400 });
      }

      const fedSvc = new FederationService(env);
      const post = await env.DB.prepare('SELECT id, federation_metadata FROM posts WHERE id = ?')
        .bind(postId).first();
      if (!post) {
        return new Response('Post not found', { status: 404 });
      }

      const meta = post.federation_metadata ? JSON.parse(post.federation_metadata) : {};
      const sourceUrl = meta.source_url || `${env.SITE_URL}/post/${postId}`;
      const comment = {
        id: Date.now(),
        content,
        author: user.username,
        published_at: new Date().toISOString(),
        parent_url: sourceUrl
      };

      const insertResult = await env.DB.prepare(`
        INSERT INTO posts (title, content, slug, author_id, created_at, published, post_type, parent_id, thread_id)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
      `).bind(
        `Comment on ${sourceUrl}`,
        content,
        `comment-${Date.now()}-${Math.random().toString(36).substring(2, 7)}`,
        user.id,
        new Date().toISOString(),
        1,
        'comment',
        postId,
        postId
      ).run();

      const domains = await fedSvc.getConnectedDomains();
      const targetDomains = domains.map(d => d.domain);
      await fedSvc.publishComment(comment, targetDomains);

      return Response.redirect(`${new URL(request.url).origin}/admin/comments/${postId}`);
    }
  },

  '/admin/comments/reply/:id': {
    GET: async (request, env, ctx) => {
      const user = await checkAuth(request, env, ctx);
      if (!user) return Response.redirect(`${new URL(request.url).origin}/login`);
      const commentId = request.params.id;
      const comment = await env.DB.prepare(`
        SELECT p.*, u.username as author_username
        FROM posts p
        LEFT JOIN users u ON p.author_id = u.id
        WHERE p.id = ? AND p.post_type = 'comment'
      `).bind(commentId).first();
      if (!comment) return new Response('Comment not found', { status: 404 });
      const { renderReplyForm } = await import('../templates/admin/comments.js');
      return new Response(renderReplyForm(comment, user), {
        headers: { 'Content-Type': 'text/html' }
      });
    },
    POST: async (request, env, ctx) => {
      const user = await checkAuth(request, env, ctx);
      if (!user) return Response.redirect(`${new URL(request.url).origin}/login`);
      const commentId = request.params.id;

      const clonedRequest = request.clone();
      const formData = await clonedRequest.formData();
      const content = formData.get('content');

      if (!content) {
        return new Response('Content is required', { status: 400 });
      }

      const parentComment = await env.DB.prepare(`
        SELECT p.*, u.username as author_username
        FROM posts p
        LEFT JOIN users u ON p.author_id = u.id
        WHERE p.id = ? AND p.post_type = 'comment'
      `).bind(commentId).first();
      if (!parentComment) {
        return new Response('Parent comment not found', { status: 404 });
      }

      const fedSvc = new FederationService(env);
      const post = await env.DB.prepare('SELECT id, federation_metadata FROM posts WHERE id = ?')
        .bind(parentComment.parent_id || parentComment.thread_id).first();
      if (!post) {
        return new Response('Post not found', { status: 404 });
      }

      const meta = post.federation_metadata ? JSON.parse(post.federation_metadata) : {};
      const sourceUrl = meta.source_url || `${env.SITE_URL}/post/${parentComment.parent_id || parentComment.thread_id}`;
      const reply = {
        id: Date.now(),
        content,
        author: user.username,
        published_at: new Date().toISOString(),
        parent_url: sourceUrl,
        in_reply_to: commentId
      };

      const insertResult = await env.DB.prepare(`
        INSERT INTO posts (title, content, slug, author_id, created_at, published, post_type, parent_id, thread_id)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
      `).bind(
        `Reply to comment on ${sourceUrl}`,
        content,
        `reply-${Date.now()}-${Math.random().toString(36).substring(2, 7)}`,
        user.id,
        new Date().toISOString(),
        1,
        'comment',
        commentId,
        parentComment.thread_id || commentId
      ).run();

      const domains = await fedSvc.getConnectedDomains();
      const targetDomains = domains.map(d => d.domain);
      await fedSvc.publishComment(reply, targetDomains);

      return Response.redirect(`${new URL(request.url).origin}/admin/comments/${parentComment.parent_id || parentComment.thread_id}`);
    }
  },

  '/admin/comments/delete/:id': {
    GET: async (request, env, ctx) => {
      const user = await checkAuth(request, env, ctx);
      if (!user) return Response.redirect(`${new URL(request.url).origin}/login`);
      const commentId = request.params.id;

      const comment = await env.DB.prepare(`
        SELECT p.*, u.username as author_username, p.parent_id AS parent_post_id
        FROM posts p
        LEFT JOIN users u ON p.author_id = u.id
        WHERE p.id = ? AND p.post_type = 'comment'
      `).bind(commentId).first();
      if (!comment) return new Response('Comment not found', { status: 404 });

      await env.DB.prepare('DELETE FROM posts WHERE id = ?').bind(commentId).run();

      const fedSvc = new FederationService(env);
      const domains = await fedSvc.getConnectedDomains();
      const targetDomains = domains.map(d => d.domain);
      await fedSvc.sendDeleteComment(commentId, targetDomains);

      return Response.redirect(`${new URL(request.url).origin}/admin/comments/${comment.parent_post_id || comment.thread_id}`);
    }
  },

  '/admin/users': {
    GET: async (request, env, ctx) => {
      const userModel = new UserModel(env.DB);
      const user = await checkAuth(request, env, ctx);
      
      if (!user) {
        return Response.redirect(`${new URL(request.url).origin}/login`);
      }

      try {
        const config = await env.services.config.getConfig();
        
        // Updated: Include stats for post_count and last_post
        const users = await userModel.list({ limit: 50, includeStats: true });
        const totalUsers = await userModel.count();

        const { renderUserManagement } = await import('../templates/admin/userManagement.js');
        
        return new Response(renderUserManagement(users, user, config), {
          headers: { 'Content-Type': 'text/html' }
        });
      } catch (error) {
        console.error('User management error:', error);
        // Fallback: Render with empty users to avoid crash, like in analytics
        const { renderUserManagement } = await import('../templates/admin/userManagement.js');
        return new Response(renderUserManagement([], user, config), {
          headers: { 'Content-Type': 'text/html' }
        });
      }
    }
  },

  '/admin/users/add': {
    GET: async (request, env, ctx) => {
      const user = await checkAuth(request, env, ctx);
      if (!user) {
        return Response.redirect(`${new URL(request.url).origin}/login`);
      }

      // Get dynamic config
      const config = await env.services.config.getConfig();

      return new Response(renderAddUserForm(user, config), {
        headers: { 'Content-Type': 'text/html' }
      });
    },

    POST: async (request, env, ctx) => {
      const userModel = new UserModel(env.DB);
      const logger = new Logger({ context: 'admin' });
      const user = await checkAuth(request, env, ctx);
      
      if (!user) {
        return Response.redirect(`${new URL(request.url).origin}/login`);
      }

      try {
        const formData = await request.formData();
        const username = formData.get('username');
        const password = formData.get('password');
        const role = formData.get('role') || 'user';

        if (!username || !password) {
          return new Response('Username and password are required', { status: 400 });
        }

        // Create user using model
        const newUser = await userModel.create({ username, password, role });

        logger.info('User created successfully', { userId: newUser.id, username, role });

        return Response.redirect(`${new URL(request.url).origin}/admin/users`);
      } catch (error) {
        logger.error('Error creating user', { error: error.message });
        
        if (error instanceof DatabaseError && error.code === 'DUPLICATE_USER') {
          return new Response('Username already exists', { status: 400 });
        }
        
        return new Response('Failed to create user', { status: 500 });
      }
    }
  },

  '/admin/users/delete/:id': {
    POST: async (request, env, ctx) => {
      const userModel = new UserModel(env.DB);
      const logger = new Logger({ context: 'admin' });
      const user = await checkAuth(request, env, ctx);
      
      if (!user) {
        return Response.redirect(`${new URL(request.url).origin}/login`);
      }

      try {
        const userId = parseInt(request.params.id);
        
        // Prevent self-deletion
        if (userId === user.id) {
          return new Response('Cannot delete yourself', { status: 400 });
        }

        // Delete user using model
        await userModel.delete(userId);

        logger.info('User deleted successfully', { userId });

        return Response.redirect(`${new URL(request.url).origin}/admin/users`);
      } catch (error) {
        logger.error('Error deleting user', { userId: request.params.id, error: error.message });
        return new Response('Failed to delete user', { status: 500 });
      }
    }
  },

  // Proxy Dashboard
  '/admin/proxy': {
    GET: async (request, env, ctx) => {
      const user = await checkAuth(request, env, ctx);
      if (!user) {
        return Response.redirect(`${new URL(request.url).origin}/login`);
      }

      return await handleProxyRoutes(request, env, user);
    }
  },

  '/admin/proxy/discover-domain': {
    POST: async (request, env, ctx) => {
      const user = await checkAuth(request, env, ctx);
      if (!user) {
        return Response.json({ success: false, error: 'Unauthorized' }, { status: 401 });
      }

      return await handleProxyTests.discoverDomain(request, env, ctx);
    }
  },

  // Proxy API Test Endpoints
  '/admin/proxy/test-blog-api': {
    GET: async (request, env, ctx) => {
      const user = await checkAuth(request, env, ctx);
      if (!user) {
        return Response.json({ success: false, error: 'Unauthorized' }, { status: 401 });
      }

      return await handleProxyTests.testBlogApi(request, env, ctx);
    }
  },

  '/admin/proxy/test-email-api': {
    GET: async (request, env, ctx) => {
      const user = await checkAuth(request, env, ctx);
      if (!user) {
        return Response.json({ success: false, error: 'Unauthorized' }, { status: 401 });
      }

      return await handleProxyTests.testEmailApi(request, env, ctx);
    }
  },

  '/admin/proxy/test-federation': {
    GET: async (request, env, ctx) => {
      const user = await checkAuth(request, env, ctx);
      if (!user) {
        return Response.json({ success: false, error: 'Unauthorized' }, { status: 401 });
      }

      return await handleProxyTests.testFederation(request, env, ctx);
    }
  },

  '/admin/proxy/send-test-email': {
    POST: async (request, env, ctx) => {
      const user = await checkAuth(request, env, ctx);
      if (!user) {
        return Response.json({ success: false, error: 'Unauthorized' }, { status: 401 });
      }

      return await handleProxyTests.sendTestEmail(request, env, ctx);
    }
  },

  '/admin/send-notification': {
    POST: async (request, env, ctx) => {
      const { to, subject, body } = await request.json();
      
      // ✅ Smart send: tries direct, queues on failure
      const result = await ctx.proxy.send('send_email', {
        to,
        from: 'noreply@deadlight.boo',
        subject,
        body
      });
      
      if (result.queued) {
        return Response.json({ 
          message: 'Email queued - proxy is offline',
          queued: true 
        }, { status: 202 });
      }
      
      return Response.json({ 
        message: 'Email sent successfully',
        sent: true,
        result: result.result 
      });
    }
  },

  '/admin/queue-status': {
    GET: async (request, env, ctx) => {
      const user = ctx.user;
      if (!user || user.role !== 'admin') {
        return Response.json({ error: 'Unauthorized' }, { status: 401 });
      }

      try {
        const status = await env.services.queue.getStatus();
        return Response.json(status);
      } catch (error) {
        console.error('Queue status error:', error);
        return Response.json({ 
          error: 'Failed to get queue status',
          details: error.message 
        }, { status: 500 });
      }
    }
  },
  
  '/admin/process-queue': {
    POST: async (request, env, ctx) => {
      const user = ctx.user;  // Already set by authMiddleware
      if (!user || user.role !== 'admin') {
        return Response.json({ error: 'Unauthorized' }, { status: 401 });
      }

      try {
        const result = await env.services.queue.processAll();
        
        return Response.json({ 
          success: true, 
          ...result,
          message: `Processed ${result.processed} items. Status: ${result.status}`
        });
      } catch (error) {
        console.error('Queue processing error:', error);
        return Response.json({ 
          success: false, 
          error: error.message
        }, { status: 500 });
      }
    }
  },

  '/admin/federation/sync' : {
    POST: async (req, env) => {
      const user = await checkAuth(req, env);
      if (!user) {
        return Response.json({ error: 'Unauthorized' }, { status: 401 });
      }

      const fedSvc = new FederationService(env);
      // syncNetwork now returns { imported: Number, domains: Number }
      const result = await fedSvc.syncNetwork();
      return Response.json({
        success: true,
        message: `Imported ${result.imported} new posts from ${result.domains} domains.`,
        imported: result.imported,
        domains: result.domains,
        newPosts: result.newPosts  // optional: raw posts for client-side rendering
      });
    }
  },

  '/federation/queue' : {
    GET: async (request, env, ctx) => {
      const url = new URL(request.url);
      const limit = parseInt(url.searchParams.get('limit') || '50');
      const since = url.searchParams.get('since'); // ISO8601 string

      let query = `
        SELECT id, title, content, created_at, author_id, federation_metadata
        FROM posts
        WHERE post_type = 'federated'
          AND published = 1
      `;
      const params = [];

      if (since) {
        query += ` AND created_at > ?`;
        params.push(since);
      }

      query += ` ORDER BY created_at DESC LIMIT ?`;
      params.push(limit);

      const { results: posts } = await env.DB.prepare(query).bind(...params).all();

      const items = posts.map(post => {
        const meta = post.federation_metadata ? JSON.parse(post.federation_metadata) : {};
        return {
          id: `${url.origin}/posts/${post.id}`,
          type: 'Create',
          actor: meta.actor || `${url.origin}/actors/system`,
          object: {
            id: `${url.origin}/posts/${post.id}`,
            type: 'Note',
            content: post.content,
            published: post.created_at,
            attributedTo: meta.actor || `${url.origin}/actors/system`,
            to: ['https://www.w3.org/ns/activitystreams#Public']
          }
        };
      });

      const response = {
        '@context': 'https://www.w3.org/ns/activitystreams',
        id: url.href,
        type: 'OrderedCollectionPage',
        partOf: `${url.origin}/federation/outbox`,
        orderedItems: items,
        next: null // Add pagination later
      };

      return new Response(JSON.stringify(response), {
        headers: { 'Content-Type': 'application/json' }
      });
    }
  },

  '/admin/federate-post/(?<id>[^/]+)': {
  //'/admin/federate-post/:id': {
    POST: async (request, env, ctx) => {
      // Keep just the POST implementation
      const user = await checkAuth(request, env, ctx);
      if (!user) return Response.json({ success: false, error: 'Unauthorized' }, { status: 401 });
      
      const postId = request.params.id;
      const federationService = new FederationService(env);
      
      const post = await env.DB.prepare('SELECT * FROM posts WHERE id = ?').bind(postId).first();
      if (!post) return Response.json({ success: false, error: 'Post not found' });
      
      const domains = await federationService.getConnectedDomains();
      const targetDomains = domains.map(d => d.domain);
      
      if (targetDomains.length === 0) {
        return Response.json({ success: false, error: 'No federated domains found' });
      }
      
      const results = await federationService.publishPost(post, targetDomains);
      
      return Response.json({ 
        success: true, 
        message: `Post federated to ${targetDomains.length} domains`,
        results 
      });
    }
  },


  '/admin/inject-emails': {
    GET: async (request, env, ctx) => {
      const user = await checkAuth(request, env, ctx);
      if (!user || user.role !== 'admin') {
        return Response.redirect(`${new URL(request.url).origin}/login`);
      }

      const content = `
        <h1>Inject Emails</h1>
        <p>This will inject mock email data into the posts table for testing purposes.</p>
        <form action="/admin/inject-emails" method="POST">
          <button type="submit">Inject Mock Emails</button>
        </form>
        <div class="admin-actions">
          <a href="/admin" class="button secondary">Back to Dashboard</a>
          <a href="/inbox" class="button">View Inbox</a>
        </div>
      `;

      return new Response(renderTemplate('Inject Emails', content, user), {
        headers: { 'Content-Type': 'text/html' }
      });
    },

    POST: async (request, env, ctx) => {
      const logger = new Logger({ context: 'admin' });
      const user = await checkAuth(request, env, ctx);
      if (!user || user.role !== 'admin') {
        return Response.redirect(`${new URL(request.url).origin}/login`);
      }

      try {
        // Mock email data to inject (replace with real data source later if needed)
        const mockEmails = [
          {
            subject: "Your account is live - join millions of businesses on Google",
            body: "thatch, welcome to Google\n\nNow you can start growing your business.\n\nComplete your profile  \n<https://business.google.com/create?hl=en&gmbsrc=US-en-et-em-z-gmb-z-l~wlcemnewv%7Ccreate&mcsubid=ww-ww-xs-mc-simedm-1-simometest!o3&trk=https%3A%2F%2Fc.gle%2FANiao5o-_gstjXfaH2vfT_kVzzSgMwbu_1X48UquUw0U6Zg1mL4h9fJvctaO5ZJBjaNHYTlIkvKGEO_YHYziseGVtWfCGQ5fZyLL60gkNNhfvIy9IkLOkgX0mej2jq0l6fkuRfcsmF7ZAlQ>\n\nCongratulations – your account is live and ready for action. You now have access to a range of tools that can help your business reach more people.\n\n...",
            from: "Google Community Team <googlecommunityteam-noreply@google.com>",
            to: "deadlight.boo@gmail.com",
            date: "Sat, 02 Aug 2025 07:21:59 -0700",
            message_id: "a1d91498095de4b1b3de613c0fe9cd1471d1f0d1-20166281-111702100@google.com"
          },
          {
            subject: "Test Email for Deadlight Comm",
            body: "Hello,\n\nThis is a test email to check if the inbox rendering works correctly in Deadlight Comm.\n\nBest regards,\nTest User",
            from: "Thatch <gnarzilla@deadlight.boo>",
            to: "deadlight.boo@gmail.com",
            date: "Sun, 03 Aug 2025 10:00:00 -0700",
            message_id: "test-1234567890@deadlight.boo"
          }
        ];

        let insertedCount = 0;
        for (const email of mockEmails) {
          try {
            const metadata = JSON.stringify({
              from: email.from,
              to: email.to,
              message_id: email.message_id,
              date: email.date
            });
            // Simplify duplicate check by extracting a short unique part of message_id
            // Use first 20 chars or so to avoid complex LIKE patterns
            const shortMsgId = email.message_id.length > 20 ? email.message_id.substring(0, 20) : email.message_id;
            const checkQuery = 'SELECT id FROM posts WHERE is_email = 1 AND email_metadata LIKE ? LIMIT 1';
            const existing = await env.DB.prepare(checkQuery).bind(`%${shortMsgId}%`).first();
            if (!existing) {
              const insertQuery = `
                INSERT INTO posts (title, content, slug, author_id, created_at, updated_at, published, is_email, email_metadata)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
              `;
              await env.DB.prepare(insertQuery).bind(
                email.subject,
                email.body,
                `email-${Date.now()}-${Math.random().toString(36).substring(2, 7)}`, // Unique slug
                user.id, // Use logged-in user's ID
                email.date || new Date().toISOString(),
                new Date().toISOString(),
                0, // Not published (private)
                1, // is_email flag
                metadata
              ).run();
              insertedCount++;
              logger.info(`Injected email: ${email.subject}`, { userId: user.id });
            } else {
              logger.info(`Skipped existing email: ${email.subject}`, { userId: user.id });
            }
          } catch (err) {
            logger.error(`Error injecting email ${email.subject}:`, { error: err.message, userId: user.id });
          }
        }

        const content = `
          <h2>Injection Complete</h2>
          <p>Inserted ${insertedCount} email(s) into the database.</p>
          <div class="admin-actions">
            <a href="/inbox" class="button">View Inbox</a>
            <a href="/admin" class="button secondary">Back to Dashboard</a>
          </div>
        `;
        return new Response(renderTemplate('Injection Complete', content, user), {
          headers: { 'Content-Type': 'text/html' }
        });
      } catch (error) {
        logger.error('Error injecting emails', { error: error.message, userId: user.id });
        return new Response(renderTemplate('Error', `<p>Failed to inject emails: ${error.message}</p>`, user), {
          headers: { 'Content-Type': 'text/html' },
          status: 500
        });
      }
    }
  },

  '/admin/fetch-emails': {
    POST: async (request, env, ctx) => {
      const logger = new Logger({ context: 'admin' });
      const user = await checkAuth(request, env, ctx);
      if (!user || user.role !== 'admin') {
        // Also allow API key authentication for automation
        const apiKey = request.headers.get('X-API-Key');
        const expectedKey = env.API_KEY || 'YOUR_API_KEY'; // Set in wrangler.toml or as secret
        if (apiKey !== expectedKey) {
          logger.warn('Unauthorized fetch-emails attempt', { ip: request.headers.get('CF-Connecting-IP') || 'unknown' });
          return new Response(JSON.stringify({ error: 'Unauthorized' }), {
            headers: { 'Content-Type': 'application/json' },
            status: 403
          });
        }
      }

      try {
        const payload = await request.json();
        let insertedCount = 0;
        if (Array.isArray(payload.emails)) {
          for (const email of payload.emails) {
            try {
              const metadata = JSON.stringify({
                from: email.from || 'Unknown Sender',
                to: email.to || 'Unknown Recipient',
                message_id: email.message_id || `msg-${Date.now()}-${Math.random().toString(36).substring(2, 7)}`,
                date: email.date || new Date().toISOString()
              });
              // Check for duplicates by message_id (simplified)
              const checkQuery = 'SELECT id FROM posts WHERE is_email = 1 AND title = ? LIMIT 1';
              const existing = await env.DB.prepare(checkQuery).bind(email.subject || 'Untitled Email').first();
              if (!existing) {
                const insertQuery = `
                  INSERT INTO posts (title, content, slug, author_id, created_at, updated_at, published, is_email, email_metadata)
                  VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                `;
                await env.DB.prepare(insertQuery).bind(
                  email.subject || 'Untitled Email',
                  email.body || 'No content',
                  `email-${Date.now()}-${Math.random().toString(36).substring(2, 7)}`, // Unique slug
                  user?.id || 2, // Use logged-in user's ID or default admin ID
                  email.date || new Date().toISOString(),
                  new Date().toISOString(),
                  0, // Not published (private)
                  1, // is_email flag
                  metadata
                ).run();
                insertedCount++;
                logger.info(`Fetched and inserted email: ${email.subject || 'Untitled Email'}`, { userId: user?.id || 'API' });
              } else {
                logger.info(`Skipped existing email: ${email.subject || 'Untitled Email'}`, { userId: user?.id || 'API' });
              }
            } catch (err) {
              logger.error(`Error inserting email ${email.subject || 'Untitled Email'}:`, { error: err.message, userId: user?.id || 'API' });
            }
          }
        }
        return new Response(JSON.stringify({ success: true, inserted: insertedCount }), {
          headers: { 'Content-Type': 'application/json' }
        });
      } catch (error) {
        logger.error('Error fetching emails via API', { error: error.message, userId: user?.id || 'API' });
        return new Response(JSON.stringify({ error: 'Failed to fetch emails', details: error.message }), {
          headers: { 'Content-Type': 'application/json' },
          status: 500
        });
      }
    }
  },

  '/admin/notifications': {
    GET: async (request, env, ctx) => {
      const user = await checkAuth(request, env, ctx);
      if (!user) return Response.redirect(`${new URL(request.url).origin}/login`);
      const notifications = await env.DB.prepare(`
        SELECT * FROM notifications WHERE user_id = ? ORDER BY created_at DESC LIMIT 50
      `).bind(user.id).all();
      // Render template
    }
  },

  'admin/moderation-keywords' : {
    GET: async (req, env) => {
      const keywords = await env.services.config.getModerationKeywords(); // ← from ConfigService
      return new Response(JSON.stringify({ keywords }), {
        headers: { 'Content-Type': 'application/json' },
      });
    },

    POST: async (req, env) => {
      const { keywords } = await req.json();
      if (!Array.isArray(keywords)) {
        return new Response(JSON.stringify({ error: 'keywords must be array' }), { status: 400 });
      }

      await env.services.moderation.setKeywords(keywords); // ← uses ModerationService
      return new Response(JSON.stringify({ success: true, keywords }));
    },
  },

  // Example: Check content moderation (e.g., for preview)
  'admin/check-moderation' : {
    POST: async (req, env) => {
      const { content } = await req.json();
      const result = await env.services.moderation.check(content);
      return new Response(JSON.stringify(result), {
        headers: { 'Content-Type': 'application/json' },
      });
    },
  },

  '/admin/moderation' : {
    GET: async (request, env, ctx) => {
      const user = await checkAuth(request, env, ctx);
      if (!user) {
        const origin = new URL(request.url).origin;
        return Response.redirect(`${origin}/login`, 302);
      }

      // grab all federated, pending posts
      const { results: pendingPosts } = await env.DB.prepare(`
        SELECT id, title, content, author_id, created_at, moderation_notes
        FROM posts
        WHERE post_type = 'federated'
          AND moderation_status = 'pending'
        ORDER BY created_at DESC
        LIMIT 100
      `).all();

      // build table rows
      const rows = pendingPosts.map(p => {
        const date = new Date(p.created_at).toLocaleString();
        const snippet = p.content.length > 100
          ? p.content.slice(0, 100) + '…'
          : p.content;
        return `
          <tr>
            <td>${p.id}</td>
            <td>${p.title}</td>
            <td>${date}</td>
            <td>${snippet}</td>
            <td>
              <form action="/admin/moderation/${p.id}/approve" method="POST" style="display:inline">
                <button type="submit">Approve</button>
              </form>
              <form action="/admin/moderation/${p.id}/reject" method="POST" style="display:inline">
                <input type="text" name="reason" placeholder="Reason" />
                <button type="submit">Reject</button>
              </form>
            </td>
          </tr>`;
      }).join('');

      const html = `
        <h1>Federation Moderation Queue</h1>
        <table>
          <thead>
            <tr>
              <th>ID</th>
              <th>Title</th>
              <th>Received</th>
              <th>Content</th>
              <th>Actions</th>
            </tr>
          </thead>
          <tbody>
            ${rows}
          </tbody>
        </table>
        <p><a href="/admin">← Back to Dashboard</a></p>
      `;

      return new Response(renderTemplate('Moderation Queue', html, user), {
        headers: { 'Content-Type': 'text/html' }
      });
    }
  },

  '/admin/pending-replies': {
    GET: async (request, env, ctx) => {
      const logger = new Logger({ context: 'admin' });
      const user = await checkAuth(request, env, ctx);
      const apiKey = request.headers.get('X-API-Key');
      const expectedKey = env.X_API_KEY || 'YOUR_API_KEY';
      
      // Debug logging (remove in production)
      console.log('Debugging API Key - Received:', apiKey ? apiKey.substring(0, 5) + '...' : 'none');
      console.log('Debugging API Key - Expected:', expectedKey ? expectedKey.substring(0, 5) + '...' : 'none');
      
      // Fix authentication logic: Allow access if user is admin OR API key matches
      const isAuthenticated = (user && user.role === 'admin') || (apiKey === expectedKey);
      if (!isAuthenticated) {
        logger.warn('Unauthorized pending-replies attempt', { 
          ip: request.headers.get('CF-Connecting-IP') || 'unknown',
          keyProvided: !!apiKey,
          userPresent: !!user,
          userRole: user ? user.role : 'none'
        });
        return new Response(JSON.stringify({ error: 'Unauthorized' }), {
          headers: { 'Content-Type': 'application/json' },
          status: 403
        });
      }
      
      try {
        const query = 'SELECT * FROM posts WHERE is_reply_draft = 1 AND email_metadata LIKE \'%sent":false%\'';
        const repliesResult = await env.DB.prepare(query).all();
        const pendingReplies = repliesResult.results.map(reply => {
          const metadata = reply.email_metadata ? JSON.parse(reply.email_metadata) : {};
          return {
            id: reply.id,
            to: metadata.to || 'Unknown',
            from: metadata.from || 'deadlight.boo@gmail.com',
            subject: reply.title,
            body: reply.content,
            original_id: metadata.original_id || null,
            queued_at: metadata.date_queued || reply.created_at
          };
        });
        
        return new Response(JSON.stringify({ success: true, replies: pendingReplies }), {
          headers: { 'Content-Type': 'application/json' }
        });
      } catch (error) {
        logger.error('Error fetching pending replies', { error: error.message, userId: user?.id || 'API' });
        return new Response(JSON.stringify({ error: 'Failed to fetch pending replies', details: error.message }), {
          headers: { 'Content-Type': 'application/json' },
          status: 500
        });
      }
    },

    POST: async (request, env, ctx) => {
      const logger = new Logger({ context: 'admin' });
      const user = await checkAuth(request, env, ctx);
      const apiKey = request.headers.get('X-API-Key');
      const expectedKey = env.X_API_KEY || 'YOUR_API_KEY';
      
      // Fix authentication logic: Allow access if user is admin OR API key matches
      const isAuthenticated = (user && user.role === 'admin') || (apiKey === expectedKey);
      if (!isAuthenticated) {
        logger.warn('Unauthorized mark-sent attempt', { 
          ip: request.headers.get('CF-Connecting-IP') || 'unknown',
          keyProvided: !!apiKey,
          userPresent: !!user,
          userRole: user ? user.role : 'none'
        });
        return new Response(JSON.stringify({ error: 'Unauthorized' }), {
          headers: { 'Content-Type': 'application/json' },
          status: 403
        });
      }
      
      try {
        const payload = await request.json();
        const replyId = payload.id;
        if (!replyId) {
          return new Response(JSON.stringify({ error: 'Reply ID required' }), {
            headers: { 'Content-Type': 'application/json' },
            status: 400
          });
        }
        
        const query = 'SELECT * FROM posts WHERE id = ? AND is_reply_draft = 1';
        const replyResult = await env.DB.prepare(query).bind(replyId).first();
        if (!replyResult) {
          return new Response(JSON.stringify({ error: 'Reply not found' }), {
            headers: { 'Content-Type': 'application/json' },
            status: 404
          });
        }
        
        const metadata = replyResult.email_metadata ? JSON.parse(replyResult.email_metadata) : {};
        metadata.sent = true;
        metadata.date_sent = new Date().toISOString();
        const updateQuery = 'UPDATE posts SET email_metadata = ?, updated_at = ? WHERE id = ?';
        await env.DB.prepare(updateQuery).bind(
          JSON.stringify(metadata),
          new Date().toISOString(),
          replyId
        ).run();
        
        logger.info(`Marked reply ${replyId} as sent`, { userId: user?.id || 'API' });
        return new Response(JSON.stringify({ success: true, id: replyId }), {
          headers: { 'Content-Type': 'application/json' }
        });
      } catch (error) {
        logger.error('Error marking reply as sent', { error: error.message, userId: user?.id || 'API' });
        return new Response(JSON.stringify({ error: 'Failed to mark reply as sent', details: error.message }), {
          headers: { 'Content-Type': 'application/json' },
          status: 500
        });
      }
    }
  },

  '/admin/proxy/status-stream': {
    GET: async (request, env, ctx) => {
      const user = await checkAuth(request, env, ctx);
      if (!user) {
        return Response.json({ success: false, error: 'Unauthorized' }, { status: 401 });
      }

      return await handleProxyTests.statusStream(request, env, ctx);
    }
  },

  '/admin/proxy/status': {
    GET: async (request, env, ctx) => {
      const user = await checkAuth(request, env, ctx);
      if (!user) {
        return Response.json({ success: false, error: 'Unauthorized' }, { status: 401 });
      }

      try {
        const proxyService = new ProxyService({ PROXY_URL: env.PROXY_URL || 'http://localhost:8080' });
        const queueService = new QueueService(env);
        
        const [proxyStatus, queueStatus] = await Promise.allSettled([
          proxyService.healthCheck(),
          queueService.getStatus()
        ]);
        
        return Response.json({
          success: true,
          data: {
            proxy_connected: proxyStatus.status === 'fulfilled' && proxyStatus.value.proxy_connected,
            blogApi: proxyStatus.status === 'fulfilled' ? proxyStatus.value.blog_api : null,
            emailApi: proxyStatus.status === 'fulfilled' ? proxyStatus.value.email_api : null,
            queueCount: queueStatus.status === 'fulfilled' ? queueStatus.value.queued_operations?.total || 0 : 0,
            circuitState: proxyService.getCircuitState(),
            timestamp: new Date().toISOString()
          }
        });
      } catch (error) {
        return Response.json({
          success: false,
          error: error.message,
          timestamp: new Date().toISOString()
        });
      }
    }
  },
  // Temp dev route
  '/admin/analytics-debug': {
    GET: async (request, env, ctx) => {
      try {
        // Check if analytics table exists
        const tableCheck = await env.DB.prepare(`
          SELECT name FROM sqlite_master 
          WHERE type='table' AND name='analytics'
        `).first();
        
        if (!tableCheck) {
          return new Response('Analytics table does not exist', { status: 404 });
        }
        
        // Get table schema
        const schema = await env.DB.prepare(`
          SELECT sql FROM sqlite_master 
          WHERE type='table' AND name='analytics'
        `).first();
        
        // Get column info
        const columns = await env.DB.prepare(`
          PRAGMA table_info(analytics)
        `).all();
        
        // Try a simple count
        let count = 0;
        try {
          const countResult = await env.DB.prepare(`
            SELECT COUNT(*) as count FROM analytics
          `).first();
          count = countResult.count;
        } catch (e) {
          count = `Error: ${e.message}`;
        }
        
        return new Response(JSON.stringify({
          exists: true,
          schema: schema.sql,
          columns: columns.results,
          rowCount: count
        }, null, 2), {
          headers: { 'Content-Type': 'application/json' }
        });
        
      } catch (error) {
        return new Response(JSON.stringify({
          error: error.message,
          stack: error.stack
        }, null, 2), {
          status: 500,
          headers: { 'Content-Type': 'application/json' }
        });
      }
    }
  },
  '/admin/analytics-check': {
    GET: async (request, env, ctx) => {
      const tableInfo = await env.DB.prepare(`
        SELECT COUNT(*) as count FROM analytics
      `).first();
        
      const recentEntries = await env.DB.prepare(`
        SELECT * FROM analytics ORDER BY timestamp DESC LIMIT 5
      `).all();
      
      return Response.json({
        totalRows: tableInfo.count,
        recentEntries: recentEntries.results || [],
        message: tableInfo.count === 0 ? 'Analytics table is empty. Visit some pages to generate data!' : 'Analytics data found'
      });
    }
  },

  '/admin/federation' : {
    GET: async (request, env, ctx) => {
      const user = await checkAuth(request, env, ctx);
      if (!user) {
        return Response.redirect(`${new URL(request.url).origin}/login`);
      }

      // load dynamic config
      const config = await env.services.config.getConfig();

      // instantiate service
      const fed = new FederationService(env);

      let domains = [];
      let posts = [];
      try {
        domains = await fed.getConnectedDomains() || [];
        const postRes = await env.DB.prepare(`
          SELECT * FROM posts 
          WHERE post_type = 'federated' 
          ORDER BY created_at DESC 
          LIMIT 20
        `).all();
        posts = postRes.results || [];
      } catch (err) {
        console.error('Federation data fetch failed:', err);
        // Render with empty data to avoid crash
      }

      // render
      return new Response(
        federationDashboard(posts, domains, user, config),
        { headers: { 'Content-Type': 'text/html' } }
      );
    }
  },

  '/admin/analytics': {
    GET: async (request, env, ctx) => {
      const config = await env.services.config.getConfig();
      
      try {
        // Get analytics summary (last 7 days)
        const summary = await env.DB.prepare(`
          SELECT 
            COUNT(*) as total_requests,
            COUNT(DISTINCT ip) as unique_visitors,
            AVG(duration) as avg_duration,
            MAX(duration) as max_duration,
            SUM(CASE WHEN status >= 400 THEN 1 ELSE 0 END) as error_count
          FROM analytics
          WHERE date(timestamp) >= date('now', '-7 days')
        `).first();
        
        // Get hourly traffic (last 24 hours) - use hour_bucket
        const hourlyTraffic = await env.DB.prepare(`
          SELECT 
            hour_bucket as hour,
            COUNT(*) as requests,
            COUNT(DISTINCT ip) as unique_visitors
          FROM analytics
          WHERE date(timestamp) >= date('now', '-1 day')
          GROUP BY hour_bucket
          ORDER BY hour_bucket
        `).all();
        
        // Get top paths (last 7 days)
        const topPaths = await env.DB.prepare(`
          SELECT 
            path,
            COUNT(*) as hit_count,
            AVG(duration) as avg_duration,
            COUNT(DISTINCT ip) as unique_visitors
          FROM analytics
          WHERE date(timestamp) >= date('now', '-7 days')
          GROUP BY path
          ORDER BY hit_count DESC
          LIMIT 10
        `).all();
        
        // Get country stats (last 7 days)
        const countryStats = await env.DB.prepare(`
          SELECT 
            country,
            COUNT(*) as requests,
            COUNT(DISTINCT ip) as unique_visitors
          FROM analytics
          WHERE date(timestamp) >= date('now', '-7 days')
            AND country IS NOT NULL 
            AND country != 'unknown'
          GROUP BY country
          ORDER BY requests DESC
          LIMIT 20
        `).all();
        
        // Ensure we have arrays even if queries return no results
        const analyticsData = {
          summary: summary || { 
            total_requests: 0, 
            unique_visitors: 0, 
            avg_duration: 0, 
            error_count: 0 
          },
          topPaths: topPaths?.results || [],
          hourlyTraffic: hourlyTraffic?.results || [],
          countryStats: countryStats?.results || []
        };
        
        // Fill in missing hours for the chart (0-23)
        const hoursData = new Map();
        for (let i = 0; i < 24; i++) {
          hoursData.set(i, { hour: i, requests: 0, unique_visitors: 0 });
        }
        
        // Update with actual data
        analyticsData.hourlyTraffic.forEach(hour => {
          hoursData.set(hour.hour, hour);
        });
        
        // Convert back to sorted array
        analyticsData.hourlyTraffic = Array.from(hoursData.values()).sort((a, b) => a.hour - b.hour);
        
        return new Response(
          renderAnalyticsTemplate({
            ...analyticsData,
            user: request.user,
            config
          }),
          { headers: { 'Content-Type': 'text/html' } }
        );
        
      } catch (error) {
        console.error('Analytics error:', error);
        
        // Return page with empty data
        return new Response(
          renderAnalyticsTemplate({
            summary: { total_requests: 0, unique_visitors: 0, avg_duration: 0, error_count: 0 },
            topPaths: [],
            hourlyTraffic: [],
            countryStats: [],
            user: request.user,
            config
          }),
          { headers: { 'Content-Type': 'text/html' } }
        );
      }
    }
  }

};
