// src/routes/admin.js
import { 
  renderAddPostForm, 
  renderEditPostForm, 
  renderAddUserForm, 
  renderDeleteConfirmation,
  renderAddCommentForm
} from '../../../lib.deadlight/core/src/components/admin/index.js';
import { federationDashboard } from '../templates/admin/federationDashboard.js';
import { FederationService } from '../services/federation.js';
import { renderTemplate } from '../templates/base.js';
import { UserModel, PostModel, SettingsModel } from '../../../lib.deadlight/core/src/db/models/index.js';
import { Logger } from '../../../lib.deadlight/core/src/logging/logger.js';
import { DatabaseError } from '../../../lib.deadlight/core/src/db/base.js';
import { ProxyService } from '../services/proxy.js';
import { QueueService } from '../services/queue.js';
import { renderAdminDashboard } from '../templates/admin/index.js';
import { renderSettings } from '../templates/admin/settings.js';
import { renderAnalyticsTemplate } from '../templates/admin/analytics.js';
import { renderCommentList, renderReplyForm } from '../templates/admin/comments.js';
import { renderUserManagement } from '../templates/admin/userManagement.js';
import { handleProxyRoutes, handleProxyTests } from './proxy.js';
import { AnalyticsService } from '../services/analytics.js';
import { parseCookies } from '../utils/utils.js';

// Constants
const DEFAULT_API_AUTHOR_ID = 2;
const POSTS_PER_PAGE_DEFAULT = 10;

// Helper functions
const getOrigin = (request) => new URL(request.url).origin;

const createErrorResponse = (message, details = null, status = 500) => {
  return Response.json({ 
    success: false, 
    error: message, 
    ...(details && { details }) 
  }, { status });
};

const renderErrorPage = (error, user, title = 'Error') => {
  return new Response(
    renderTemplate(title, `<p>Error: ${error.message}</p>`, user),
    { headers: { 'Content-Type': 'text/html' }, status: 500 }
  );
};

// API Key Authentication Helper
const checkApiKey = (request, env) => {
  const apiKey = request.headers.get('X-API-Key');
  const expectedKey = env.X_API_KEY;
  return apiKey === expectedKey;
};

export const adminRoutes = {
  '/admin': {
    GET: async (request, env, ctx) => {
      const user = ctx.user;
      const logger = new Logger({ context: 'admin' });

      try {
        const config = await env.services.config.getConfig();
        const postModel = new PostModel(env.DB);
        const userModel = new UserModel(env.DB);
        const analyticsService = new AnalyticsService(env.DB); // Instantiate service

        // Get recent posts
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
        // Make sure PostModel has getPostsCreatedToday() implemented as discussed
        const [totalPosts, publishedPosts, totalUsers, postsToday] = await Promise.all([
          postModel.count(false),
          postModel.count(true),
          userModel.count(),
          postModel.getPostsCreatedToday() // Assuming PostModel has this now
        ]);

        // Get analytics data using the new service
        let dashboardAnalytics = {
          requestStats: [],
          browserStats: [],
          activeVisitors: 0
        };
        try {
          dashboardAnalytics = await analyticsService.getDashboardAnalytics();
        } catch (analyticsError) {
          logger.warn('Dashboard analytics failed to load', { error: analyticsError.message });
          // dashboardAnalytics already initialized with defaults, so no need to re-assign
        }

        const stats = {
          totalPosts,
          publishedPosts,
          postsToday,
          totalUsers,
          activeVisitors: dashboardAnalytics.activeVisitors,
          browserStats: dashboardAnalytics.browserStats
        };

        return new Response(
          renderAdminDashboard(stats, recentPostsResult.posts, dashboardAnalytics.requestStats, user, config),
          { headers: { 'Content-Type': 'text/html' } }
        );
      } catch (error) {
        logger.error('Dashboard error', { error: error.message, stack: error.stack });
        // Simplified error page render, using the helper
        return renderErrorPage(error, user, 'Admin Dashboard Error');
      }
    }
  },

  '/admin/edit/:id': {
    GET: async (request, env, ctx) => {
      const user = ctx.user;
      const logger = new Logger({ context: 'admin' });

      try {
        const config = await env.services.config.getConfig();
        const postModel = new PostModel(env.DB);
        const postId = ctx.params.id;
        const post = await postModel.getById(postId);

        if (!post) {
          return new Response('Post not found', { status: 404 });
        }

        return new Response(renderEditPostForm(post, user, config), {
          headers: { 'Content-Type': 'text/html' }
        });
      } catch (error) {
        logger.error('Error loading post for edit', { postId: ctx.params.id, error: error.message });
        return new Response('Internal server error', { status: 500 });
      }
    },

    POST: async (request, env, ctx) => {
      const user = ctx.user;
      const postModel = new PostModel(env.DB);
      const logger = new Logger({ context: 'admin' });

      try {
        const postId = ctx.params.id;
        
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
        
        const updatedSlug = slug && slug !== existingPost.slug ? slug : existingPost.slug;
        
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

        return Response.redirect(getOrigin(request));
      } catch (error) {
        logger.error('Error updating post', { postId: ctx.params.id, error: error.message });
        
        if (error instanceof DatabaseError && error.code === 'NOT_FOUND') {
          return new Response('Post not found', { status: 404 });
        }
        
        return new Response(`Failed to update post: ${error.message}`, { status: 500 });
      }
    }
  },

  '/admin/settings': {
    GET: async (request, env, ctx) => {
      const user = ctx.user;
      const logger = new Logger({ context: 'admin' });

      try {
        const settingsModel = new SettingsModel(env.DB);
        const settings = await settingsModel.getAll();

        return new Response(renderSettings(settings, user), {
          headers: { 'Content-Type': 'text/html' }
        });
      } catch (error) {
        logger.error('Settings error', { error: error.message });
        return new Response('Internal server error', { status: 500 });
      }
    },

    POST: async (request, env, ctx) => {
      const user = ctx.user;
      const logger = new Logger({ context: 'admin' });

      try {
        const formData = await request.formData();
        const settingsModel = new SettingsModel(env.DB);
        
        // Update text/number settings
        await settingsModel.set('site_title', formData.get('site_title') || '', 'string');
        await settingsModel.set('site_description', formData.get('site_description') || '', 'string');
        await settingsModel.set('posts_per_page', formData.get('posts_per_page') || String(POSTS_PER_PAGE_DEFAULT), 'number');
        await settingsModel.set('date_format', formData.get('date_format') || 'M/D/YYYY', 'string');
        await settingsModel.set('timezone', formData.get('timezone') || 'UTC', 'string');
        await settingsModel.set('accent_color', formData.get('accent_color') || '#8ba3c7', 'string');
        
        // Update boolean settings
        await settingsModel.set('enable_registration', formData.has('enable_registration'), 'boolean');
        await settingsModel.set('require_login_to_read', formData.has('require_login_to_read'), 'boolean');
        await settingsModel.set('maintenance_mode', formData.has('maintenance_mode'), 'boolean');

        env.services.config.clearCache();

        return Response.redirect(getOrigin(request) + '/admin');
      } catch (error) {
        logger.error('Settings update error', { error: error.message });
        return new Response('Failed to update settings', { status: 500 });
      }
    }
  },

  '/admin/add': {
    GET: async (request, env, ctx) => {
      const user = ctx.user;
      const config = await env.services.config.getConfig();

      return new Response(renderAddPostForm(user, config), {
        headers: { 'Content-Type': 'text/html' }
      });
    },

    POST: async (request, env, ctx) => {
      const user = ctx.user;
      const postModel = new PostModel(env.DB);
      const logger = new Logger({ context: 'admin' });

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

        return Response.redirect(getOrigin(request));
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
      const user = ctx.user;
      const postModel = new PostModel(env.DB);
      const postId = ctx.params.id;
      
      const post = await postModel.getById(postId);
      if (!post) {
        return new Response('Post not found', { status: 404 });
      }
      
      const config = await env.services.config.getConfig();
      const csrfToken = ctx.csrfToken; 
      
      return new Response(
        renderDeleteConfirmation(post, user, config, csrfToken), 
        { headers: { 'Content-Type': 'text/html' } }
      );
    },
    
    POST: async (request, env, ctx) => { 
      const user = ctx.user;
      const postModel = new PostModel(env.DB);
      const logger = new Logger({ context: 'admin' });

      try {
        const postId = ctx.params.id;
        await postModel.delete(postId);

        logger.info('Post deleted successfully', { postId, userId: user.id });

        return Response.redirect(getOrigin(request), 303); 
      } catch (error) {
        logger.error('Error deleting post', { postId: ctx.params.id, error: error.message });
        
        if (error instanceof DatabaseError && error.code === 'NOT_FOUND') {
          return new Response('Post not found', { status: 404 });
        }
        
        return new Response('Failed to delete post', { status: 500 });
      }
    }
  },

  '/admin/users': {
    GET: async (request, env, ctx) => {
      const user = ctx.user;
      const logger = new Logger({ context: 'admin' });

      try {
        const userModel = new UserModel(env.DB);
        const config = await env.services.config.getConfig();
        
        const users = await userModel.list({ limit: 50, includeStats: true });
        
        return new Response(renderUserManagement(users, user, config), {
          headers: { 'Content-Type': 'text/html' }
        });
      } catch (error) {
        logger.error('User management error', { error: error.message });
        return new Response('Internal server error', { status: 500 });
      }
    }
  },

  '/admin/users/add': {
    GET: async (request, env, ctx) => {
      const user = ctx.user;
      const config = await env.services.config.getConfig();

      return new Response(renderAddUserForm(user, config), {
        headers: { 'Content-Type': 'text/html' }
      });
    },

    POST: async (request, env, ctx) => {
      const user = ctx.user;
      const userModel = new UserModel(env.DB);
      const logger = new Logger({ context: 'admin' });

      try {
        const formData = await request.formData();
        const username = formData.get('username');
        const password = formData.get('password');
        const role = formData.get('role') || 'user';

        if (!username || !password) {
          return new Response('Username and password are required', { status: 400 });
        }

        const newUser = await userModel.create({ username, password, role });

        logger.info('User created successfully', { userId: newUser.id, username, role });

        return Response.redirect(`${getOrigin(request)}/admin/users`);
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
      const user = ctx.user;
      const userModel = new UserModel(env.DB);
      const logger = new Logger({ context: 'admin' });

      try {
        const userId = parseInt(ctx.params.id);
        
        if (userId === user.id) {
          return new Response('Cannot delete yourself', { status: 400 });
        }

        await userModel.delete(userId);

        logger.info('User deleted successfully', { userId });

        return Response.redirect(`${getOrigin(request)}/admin/users`);
      } catch (error) {
        logger.error('Error deleting user', { userId: ctx.params.id, error: error.message });
        return new Response('Failed to delete user', { status: 500 });
      }
    }
  },

  '/admin/proxy': {
    GET: async (request, env, ctx) => {
      const user = ctx.user;
      return await handleProxyRoutes(request, env, user);
    }
  },

  '/admin/proxy/discover-domain': {
    POST: async (request, env, ctx) => {
      return await handleProxyTests.discoverDomain(request, env, ctx);
    }
  },

  '/admin/proxy/test-blog-api': {
    GET: async (request, env, ctx) => {
      return await handleProxyTests.testBlogApi(request, env, ctx);
    }
  },

  '/admin/proxy/test-email-api': {
    GET: async (request, env, ctx) => {
      return await handleProxyTests.testEmailApi(request, env, ctx);
    }
  },

  '/admin/proxy/test-federation': {
    GET: async (request, env, ctx) => {
      return await handleProxyTests.testFederation(request, env, ctx);
    }
  },

  '/admin/proxy/send-test-email': {
    POST: async (request, env, ctx) => {
      return await handleProxyTests.sendTestEmail(request, env, ctx);
    }
  },

  '/admin/send-notification': {
    POST: async (request, env, ctx) => {
      const logger = new Logger({ context: 'admin' });
      
      try {
        const { to, subject, body } = await request.json();
        
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
      } catch (error) {
        logger.error('Send notification error', { error: error.message });
        return createErrorResponse('Failed to send notification', error.message);
      }
    }
  },

  '/admin/queue-status': {
    GET: async (request, env, ctx) => {
      const user = ctx.user;
      
      if (user.role !== 'admin') {
        return createErrorResponse('Unauthorized', null, 401);
      }

      try {
        const status = await env.services.queue.getStatus();
        return Response.json(status);
      } catch (error) {
        return createErrorResponse('Failed to get queue status', error.message);
      }
    }
  },
  
  '/admin/process-queue': {
    POST: async (request, env, ctx) => {
      const user = ctx.user;
      
      if (user.role !== 'admin') {
        return createErrorResponse('Unauthorized', null, 401);
      }

      try {
        const result = await env.services.queue.processAll();
        
        return Response.json({ 
          success: true, 
          ...result,
          message: `Processed ${result.processed} items. Status: ${result.status}`
        });
      } catch (error) {
        return createErrorResponse('Queue processing failed', error.message);
      }
    }
  },

  '/admin/federation/sync': {
    POST: async (req, env, ctx) => {
      const user = ctx.user;
      const logger = new Logger({ context: 'admin' });
      
      try {
        const fedSvc = new FederationService(
          env,
          env.services.config,
          env.services.proxy,
          env.services.queue
        );
        
        const result = await fedSvc.syncNetwork();
        
        return Response.json({
          success: true,
          message: `Imported ${result.imported} new posts from ${result.domains} domains.`,
          imported: result.imported,
          domains: result.domains,
          newPosts: result.newPosts
        });
      } catch (error) {
        logger.error('Federation sync error', { error: error.message });
        return createErrorResponse('Federation sync failed', error.message);
      }
    }
  },

  '/federation/queue': {
    GET: async (request, env, ctx) => {
      const logger = new Logger({ context: 'federation' });
      
      try {
        const url = new URL(request.url);
        const limit = parseInt(url.searchParams.get('limit') || '50');
        const since = url.searchParams.get('since');

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
          next: null
        };

        return new Response(JSON.stringify(response), {
          headers: { 'Content-Type': 'application/json' }
        });
      } catch (error) {
        logger.error('Federation queue error', { error: error.message });
        return createErrorResponse('Failed to fetch federation queue', error.message);
      }
    }
  },

  '/admin/federate-post/:id': {
    POST: async (request, env, ctx) => {
      const user = ctx.user;
      const logger = new Logger({ context: 'admin' });
      const postId = ctx.params.id;
      
      try {
        const fedSvc = new FederationService(
          env,
          env.services.config,
          env.services.proxy,
          env.services.queue
        );
        
        const post = await env.DB.prepare('SELECT * FROM posts WHERE id = ?').bind(postId).first();
        if (!post) {
          return createErrorResponse('Post not found', null, 404);
        }
        
        const domains = await fedSvc.getConnectedDomains();
        const targetDomains = domains.map(d => d.domain);
        
        if (targetDomains.length === 0) {
          return createErrorResponse('No federated domains found', null, 400);
        }
        
        const results = await fedSvc.publishPost(post, targetDomains);
        
        logger.info('Post federated', { postId, domains: targetDomains.length });
        
        return Response.json({ 
          success: true, 
          message: `Post federated to ${targetDomains.length} domains`,
          results 
        });
      } catch (error) {
        logger.error('Federation error', { postId, error: error.message });
        return createErrorResponse('Failed to federate post', error.message);
      }
    }
  },

  '/admin/inject-emails': {
    GET: async (request, env, ctx) => {
      const user = ctx.user;

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
      const user = ctx.user;
      const logger = new Logger({ context: 'admin' });

      try {
        const mockEmails = [
          {
            subject: "Your account is live - join millions of businesses on Google",
            body: "thatch, welcome to Google\n\nNow you can start growing your business.\n\nComplete your profile...",
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

            const shortMsgId = email.message_id.length > 20 
              ? email.message_id.substring(0, 20) 
              : email.message_id;
              
            const existing = await env.DB.prepare(
              'SELECT id FROM posts WHERE is_email = 1 AND email_metadata LIKE ? LIMIT 1'
            ).bind(`%${shortMsgId}%`).first();
            
            if (!existing) {
              await env.DB.prepare(`
                INSERT INTO posts (title, content, slug, author_id, created_at, updated_at, published, is_email, email_metadata)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
              `).bind(
                email.subject,
                email.body,
                `email-${Date.now()}-${Math.random().toString(36).substring(2, 7)}`,
                user.id,
                email.date || new Date().toISOString(),
                new Date().toISOString(),
                0,
                1,
                metadata
              ).run();
              
              insertedCount++;
              logger.info('Injected email', { subject: email.subject, userId: user.id });
            } else {
              logger.info('Skipped existing email', { subject: email.subject });
            }
          } catch (err) {
            logger.error('Error injecting email', { subject: email.subject, error: err.message });
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
        return renderErrorPage(error, user, 'Injection Error');
      }
    }
  },

  '/admin/fetch-emails': {
    POST: async (request, env, ctx) => {
      const logger = new Logger({ context: 'admin' });
      
      // Check both user auth and API key
      const user = ctx.user;
      const hasApiKey = checkApiKey(request, env);
      
      if (!user && !hasApiKey) {
        logger.warn('Unauthorized fetch-emails attempt', { 
          ip: request.headers.get('CF-Connecting-IP') || 'unknown' 
        });
        return createErrorResponse('Unauthorized', null, 403);
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

              const existing = await env.DB.prepare(
                'SELECT id FROM posts WHERE is_email = 1 AND title = ? LIMIT 1'
              ).bind(email.subject || 'Untitled Email').first();
              
              if (!existing) {
                await env.DB.prepare(`
                  INSERT INTO posts (title, content, slug, author_id, created_at, updated_at, published, is_email, email_metadata)
                  VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                `).bind(
                  email.subject || 'Untitled Email',
                  email.body || 'No content',
                  `email-${Date.now()}-${Math.random().toString(36).substring(2, 7)}`,
                  user?.id || DEFAULT_API_AUTHOR_ID,
                  email.date || new Date().toISOString(),
                  new Date().toISOString(),
                  0,
                  1,
                  metadata
                ).run();
                
                insertedCount++;
                logger.info('Fetched and inserted email', { 
                  subject: email.subject || 'Untitled Email',
                  userId: user?.id || 'API'
                });
              } else {
                logger.info('Skipped existing email', { 
                  subject: email.subject || 'Untitled Email' 
                });
              }
            } catch (err) {
              logger.error('Error inserting email', { 
                subject: email.subject || 'Untitled Email',
                error: err.message 
              });
            }
          }
        }
        
        return Response.json({ success: true, inserted: insertedCount });
      } catch (error) {
        logger.error('Error fetching emails via API', { error: error.message });
        return createErrorResponse('Failed to fetch emails', error.message);
      }
    }
  },

  '/admin/notifications': {
    GET: async (request, env, ctx) => {
      const user = ctx.user;
      const logger = new Logger({ context: 'admin' });
      
      try {
        const notifications = await env.DB.prepare(`
          SELECT * FROM notifications WHERE user_id = ? ORDER BY created_at DESC LIMIT 50
        `).bind(user.id).all();
        
        // TODO: Implement notification template rendering
        return Response.json({ 
          success: true, 
          notifications: notifications.results || [] 
        });
      } catch (error) {
        logger.error('Notifications error', { error: error.message });
        return createErrorResponse('Failed to fetch notifications', error.message);
      }
    }
  },

  '/admin/moderation-keywords': {
    GET: async (req, env, ctx) => {
      try {
        const keywords = await env.services.config.getModerationKeywords();
        return Response.json({ keywords });
      } catch (error) {
        return createErrorResponse('Failed to get moderation keywords', error.message);
      }
    },

    POST: async (req, env, ctx) => {
      const logger = new Logger({ context: 'admin' });
      
      try {
        const { keywords } = await req.json();
        
        if (!Array.isArray(keywords)) {
          return createErrorResponse('keywords must be array', null, 400);
        }

        await env.services.moderation.setKeywords(keywords);
        
        logger.info('Moderation keywords updated', { count: keywords.length });
        
        return Response.json({ success: true, keywords });
      } catch (error) {
        logger.error('Error updating moderation keywords', { error: error.message });
        return createErrorResponse('Failed to update keywords', error.message);
      }
    }
  },

  '/admin/check-moderation': {
    POST: async (req, env, ctx) => {
      const logger = new Logger({ context: 'admin' });
      
      try {
        const { content } = await req.json();
        const result = await env.services.moderation.check(content);
        return Response.json(result);
      } catch (error) {
        logger.error('Moderation check error', { error: error.message });
        return createErrorResponse('Moderation check failed', error.message);
      }
    }
  },

  '/admin/moderation': {
    GET: async (request, env, ctx) => {
      const user = ctx.user;
      const logger = new Logger({ context: 'admin' });

      try {
        const { results: pendingPosts } = await env.DB.prepare(`
          SELECT id, title, content, author_id, created_at, moderation_notes
          FROM posts
          WHERE post_type = 'federated'
            AND moderation_status = 'pending'
          ORDER BY created_at DESC
          LIMIT 100
        `).all();

        const rows = (pendingPosts || []).map(p => {
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
      } catch (error) {
        logger.error('Moderation queue error', { error: error.message });
        return renderErrorPage(error, user, 'Moderation Queue Error');
      }
    }
  },

  '/admin/pending-replies': {
    GET: async (request, env, ctx) => {
      const logger = new Logger({ context: 'admin' });
      
      const user = ctx.user;
      const hasApiKey = checkApiKey(request, env);
      
      if ((!user || user.role !== 'admin') && !hasApiKey) {
        logger.warn('Unauthorized pending-replies attempt', { 
          ip: request.headers.get('CF-Connecting-IP') || 'unknown',
          keyProvided: !!request.headers.get('X-API-Key'),
          userPresent: !!user,
          userRole: user?.role || 'none'
        });
        return createErrorResponse('Unauthorized', null, 403);
      }
      
      try {
        const query = 'SELECT * FROM posts WHERE is_reply_draft = 1 AND email_metadata LIKE \'%"sent":false%\'';
        const repliesResult = await env.DB.prepare(query).all();
        
        const pendingReplies = (repliesResult.results || []).map(reply => {
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
        
        return Response.json({ success: true, replies: pendingReplies });
      } catch (error) {
        logger.error('Error fetching pending replies', { error: error.message });
        return createErrorResponse('Failed to fetch pending replies', error.message);
      }
    },

    POST: async (request, env, ctx) => {
      const logger = new Logger({ context: 'admin' });
      
      const user = ctx.user;
      const hasApiKey = checkApiKey(request, env);
      
      if ((!user || user.role !== 'admin') && !hasApiKey) {
        logger.warn('Unauthorized mark-sent attempt', { 
          ip: request.headers.get('CF-Connecting-IP') || 'unknown'
        });
        return createErrorResponse('Unauthorized', null, 403);
      }
      
      try {
        const payload = await request.json();
        const replyId = payload.id;
        
        if (!replyId) {
          return createErrorResponse('Reply ID required', null, 400);
        }
        
        const replyResult = await env.DB.prepare(
          'SELECT * FROM posts WHERE id = ? AND is_reply_draft = 1'
        ).bind(replyId).first();
        
        if (!replyResult) {
          return createErrorResponse('Reply not found', null, 404);
        }
        
        const metadata = replyResult.email_metadata ? JSON.parse(replyResult.email_metadata) : {};
        metadata.sent = true;
        metadata.date_sent = new Date().toISOString();
        
        await env.DB.prepare(
          'UPDATE posts SET email_metadata = ?, updated_at = ? WHERE id = ?'
        ).bind(
          JSON.stringify(metadata),
          new Date().toISOString(),
          replyId
        ).run();
        
        logger.info('Marked reply as sent', { replyId, userId: user?.id || 'API' });
        
        return Response.json({ success: true, id: replyId });
      } catch (error) {
        logger.error('Error marking reply as sent', { error: error.message });
        return createErrorResponse('Failed to mark reply as sent', error.message);
      }
    }
  },

  '/admin/proxy/status-stream': {
    GET: async (request, env, ctx) => {
      return await handleProxyTests.statusStream(request, env, ctx);
    }
  },

  '/admin/proxy/status': {
    GET: async (request, env, ctx) => {
      const logger = new Logger({ context: 'admin' });
      
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
        logger.error('Proxy status error', { error: error.message });
        return Response.json({
          success: false,
          error: error.message,
          timestamp: new Date().toISOString()
        });
      }
    }
  },

  '/admin/analytics-debug': {
    GET: async (request, env, ctx) => {
      const logger = new Logger({ context: 'admin' });
      
      try {
        const tableCheck = await env.DB.prepare(`
          SELECT name FROM sqlite_master 
          WHERE type='table' AND name='analytics'
        `).first();
        
        if (!tableCheck) {
          return new Response('Analytics table does not exist', { status: 404 });
        }
        
        const schema = await env.DB.prepare(`
          SELECT sql FROM sqlite_master 
          WHERE type='table' AND name='analytics'
        `).first();
        
        const columns = await env.DB.prepare(`
          PRAGMA table_info(analytics)
        `).all();
        
        let count = 0;
        try {
          const countResult = await env.DB.prepare(`
            SELECT COUNT(*) as count FROM analytics
          `).first();
          count = countResult.count;
        } catch (e) {
          count = `Error: ${e.message}`;
        }
        
        return Response.json({
          exists: true,
          schema: schema.sql,
          columns: columns.results,
          rowCount: count
        }, { status: 200 });
        
      } catch (error) {
        logger.error('Analytics debug error', { error: error.message });
        return Response.json({
          error: error.message,
          stack: error.stack
        }, { status: 500 });
      }
    }
  },

  '/admin/analytics-check': {
    GET: async (request, env, ctx) => {
      const logger = new Logger({ context: 'admin' });
      
      try {
        const tableInfo = await env.DB.prepare(`
          SELECT COUNT(*) as count FROM analytics
        `).first();
          
        const recentEntries = await env.DB.prepare(`
          SELECT * FROM analytics ORDER BY timestamp DESC LIMIT 5
        `).all();
        
        return Response.json({
          totalRows: tableInfo.count,
          recentEntries: recentEntries.results || [],
          message: tableInfo.count === 0 
            ? 'Analytics table is empty. Visit some pages to generate data!' 
            : 'Analytics data found'
        });
      } catch (error) {
        logger.error('Analytics check error', { error: error.message });
        return createErrorResponse('Analytics check failed', error.message);
      }
    }
  },

  '/admin/federation': {
    GET: async (request, env, ctx) => {
      const user = ctx.user;
      const logger = new Logger({ context: 'admin' });

      try {
        const config = await env.services.config.getConfig();

        const fedSvc = new FederationService(
          env,
          env.services.config,
          env.services.proxy,
          env.services.queue
        );

        let domains = [];
        let posts = [];
        
        try {
          domains = await fedSvc.getConnectedDomains() || [];
          const postRes = await env.DB.prepare(`
            SELECT * FROM posts 
            WHERE post_type = 'federated' 
            ORDER BY created_at DESC 
            LIMIT 20
          `).all();
          posts = postRes.results || [];
        } catch (err) {
          logger.error('Federation data fetch failed', { error: err.message });
        }

        return new Response(
          federationDashboard(posts, domains, user, config),
          { headers: { 'Content-Type': 'text/html' } }
        );
      } catch (error) {
        logger.error('Federation dashboard error', { error: error.message });
        return renderErrorPage(error, user, 'Federation Dashboard Error');
      }
    }
  },

  '/admin/analytics': {
    GET: async (request, env, ctx) => {
      const user = ctx.user;
      const logger = new Logger({ context: 'admin' });
      
      try {
        const config = await env.services.config.getConfig();
        
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
        
        analyticsData.hourlyTraffic.forEach(hour => {
          hoursData.set(hour.hour, hour);
        });
        
        analyticsData.hourlyTraffic = Array.from(hoursData.values())
          .sort((a, b) => a.hour - b.hour);
        
        return new Response(
          renderAnalyticsTemplate({
            ...analyticsData,
            user,
            config
          }),
          { headers: { 'Content-Type': 'text/html' } }
        );
        
      } catch (error) {
        logger.error('Analytics error', { error: error.message });
        
        // Return page with empty data on error
        const config = await env.services.config.getConfig();
        return new Response(
          renderAnalyticsTemplate({
            summary: { total_requests: 0, unique_visitors: 0, avg_duration: 0, error_count: 0 },
            topPaths: [],
            hourlyTraffic: [],
            countryStats: [],
            user,
            config
          }),
          { headers: { 'Content-Type': 'text/html' } }
        );
      }
    }
  }
};