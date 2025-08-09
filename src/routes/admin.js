// src/routes/admin.js - Refactored to use deadlight-lib
import { 
  renderAddPostForm, 
  renderEditPostForm, 
  renderAddUserForm, 
  renderDeleteConfirmation
} from '../templates/admin/index.js';
import { handleProxyRoutes, handleProxyTests } from './proxy.js';
import { checkAuth } from '../utils/auth.js';
import { renderTemplate } from '../templates/base.js';
import { UserModel, PostModel } from '../../lib.deadlight/core/src/db/models/index.js';
import { Logger } from '../../lib.deadlight/core/src/logging/logger.js';
import { DatabaseError } from '../../lib.deadlight/core/src/db/base.js';

export const adminRoutes = {
'/admin': {
  GET: async (request, env) => {
    const user = await checkAuth(request, env);
    if (!user) {
      return Response.redirect(`${new URL(request.url).origin}/login`);
    }

    try {
      // Get dynamic config
      const { configService } = await import('../services/config.js');
      const config = await configService.getConfig(env.DB);

      // Gather stats using direct DB queries
      let stats = {
        totalPosts: 0,
        totalUsers: 0,
        postsToday: 0,
        publishedPosts: 0
      };

      let posts = [];
      let requestStats = []; // You can implement this later if needed

      try {
        // Count total posts (excluding emails)
        const postsCount = await env.DB.prepare(`
          SELECT COUNT(*) as count FROM posts 
          WHERE (is_email = 0 OR is_email IS NULL)
        `).first();
        stats.totalPosts = postsCount?.count || 0;

        // Count total users
        const usersCount = await env.DB.prepare('SELECT COUNT(*) as count FROM users').first();
        stats.totalUsers = usersCount?.count || 0;

        // Count posts created today
        const today = new Date().toISOString().split('T')[0];
        const todayCount = await env.DB.prepare(`
          SELECT COUNT(*) as count FROM posts 
          WHERE DATE(created_at) = ? AND (is_email = 0 OR is_email IS NULL)
        `).bind(today).first();
        stats.postsToday = todayCount?.count || 0;

        // Count published posts
        const publishedCount = await env.DB.prepare(`
          SELECT COUNT(*) as count FROM posts 
          WHERE published = 1 AND (is_email = 0 OR is_email IS NULL)
        `).first();
        stats.publishedPosts = publishedCount?.count || 0;

        // Get recent posts with author info
        const recentPostsQuery = await env.DB.prepare(`
          SELECT p.id, p.title, p.slug, p.created_at, p.published, p.author_id, u.username as author_username
          FROM posts p
          LEFT JOIN users u ON p.author_id = u.id
          WHERE (p.is_email = 0 OR p.is_email IS NULL)
          ORDER BY p.created_at DESC 
          LIMIT 10
        `).all();
        posts = recentPostsQuery.results || [];

      } catch (dbError) {
        console.error('Database query error in admin dashboard:', dbError);
        // Keep default empty stats if queries fail
      }

      // Your template expects: renderAdminDashboard(stats, posts, requestStats, user, config)
      const { renderAdminDashboard } = await import('../templates/admin/dashboard.js');
      return new Response(renderAdminDashboard(stats, posts, requestStats, user, config), {
        headers: { 'Content-Type': 'text/html' }
      });

    } catch (error) {
      console.error('Admin dashboard error:', error);
      
      // Fallback with minimal stats
      const fallbackStats = { totalPosts: 0, totalUsers: 0, postsToday: 0, publishedPosts: 0 };
      const { renderAdminDashboard } = await import('../templates/admin/dashboard.js');
      
      try {
        return new Response(renderAdminDashboard(fallbackStats, [], [], user, config), {
          headers: { 'Content-Type': 'text/html' }
        });
      } catch (templateError) {
        // Ultimate fallback
        return new Response(`
          <h1>Admin Dashboard</h1>
          <p>Dashboard temporarily unavailable. <a href="/admin/add">Add Post</a> | <a href="/admin/users">Manage Users</a></p>
        `, {
          headers: { 'Content-Type': 'text/html' }
        });
      }
    }
  }
},

  '/admin/edit/:id': {
    GET: async (request, env) => {
      const postModel = new PostModel(env.DB);
      const user = await checkAuth(request, env);
      
      if (!user) {
        return Response.redirect(`${new URL(request.url).origin}/login`);
      }

      try {
        // Get dynamic config
        const { configService } = await import('../services/config.js');
        const config = await configService.getConfig(env.DB);
        
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
    POST: async (request, env) => {
      const postModel = new PostModel(env.DB);
      const logger = new Logger({ context: 'admin' });
      const user = await checkAuth(request, env);
      
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
          published
        });

        logger.info('Post updated successfully', { 
          postId, 
          title,
          slug: updatedPost.slug,
          published: updatedPost.published 
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
    GET: async (request, env) => {
      const user = await checkAuth(request, env);
      if (!user) {
        return Response.redirect(`${new URL(request.url).origin}/login`);
      }

      try {
        const { SettingsModel } = await import('../../../../lib.deadlight/core/src/db/models/index.js');
        const settingsModel = new SettingsModel(env.DB);
        const settings = await settingsModel.getAll();
        
        const { renderSettings } = await import('../templates/admin/settings.js');
        return new Response(renderSettings(settings, user), {
          headers: { 'Content-Type': 'text/html' }
        });
      } catch (error) {
        console.error('Settings error:', error);
        return new Response('Internal server error', { status: 500 });
      }
    },

    POST: async (request, env) => {
      const user = await checkAuth(request, env);
      if (!user) {
        return Response.redirect(`${new URL(request.url).origin}/login`);
      }

      try {
        const formData = await request.formData();
        const { SettingsModel } = await import('../../../../lib.deadlight/core/src/db/models/index.js');
        const settingsModel = new SettingsModel(env.DB);
        
        // Update text/number settings
        await settingsModel.set('site_title', formData.get('site_title') || '', 'string');
        await settingsModel.set('site_description', formData.get('site_description') || '', 'string');
        await settingsModel.set('posts_per_page', formData.get('posts_per_page') || '10', 'number');
        await settingsModel.set('date_format', formData.get('date_format') || 'M/D/YYYY', 'string');
        await settingsModel.set('timezone', formData.get('timezone') || 'UTC', 'string');
        
        // Update boolean settings (checkboxes)
        await settingsModel.set('enable_registration', formData.has('enable_registration'), 'boolean');
        await settingsModel.set('require_login_to_read', formData.has('require_login_to_read'), 'boolean');
        await settingsModel.set('maintenance_mode', formData.has('maintenance_mode'), 'boolean');
        
        // Clear config cache so changes take effect immediately
        const { configService } = await import('../services/config.js');
        configService.clearCache();
        
        return Response.redirect(`${new URL(request.url).origin}/admin`);
      } catch (error) {
        console.error('Settings update error:', error);
        return new Response('Failed to update settings', { status: 500 });
      }
    }
  },

  '/admin/add': {
    GET: async (request, env) => {
      const user = await checkAuth(request, env);
      if (!user) {
        return Response.redirect(`${new URL(request.url).origin}/login`);
      }

      // Get dynamic config
      const { configService } = await import('../services/config.js');
      const config = await configService.getConfig(env.DB);

      return new Response(renderAddPostForm(user, config), {
        headers: { 'Content-Type': 'text/html' }
      });
    },

    POST: async (request, env) => {
      const postModel = new PostModel(env.DB);
      const logger = new Logger({ context: 'admin' });
      const user = await checkAuth(request, env);
      
      if (!user) {
        return Response.redirect(`${new URL(request.url).origin}/login`);
      }

      try {
        const formData = await request.formData();
        const title = formData.get('title');
        const content = formData.get('content');
        const slug = formData.get('slug') || '';
        const excerpt = formData.get('excerpt') || '';
        // Check if checkbox is present (checkboxes only send value when checked)
        const published = formData.has('published');

        logger.info('Adding post', { 
          title, 
          contentLength: content?.length,
          published // Log the published status
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
          published // This will be true/false
        });

        logger.info('Post created successfully', { 
          postId: newPost.id, 
          title,
          published: newPost.published 
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
    POST: async (request, env) => {
      const postModel = new PostModel(env.DB);
      const logger = new Logger({ context: 'admin' });
      const user = await checkAuth(request, env);
      
      if (!user) {
        return Response.redirect(`${new URL(request.url).origin}/login`);
      }

      try {
        const postId = request.params.id;
        
        // Delete post using model
        await postModel.delete(postId);

        logger.info('Post deleted successfully', { postId });

        return Response.redirect(`${new URL(request.url).origin}/`);
      } catch (error) {
        logger.error('Error deleting post', { postId: request.params.id, error: error.message });
        
        if (error instanceof DatabaseError && error.code === 'NOT_FOUND') {
          return new Response('Post not found', { status: 404 });
        }
        
        return new Response('Failed to delete post', { status: 500 });
      }
    }
  },

  '/admin/users': {
    GET: async (request, env) => {
      const userModel = new UserModel(env.DB);
      const user = await checkAuth(request, env);
      
      if (!user) {
        return Response.redirect(`${new URL(request.url).origin}/login`);
      }

      try {
        // Get dynamic config
        const { configService } = await import('../services/config.js');
        const config = await configService.getConfig(env.DB);
        
        // Get all users (paginated in the future if needed)
        const users = await userModel.list({ limit: 50 });
        const totalUsers = await userModel.count();

        // Use the template instead of inline HTML
        const { renderUserManagement } = await import('../templates/admin/userManagement.js');
        
        return new Response(renderUserManagement(users, user, config), {
          headers: { 'Content-Type': 'text/html' }
        });
      } catch (error) {
        console.error('User management error:', error);
        return new Response('Internal server error', { status: 500 });
      }
    }
  },

  '/admin/users/add': {
    GET: async (request, env) => {
      const user = await checkAuth(request, env);
      if (!user) {
        return Response.redirect(`${new URL(request.url).origin}/login`);
      }

      // Get dynamic config
      const { configService } = await import('../services/config.js');
      const config = await configService.getConfig(env.DB);

      return new Response(renderAddUserForm(user, config), {
        headers: { 'Content-Type': 'text/html' }
      });
    },

    POST: async (request, env) => {
      const userModel = new UserModel(env.DB);
      const logger = new Logger({ context: 'admin' });
      const user = await checkAuth(request, env);
      
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
    POST: async (request, env) => {
      const userModel = new UserModel(env.DB);
      const logger = new Logger({ context: 'admin' });
      const user = await checkAuth(request, env);
      
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
    GET: async (request, env) => {
      const user = await checkAuth(request, env);
      if (!user) {
        return Response.redirect(`${new URL(request.url).origin}/login`);
      }

      return await handleProxyRoutes(request, env, user);
    }
  },

  // Proxy API Test Endpoints
  '/admin/proxy/test-blog-api': {
    GET: async (request, env) => {
      const user = await checkAuth(request, env);
      if (!user) {
        return Response.json({ success: false, error: 'Unauthorized' }, { status: 401 });
      }

      return await handleProxyTests.testBlogApi(request, env);
    }
  },

  '/admin/proxy/test-email-api': {
    GET: async (request, env) => {
      const user = await checkAuth(request, env);
      if (!user) {
        return Response.json({ success: false, error: 'Unauthorized' }, { status: 401 });
      }

      return await handleProxyTests.testEmailApi(request, env);
    }
  },

  '/admin/proxy/test-federation': {
    GET: async (request, env) => {
      const user = await checkAuth(request, env);
      if (!user) {
        return Response.json({ success: false, error: 'Unauthorized' }, { status: 401 });
      }

      return await handleProxyTests.testFederation(request, env);
    }
  },

  '/admin/proxy/send-test-email': {
    POST: async (request, env) => {
      const user = await checkAuth(request, env);
      if (!user) {
        return Response.json({ success: false, error: 'Unauthorized' }, { status: 401 });
      }

      return await handleProxyTests.sendTestEmail(request, env);
    }
  },

  '/admin/inject-emails': {
    GET: async (request, env) => {
      const user = await checkAuth(request, env);
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

    POST: async (request, env) => {
      const logger = new Logger({ context: 'admin' });
      const user = await checkAuth(request, env);
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
            from: "Test User <test@example.com>",
            to: "deadlight.boo@gmail.com",
            date: "Sun, 03 Aug 2025 10:00:00 -0700",
            message_id: "test-1234567890@example.com"
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
    POST: async (request, env) => {
      const logger = new Logger({ context: 'admin' });
      const user = await checkAuth(request, env);
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

  '/admin/pending-replies': {
    GET: async (request, env) => {
      const logger = new Logger({ context: 'admin' });
      const user = await checkAuth(request, env);
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

    POST: async (request, env) => {
      const logger = new Logger({ context: 'admin' });
      const user = await checkAuth(request, env);
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
  }
};
