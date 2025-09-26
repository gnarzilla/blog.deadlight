// src/routes/api.js - Complete file without withAuth wrapper
import { PostModel, UserModel, SettingsModel } from '../../../lib.deadlight/core/src/db/models/index.js';
import { Logger } from '../../../lib.deadlight/core/src/logging/logger.js';
import { FederationService } from '../services/federation.js';
import { OutboxService } from '../services/outbox.js';
import { EnhancedOutboxService } from '../services/enhanced-outbox.js';
import { ProxyService } from '../services/proxy.js';

const logger = new Logger({ context: 'api' });

export const apiRoutes = {
  // ===== HEALTH & STATUS (Public) =====
  '/api/health': {
    GET: async (request, env, ctx) => {
      return Response.json({ 
        status: 'ok', 
        timestamp: new Date().toISOString(),
        version: '4.0.0'
      });
    }
  },

  '/api/status': {
    GET: async (request, env, ctx) => {
      try {
        const [dbCheck, proxyCheck] = await Promise.allSettled([
          env.DB.prepare('SELECT 1').first(),
          fetch(`${env.PROXY_URL || 'http://localhost:8080'}/api/health`).then(r => r.ok)
        ]);
        
        return Response.json({
          status: 'operational',
          components: {
            database: dbCheck.status === 'fulfilled' ? 'healthy' : 'unhealthy',
            proxy: proxyCheck.status === 'fulfilled' && proxyCheck.value ? 'healthy' : 'unhealthy',
            worker: 'healthy'
          },
          timestamp: new Date().toISOString()
        });
      } catch (error) {
        return Response.json({ 
          status: 'degraded', 
          error: error.message 
        }, { status: 503 });
      }
    }
  },

  // ===== NEW METRICS ENDPOINT (Corrected DB Logic) =====
  '/api/metrics': {
    GET: async (request, env, ctx) => {
      try {
        // 1. Prepare the D1 queries (without .first() or .all() at this stage)
        const statements = [
          env.DB.prepare('SELECT COUNT(id) as total_posts FROM posts'),
          env.DB.prepare('SELECT COUNT(id) as published_posts FROM posts WHERE published = 1 AND is_email = 0'),
          env.DB.prepare('SELECT COUNT(id) as total_users FROM users'),
          env.DB.prepare('SELECT COUNT(id) as inbox_emails FROM posts WHERE is_email = 1'),
          env.DB.prepare('SELECT COUNT(id) as pending_replies FROM posts WHERE is_reply_draft = 1 AND email_metadata LIKE \'%"sent":false%\'')
        ];
        
        // 2. Execute the batch
        const results = await env.DB.batch(statements);

        // 3. Extract the counts from the results of the batch
        // Each result is an object containing a `results` array with one row (the count)
        const counts = {
          total_posts: results[0].results[0].total_posts,
          published_posts: results[1].results[0].published_posts,
          total_users: results[2].results[0].total_users,
          inbox_emails: results[3].results[0].inbox_emails,
          pending_replies: results[4].results[0].pending_replies
        };

        // 4. Check Proxy/External Service Status (Keep separate, as it's an HTTP fetch)
        const proxyCheck = await fetch(`${env.PROXY_URL || 'http://localhost:8080'}/api/health`).then(r => r.ok).catch(() => false);

        // 5. Gather key Settings
        const settingsModel = new SettingsModel(env.DB);
        const federationStatus = await settingsModel.get('federation_enabled').catch(() => 'false');
        const emailStatus = await settingsModel.get('email_enabled').catch(() => 'false');


        return Response.json({
          status: 'ok',
          metrics: {
            // Content Metrics
            total_posts: counts.total_posts,
            published_posts: counts.published_posts,
            total_users: counts.total_users,
            
            // Email/Queue Metrics
            inbox_emails: counts.inbox_emails,
            pending_replies: counts.pending_replies,
            
            // Service Health
            proxy_api_status: proxyCheck ? 'healthy' : 'unhealthy',
            
            // Configuration Status
            federation_enabled: federationStatus === 'true',
            email_enabled: emailStatus === 'true',
            
            // Operational
            worker_uptime_seconds: Math.floor(Date.now() / 1000) - Math.floor(env.WORKER_START_TIME / 1000),
          },
          timestamp: new Date().toISOString()
        });
      } catch (error) {
        logger.error('Failed to generate metrics', { error: error.message });
        return Response.json({ 
          status: 'error', 
          message: 'Error fetching application metrics (Database failure)',
          error: error.message 
        }, { status: 500 });
      }
    }
  },


  // ===== EMAIL ENDPOINTS (Protected) =====
  '/api/email/receive': {
    POST: async (request, env, ctx) => {
      // request.user is already set by middleware!
      try {
        const data = await request.json();
        logger.info('Received email via API', { 
          from: data.from, 
          to: data.to,
          subject: data.subject
        });

        const postModel = new PostModel(env.DB);
        
        if (data.is_blog_post || data.to?.includes('blog@')) {
          const title = data.subject || data.body.split('\n')[0].slice(0, 100);
          
          let content = data.body;
          if (content.includes('\r\n\r\n')) {
            content = content.split('\r\n\r\n').slice(1).join('\r\n\r\n');
          }
          
          const post = await postModel.create({
            title: title,
            content: content,
            slug: postModel.generateSlug(title),
            author_id: 1,
            published: false,
            post_type: 'email_post',
            metadata: JSON.stringify({
              from: data.from,
              to: data.to,
              timestamp: data.timestamp,
              source: 'smtp_bridge',
              federation: data.federation
            })
          });

          logger.info('Created blog post from email', { postId: post.id });

          if (data.federation?.enabled && data.federation?.auto_federate) {
            const fedService = new FederationService(env);
            const domains = await fedService.getConnectedDomains();
            
            if (domains.length > 0) {
              await fedService.queueFederation(post.id, domains.map(d => d.domain));
              logger.info('Queued post for federation', { 
                postId: post.id, 
                domainCount: domains.length 
              });
            }
          }

          return Response.json({
            status: 'success',
            message: 'Email converted to blog post',
            blog_post_id: post.id.toString(),
            blog_url: `https://deadlight.boo/posts/${post.slug}`,
            federation_status: data.federation?.auto_federate ? 'queued' : 'not_requested'
          });

        } else {
          const metadata = JSON.stringify({
            from: data.from,
            to: data.to,
            message_id: `smtp-${Date.now()}`,
            date: new Date().toISOString(),
            source: 'smtp_bridge'
          });

          const result = await env.DB.prepare(`
            INSERT INTO posts (title, content, slug, author_id, created_at, published, is_email, email_metadata)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
          `).bind(
            data.subject || 'No Subject',
            data.body,
            `email-${Date.now()}-${Math.random().toString(36).substring(2, 7)}`,
            1,
            new Date().toISOString(),
            0,
            1,
            metadata
          ).run();

          logger.info('Stored email in inbox', { emailId: result.meta.last_row_id });

          return Response.json({
            status: 'success',
            message: 'Email received and stored',
            email_id: result.meta.last_row_id
          });
        }

      } catch (error) {
        logger.error('Failed to process email', { error: error.message });
        return Response.json({ 
          status: 'error',
          message: 'Failed to process email',
          error: error.message 
        }, { status: 500 });
      }
    }
  },

  '/api/email/fetch': {
    POST: async (request, env, ctx) => {
      try {
        const payload = await request.json();
        let insertedCount = 0;
        
        if (Array.isArray(payload.emails)) {
          for (const email of payload.emails) {
            const metadata = JSON.stringify({
              from: email.from || 'Unknown Sender',
              to: email.to || 'Unknown Recipient',
              message_id: email.message_id || `msg-${Date.now()}`,
              date: email.date || new Date().toISOString()
            });
            
            const existing = await env.DB.prepare(
              'SELECT id FROM posts WHERE is_email = 1 AND title = ? LIMIT 1'
            ).bind(email.subject || 'Untitled Email').first();
            
            if (!existing) {
              await env.DB.prepare(`
                INSERT INTO posts (title, content, slug, author_id, created_at, published, is_email, email_metadata)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
              `).bind(
                email.subject || 'Untitled Email',
                email.body || 'No content',
                `email-${Date.now()}-${Math.random().toString(36).substring(2, 7)}`,
                1,
                email.date || new Date().toISOString(),
                0,
                1,
                metadata
              ).run();
              insertedCount++;
            }
          }
        }
        
        return Response.json({ 
          success: true, 
          inserted: insertedCount,
          total: payload.emails?.length || 0
        });
      } catch (error) {
        logger.error('Error fetching emails', { error: error.message });
        return Response.json({ 
          error: 'Failed to fetch emails', 
          details: error.message 
        }, { status: 500 });
      }
    }
  },

  '/api/email/pending-replies': {
    GET: async (request, env, ctx) => {
      try {
        const repliesResult = await env.DB.prepare(`
          SELECT * FROM posts 
          WHERE is_reply_draft = 1 
          AND email_metadata LIKE '%"sent":false%'
        `).all();
        
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
        
        return Response.json({ 
          success: true, 
          replies: pendingReplies,
          count: pendingReplies.length
        });
      } catch (error) {
        logger.error('Error fetching pending replies', { error: error.message });
        return Response.json({ 
          error: 'Failed to fetch pending replies', 
          details: error.message 
        }, { status: 500 });
      }
    },

    POST: async (request, env, ctx) => {
      try {
        const { id } = await request.json();
        if (!id) {
          return Response.json({ error: 'Reply ID required' }, { status: 400 });
        }
        
        const replyResult = await env.DB.prepare(
          'SELECT * FROM posts WHERE id = ? AND is_reply_draft = 1'
        ).bind(id).first();
        
        if (!replyResult) {
          return Response.json({ error: 'Reply not found' }, { status: 404 });
        }
        
        const metadata = replyResult.email_metadata ? JSON.parse(replyResult.email_metadata) : {};
        metadata.sent = true;
        metadata.date_sent = new Date().toISOString();
        
        await env.DB.prepare(
          'UPDATE posts SET email_metadata = ?, updated_at = ? WHERE id = ?'
        ).bind(
          JSON.stringify(metadata),
          new Date().toISOString(),
          id
        ).run();
        
        logger.info('Marked reply as sent', { replyId: id });
        return Response.json({ 
          success: true, 
          id: id,
          sent_at: metadata.date_sent
        });
      } catch (error) {
        logger.error('Error marking reply as sent', { error: error.message });
        return Response.json({ 
          error: 'Failed to mark reply as sent', 
          details: error.message 
        }, { status: 500 });
      }
    }
  },

  // ===== BLOG ENDPOINTS =====
  '/api/blog/status': {
    GET: async (request, env, ctx) => {
      return Response.json({
        status: 'running',
        version: '5.0.0',
        features: ['email_integration', 'federation', 'proxy_support']
      });
    }
  },

  '/api/blog/posts': {
    GET: async (request, env, ctx) => {
      try {
        const url = new URL(request.url);
        const limit = parseInt(url.searchParams.get('limit') || '10');
        const offset = parseInt(url.searchParams.get('offset') || '0');
        
        const postModel = new PostModel(env.DB);
        const posts = await postModel.list({ 
          limit, 
          offset, 
          published: true 
        });
        
        return Response.json({
          posts: posts,
          total: posts.length,
          limit,
          offset
        });
      } catch (error) {
        logger.error('Error fetching posts', { error: error.message });
        return Response.json({ 
          error: 'Failed to fetch posts' 
        }, { status: 500 });
      }
    }
  }
};