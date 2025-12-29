// src/routes/comments.js 
// Separate comment routes for authenticated users (not just admins)

import { checkAuth } from '../../../lib.deadlight/core/src/auth/password.js';
import { FederationService } from '../services/federation.js';
import { Logger } from '../../../lib.deadlight/core/src/logging/logger.js';
import { renderCommentList, renderAddCommentForm, renderReplyForm } from '../templates/admin/comments.js';

export const commentRoutes = {
  // View comments for a post (public or authenticated depending on config)
  '/comments/:postId': {
    GET: async (request, env, ctx) => {
      const user = await checkAuth(request, env, ctx);
      const config = await env.services.config.getConfig();
      
      // Check if login required to read
      if (config.requireLoginToRead && !user) {
        return Response.redirect(`${new URL(request.url).origin}/login`);
      }
      
      const postId = request.params.postId;
      const fedSvc = new FederationService(
        env,
        env.services.config,
        env.services.proxy,
        env.services.queue
      );
      
      const comments = await fedSvc.getThreadedComments(postId);
      
      return new Response(renderCommentList(comments, postId, user, config), {
        headers: { 'Content-Type': 'text/html' }
      });
    }
  },

  // Add comment (requires authentication, not admin)
  '/comments/add/:postId': {
    GET: async (request, env, ctx) => {
      const user = await checkAuth(request, env, ctx);
      if (!user) {
        return Response.redirect(`${new URL(request.url).origin}/login`);
      }
      
      const postId = request.params.postId;
      const config = await env.services.config.getConfig();
      
      return new Response(renderAddCommentForm(postId, user, config), {
        headers: { 'Content-Type': 'text/html' }
      });
    },
    
    POST: async (request, env, ctx) => {
      const logger = new Logger({ context: 'comments' });
      const user = await checkAuth(request, env, ctx);
      
      if (!user) {
        return Response.redirect(`${new URL(request.url).origin}/login`);
      }
      
      const postId = request.params.postId;
      const formData = await request.formData();
      const content = formData.get('content');

      if (!content) {
        return new Response('Content is required', { status: 400 });
      }

      try {
        // Get the parent post
        const post = await env.DB.prepare(
          'SELECT id, federation_metadata FROM posts WHERE id = ?'
        ).bind(postId).first();
        
        if (!post) {
          return new Response('Post not found', { status: 404 });
        }

        const meta = post.federation_metadata ? JSON.parse(post.federation_metadata) : {};
        const sourceUrl = meta.source_url || `${env.SITE_URL}/post/${postId}`;
        
        // Generate comment metadata
        const commentMeta = JSON.stringify({
          author: user.username,
          source_domain: new URL(env.SITE_URL || 'https://deadlight.boo').hostname,
          created_at: new Date().toISOString()
        });
        
        const slug = `comment-${Date.now()}-${Math.random().toString(36).substring(2, 7)}`;
        
        // Create local comment WITH metadata
        const insertResult = await env.DB.prepare(`
          INSERT INTO posts (
            title, content, slug, author_id, 
            created_at, published, post_type, 
            parent_id, thread_id, federation_metadata
          )
          VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        `).bind(
          `Comment on ${sourceUrl}`,
          content,
          slug,
          user.id,
          new Date().toISOString(),
          1,
          'comment',
          postId,
          postId,
          commentMeta
        ).run();

        const commentId = insertResult.meta.last_row_id;

        // Federate if there are connected domains
        const fedSvc = new FederationService(
          env,
          env.services.config,
          env.services.proxy,
          env.services.queue
        );
        
        const domains = await fedSvc.getConnectedDomains();
        
        if (domains.length > 0) {
          const targetDomains = domains.map(d => d.domain);
          
          const federatedComment = {
            id: commentId,
            content,
            author: user.username,
            published_at: new Date().toISOString(),
            parent_url: sourceUrl,
            source_url: `${env.SITE_URL}/post/${postId}#comment-${commentId}`
          };
          
          await fedSvc.publishComment(federatedComment, targetDomains);
        }

        logger.info('Comment created', { commentId, postId, userId: user.id });
        
        return Response.redirect(
          `${new URL(request.url).origin}/comments/${postId}`
        );
      } catch (error) {
        logger.error('Error creating comment', { error: error.message, postId, userId: user.id });
        return new Response('Failed to create comment', { status: 500 });
      }
    }
  },

  // Reply to comment (requires authentication)
  '/comments/reply/:id': {
    GET: async (request, env, ctx) => {
      const user = await checkAuth(request, env, ctx);
      if (!user) {
        return Response.redirect(`${new URL(request.url).origin}/login`);
      }
      
      const commentId = request.params.id;
      const comment = await env.DB.prepare(`
        SELECT p.*, u.username as author_username
        FROM posts p
        LEFT JOIN users u ON p.author_id = u.id
        WHERE p.id = ? AND p.post_type = 'comment'
      `).bind(commentId).first();
      
      if (!comment) {
        return new Response('Comment not found', { status: 404 });
      }
      
      const config = await env.services.config.getConfig();
      
      return new Response(renderReplyForm(comment, user, config), {
        headers: { 'Content-Type': 'text/html' }
      });
    },
    
    POST: async (request, env, ctx) => {
      const logger = new Logger({ context: 'comments' });
      const user = await checkAuth(request, env, ctx);
      
      if (!user) {
        return Response.redirect(`${new URL(request.url).origin}/login`);
      }
      
      const commentId = request.params.id;
      const formData = await request.formData();
      const content = formData.get('content');

      if (!content) {
        return new Response('Content is required', { status: 400 });
      }

      try {
        const parentComment = await env.DB.prepare(`
          SELECT p.*, u.username as author_username
          FROM posts p
          LEFT JOIN users u ON p.author_id = u.id
          WHERE p.id = ? AND p.post_type = 'comment'
        `).bind(commentId).first();
        
        if (!parentComment) {
          return new Response('Parent comment not found', { status: 404 });
        }

        const fedSvc = new FederationService(
          env,
          env.services.config,
          env.services.proxy,
          env.services.queue
        );

        const post = await env.DB.prepare(
          'SELECT id, federation_metadata FROM posts WHERE id = ?'
        ).bind(parentComment.parent_id || parentComment.thread_id).first();
        
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

        logger.info('Reply created', { replyId: insertResult.meta.last_row_id, parentId: commentId, userId: user.id });

        return Response.redirect(
          `${new URL(request.url).origin}/comments/${parentComment.parent_id || parentComment.thread_id}`
        );
      } catch (error) {
        logger.error('Error creating reply', { error: error.message, commentId, userId: user.id });
        return new Response('Failed to create reply', { status: 500 });
      }
    }
  },

  // Delete comment (requires ownership OR admin)
  '/comments/delete/:id': {
    GET: async (request, env, ctx) => {
      const logger = new Logger({ context: 'comments' });
      const user = await checkAuth(request, env, ctx);
      
      if (!user) {
        return Response.redirect(`${new URL(request.url).origin}/login`);
      }
      
      const commentId = request.params.id;

      try {
        const comment = await env.DB.prepare(`
          SELECT p.*, u.username as author_username, p.parent_id AS parent_post_id
          FROM posts p
          LEFT JOIN users u ON p.author_id = u.id
          WHERE p.id = ? AND p.post_type = 'comment'
        `).bind(commentId).first();
        
        if (!comment) {
          return new Response('Comment not found', { status: 404 });
        }

        // Check permissions: only author or admin can delete
        if (user.role !== 'admin' && user.id !== comment.author_id) {
          return new Response('Unauthorized', { status: 403 });
        }

        // Delete comment
        await env.DB.prepare('DELETE FROM posts WHERE id = ?').bind(commentId).run();
        
        logger.info('Comment deleted', { 
          commentId, 
          userId: user.id,
          parentId: comment.parent_post_id 
        });

        // Redirect back to comment list
        return Response.redirect(
          `${new URL(request.url).origin}/comments/${comment.parent_post_id || comment.thread_id}`,
          303
        );
        
      } catch (error) {
        logger.error('Failed to delete comment', { 
          commentId, 
          error: error.message 
        });
        return new Response('Failed to delete comment', { status: 500 });
      }
    }
  }
};
