import { renderPostList } from '../templates/blog/list.js';
import { renderSinglePost } from '../templates/blog/single.js';
import { checkAuth } from '../../../lib.deadlight/core/src/auth/password.js';
import { FederationService } from '../services/federation.js';

export const blogRoutes = {
  '/': {
    GET: async (request, env) => {
      try {
        const user = await checkAuth(request, env);
        const { configService } = await import('../services/config.js');
        const config = await configService.getConfig(env.DB);

        const postsPerPage = parseInt(config.postsPerPage) || 10;
        const url = new URL(request.url);
        const page = parseInt(url.searchParams.get('page') || '1');
        const offset = (page - 1) * postsPerPage;

        const countResult = await env.DB.prepare(`
          SELECT COUNT(*) as total 
          FROM posts 
          WHERE published = 1 AND post_type != 'comment'
        `).first();
        const totalPosts = countResult.total;
        const totalPages = Math.ceil(totalPosts / postsPerPage);

        const result = await env.DB.prepare(`
          SELECT posts.*, users.username as author_username 
          FROM posts 
          JOIN users ON posts.author_id = users.id 
          WHERE posts.published = 1 AND posts.post_type != 'comment'
          ORDER BY posts.created_at DESC
          LIMIT ? OFFSET ?
        `).bind(postsPerPage, offset).all();

        const paginationData = {
          currentPage: page,
          totalPages,
          totalPosts,
          postsPerPage,
          hasPrevious: page > 1,
          hasNext: page < totalPages,
          previousPage: page - 1,
          nextPage: page + 1
        };

        return new Response(
          renderPostList(result.results, user, paginationData, config),
          { headers: { 'Content-Type': 'text/html' } }
        );
      } catch (error) {
        console.error('Blog route error:', error);
        return new Response('Internal server error', { status: 500 });
      }
    }
  },

  '/post/:slug': {
    GET: async (request, env) => {
      try {
        const user = await checkAuth(request, env);
        const { configService } = await import('../services/config.js');
        const config = await configService.getConfig(env.DB);

        const slug = request.params.slug;
        let post = await env.DB.prepare(`
          SELECT posts.*, users.username as author_username
          FROM posts 
          LEFT JOIN users ON posts.author_id = users.id
          WHERE posts.slug = ? AND posts.published = 1 AND posts.post_type != 'comment'
        `).bind(slug).first();

        if (!post && !isNaN(slug)) {
          post = await env.DB.prepare(`
            SELECT posts.*, users.username as author_username
            FROM posts 
            LEFT JOIN users ON posts.author_id = users.id
            WHERE posts.id = ? AND posts.published = 1 AND posts.post_type != 'comment'
          `).bind(parseInt(slug)).first();
        }

        if (!post) {
          return new Response('Post not found', { status: 404 });
        }

        let navigation = null;
        try {
          const prevPost = await env.DB.prepare(`
            SELECT id, title, slug
            FROM posts 
            WHERE created_at < ? AND published = 1 AND post_type != 'comment' AND (is_email = 0 OR is_email IS NULL)
            ORDER BY created_at DESC 
            LIMIT 1
          `).bind(post.created_at).first();

          const nextPost = await env.DB.prepare(`
            SELECT id, title, slug
            FROM posts 
            WHERE created_at > ? AND published = 1 AND post_type != 'comment' AND (is_email = 0 OR is_email IS NULL)
            ORDER BY created_at ASC 
            LIMIT 1
          `).bind(post.created_at).first();

          if (prevPost || nextPost) {
            navigation = {
              prev_id: prevPost ? (prevPost.slug || prevPost.id) : null,
              prev_title: prevPost ? prevPost.title : null,
              next_id: nextPost ? (nextPost.slug || nextPost.id) : null,
              next_title: nextPost ? nextPost.title : null
            };
          }
        } catch (navError) {
          console.error('Navigation query error:', navError);
        }

        const fedSvc = new FederationService(env);
        const comments = await fedSvc.getThreadedComments(post.id);

        return new Response(renderSinglePost(post, user, navigation, config, comments), {
          headers: { 'Content-Type': 'text/html' }
        });
      } catch (error) {
        console.error('Post page error:', error);
        return new Response('Internal server error', { status: 500 });
      }
    }
  },
  '/post/:slug/comment': {
    POST: async (request, env, ctx) => {
      const currentUser = await checkAuth(request, env);
      if (!currentUser) {
        return Response.redirect('/login', 302);
      }
      
      const slug = request.params.slug;
      const formData = await request.formData();
      const content = formData.get('content');
      
      if (!content || content.trim().length === 0) {
        return Response.redirect(`/post/${slug}`, 302);
      }
      
      const postModel = new PostModel(env.DB);
      const parentPost = await postModel.getBySlug(slug);
      
      if (!parentPost || !parentPost.comments_enabled) {
        return new Response('Comments disabled', { status: 403 });
      }
      
      // Create comment
      await env.DB.prepare(`
        INSERT INTO posts (
          title, content, slug, author_id, published, 
          parent_id, post_type, created_at
        ) VALUES (?, ?, ?, ?, 1, ?, 'comment', CURRENT_TIMESTAMP)
      `).bind(
        `Comment on ${parentPost.title}`,
        content,
        `comment-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`,
        currentUser.id,
        parentPost.id
      ).run();
      
      return Response.redirect(`/post/${slug}#comments`, 302);
    }
  }
};