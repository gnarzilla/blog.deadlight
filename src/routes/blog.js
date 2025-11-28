import { renderPostList } from '../templates/blog/list.js';
import { renderSinglePost } from '../templates/blog/single.js';
import { checkAuth } from '../../../lib.deadlight/core/src/auth/password.js';
import { FederationService } from '../services/federation.js';
import { ConfigService } from '../services/config.js';
import { renderAnalyticsTemplate } from '../templates/admin/analytics.js';

export const blogRoutes = {
  '/': {
    GET: async (request, env) => {
      try {
        const user = await checkAuth(request, env);
        const config = await env.services.config.getConfig();

        const postsPerPage = parseInt(config.postsPerPage) || 10;
        const url = new URL(request.url);
        const page = parseInt(url.searchParams.get('page') || '1');
        const sort = url.searchParams.get('sort') || 'newest'; // Add sort parameter
        const offset = (page - 1) * postsPerPage;

        // Build ORDER BY based on sort parameter
        let orderByClause;
        switch(sort) {
          case 'oldest':
            orderByClause = 'posts.created_at ASC';
            break;
          case 'karma':
            orderByClause = `(
              SELECT COUNT(*) FROM post_reactions WHERE post_id = posts.id AND reaction = 'like'
            ) - (
              SELECT COUNT(*) FROM post_reactions WHERE post_id = posts.id AND reaction = 'dislike'
            ) DESC`;
            break;
          case 'discussed':
            orderByClause = `(
              SELECT COUNT(*) FROM posts c WHERE c.parent_id = posts.id AND c.post_type = 'comment'
            ) DESC`;
            break;
          case 'newest':
          default:
            orderByClause = 'posts.created_at DESC';
        }

        const countResult = await env.DB.prepare(`
          SELECT COUNT(*) as total 
          FROM posts 
          WHERE published = 1 
            AND post_type != 'comment'
            AND visibility = 'public'
        `).first();
        const totalPosts = countResult.total;
        const totalPages = Math.ceil(totalPosts / postsPerPage);

        const result = await env.DB.prepare(`
          SELECT posts.*, users.username as author_username,
            posts.content,  -- Make sure content is included for excerpt extraction
            (
              SELECT COUNT(*) FROM post_reactions WHERE post_id = posts.id AND reaction = 'like'
            ) - (
              SELECT COUNT(*) FROM post_reactions WHERE post_id = posts.id AND reaction = 'dislike'
            ) AS karma
          FROM posts 
          JOIN users ON posts.author_id = users.id 
          WHERE posts.published = 1 
            AND posts.post_type != 'comment'
            AND posts.visibility = 'public'
          ORDER BY ${orderByClause}
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
          nextPage: page + 1,
          currentSort: sort 
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
        const config = await env.services.config.getConfig();
        const slug = request.params.slug;

        // Build the visibility condition based on authentication
        let visibilityCondition = "posts.visibility = 'public'";
        let visibilityParams = [];
        
        if (user) {
          if (user.role === 'admin') {
            visibilityCondition = "(posts.visibility = 'public' OR posts.visibility = 'private')";
          } else {
            visibilityCondition = "(posts.visibility = 'public' OR (posts.visibility = 'private' AND posts.author_id = ?))";
            visibilityParams = [user.id];
          }
        }

        // Query by slug - INCLUDE KARMA
        let post = await env.DB.prepare(`
          SELECT posts.*, users.username as author_username,
            (
              SELECT COUNT(*) FROM post_reactions WHERE post_id = posts.id AND reaction = 'like'
            ) - (
              SELECT COUNT(*) FROM post_reactions WHERE post_id = posts.id AND reaction = 'dislike'
            ) AS karma
          FROM posts 
          LEFT JOIN users ON posts.author_id = users.id
          WHERE posts.slug = ? 
            AND posts.published = 1 
            AND posts.post_type != 'comment'
            AND ${visibilityCondition}
        `).bind(slug, ...visibilityParams).first();

        // Fallback to ID if slug didn't work and it's numeric - INCLUDE KARMA
        if (!post && !isNaN(slug)) {
          post = await env.DB.prepare(`
            SELECT posts.*, users.username as author_username,
              (
                SELECT COUNT(*) FROM post_reactions WHERE post_id = posts.id AND reaction = 'like'
              ) - (
                SELECT COUNT(*) FROM post_reactions WHERE post_id = posts.id AND reaction = 'dislike'
              ) AS karma
            FROM posts 
            LEFT JOIN users ON posts.author_id = users.id
            WHERE posts.id = ? 
              AND posts.published = 1 
              AND posts.post_type != 'comment'
              AND ${visibilityCondition}
          `).bind(parseInt(slug), ...visibilityParams).first();
        }

        if (!post) {
          return new Response('Post not found', { status: 404 });
        }

        // For navigation, only show posts the user can see
        const prevPost = await env.DB.prepare(`
          SELECT id, title, slug
          FROM posts 
          WHERE created_at < ? 
            AND published = 1 
            AND post_type != 'comment' 
            AND (is_email = 0 OR is_email IS NULL)
            AND ${visibilityCondition}
          ORDER BY created_at DESC 
          LIMIT 1
        `).bind(post.created_at, ...visibilityParams).first();

        const nextPost = await env.DB.prepare(`
          SELECT id, title, slug
          FROM posts 
          WHERE created_at > ? 
            AND published = 1 
            AND post_type != 'comment' 
            AND (is_email = 0 OR is_email IS NULL)
            AND ${visibilityCondition}
          ORDER BY created_at ASC 
          LIMIT 1
        `).bind(post.created_at, ...visibilityParams).first();

        let navigation = null;
        if (prevPost || nextPost) {
          navigation = {
            prev_id: prevPost ? (prevPost.slug || prevPost.id) : null,
            prev_title: prevPost ? prevPost.title : null,
            next_id: nextPost ? (nextPost.slug || nextPost.id) : null,
            next_title: nextPost ? nextPost.title : null
          };
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
  },

  
  '/analytics': {
    GET: async (request, env, ctx) => {
      const config = await env.services.config.getConfig();
      const timeRange = request.query.range || '7d'; // Get from query param

      let timeClause;
      switch(timeRange) {
        case '24h':
          timeClause = "datetime('now', '-24 hours')";
          break;
        case '7d':
          timeClause = "datetime('now', '-7 days')";
          break;
        case '30d':
          timeClause = "datetime('now', '-30 days')";
          break;
        default:
          timeClause = "datetime('now', '-7 days')";
      }

      // Then use in your queries:
      // WHERE timestamp >= ${timeClause}
      
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
          WHERE timestamp >= datetime('now', '-7 days')
        `).first();
        
        // Get hourly traffic (last 24 hours)
        const hourlyTraffic = await env.DB.prepare(`
          SELECT 
            hour_bucket as hour,
            COUNT(*) as requests,
            COUNT(DISTINCT ip) as unique_visitors
          FROM analytics
          WHERE timestamp >= datetime('now', '-24 hours')
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
          WHERE timestamp >= datetime('now', '-7 days')
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
          WHERE timestamp >= datetime('now', '-7 days') 
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
        
        // Fill in missing hours for the chart
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