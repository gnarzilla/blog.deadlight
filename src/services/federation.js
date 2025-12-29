// src/services/federation.js
import { Logger } from '../../../lib.deadlight/core/src/logging/logger.js';
import { hashPassword, verifyPassword } from '../../../lib.deadlight/core/src/auth/password.js';
import { EmailTransport } from './federation-transport.js';

export class FederationService {
  constructor(env, configService, proxyService, queueService) {
    this.env = env;
    this.db = env.DB;
    this.logger = new Logger({ context: 'federation' });
    this.config = configService;
    this.proxy = proxyService;
    this.queue = queueService;
    this.transport = new EmailTransport(this.proxy);   // can be swapped later
  }

  /* --------------------------------------------------------------
     OUTBOUND – called by routes when a post/comment is published
     -------------------------------------------------------------- */
  async publishPost(post, targetDomains) {
    const domain = await this._domain();
    const siteUrl = await this._siteUrl();
    
    const payload = {
      post,
      federationType: 'new_post',
      instanceUrl: siteUrl,
      domain: domain,
    };
    const signed = await this._sign(payload);
    await this.queue.queueItem('federation', { ...signed, targetDomains });
  }

  async publishComment(comment, targetDomains) {
    const domain = await this._domain();
    const siteUrl = await this._siteUrl();
    
    const payload = {
      comment,
      federationType: 'comment',
      instanceUrl: siteUrl,
      domain: domain,
    };
    const signed = await this._sign(payload);
    await this.queue.queueItem('federation', { ...signed, targetDomains });
  }

  async sendDeleteComment(commentId, targetDomains) {
    const domain = await this._domain();
    const siteUrl = await this._siteUrl();
    
    // Fetch the comment to get metadata about it
    const comment = await this.db.prepare(`
      SELECT id, parent_id, thread_id, federation_metadata
      FROM posts
      WHERE id = ? AND post_type = 'comment'
    `).bind(commentId).first();

    if (!comment) {
      this.logger.warn('Comment not found for deletion federation', { commentId });
      return;
    }

    const meta = comment.federation_metadata ? JSON.parse(comment.federation_metadata) : {};
    
    const payload = {
      commentId,
      parentId: comment.parent_id || comment.thread_id,
      sourceUrl: meta.source_url || `${siteUrl}/post/${comment.parent_id}#comment-${commentId}`,
      federationType: 'delete_comment',
      instanceUrl: siteUrl,
      domain: domain,
    };
    
    const signed = await this._sign(payload);
    await this.queue.queueItem('federation', { ...signed, targetDomains });
    
    this.logger.info('Delete comment queued for federation', { 
      commentId, 
      targetDomains: targetDomains.length 
    });
  }

  async sendDeletePost(postId, targetDomains) {
    const domain = await this._domain();
    const siteUrl = await this._siteUrl();
    
    const post = await this.db.prepare(`
      SELECT id, slug, federation_metadata
      FROM posts
      WHERE id = ?
    `).bind(postId).first();

    if (!post) {
      this.logger.warn('Post not found for deletion federation', { postId });
      return;
    }

    const meta = post.federation_metadata ? JSON.parse(post.federation_metadata) : {};
    
    const payload = {
      postId,
      slug: post.slug,
      sourceUrl: meta.source_url || `${siteUrl}/post/${post.slug}`,
      federationType: 'delete_post',
      instanceUrl: siteUrl,
      domain: domain,
    };
    
    const signed = await this._sign(payload);
    await this.queue.queueItem('federation', { ...signed, targetDomains });
    
    this.logger.info('Delete post queued for federation', { 
      postId, 
      targetDomains: targetDomains.length 
    });
  }

  /* --------------------------------------------------------------
     PROCESSING – called by QueueService (see _processFederation)
     -------------------------------------------------------------- */
  async sendViaTransport(item) {
    // item is the JSON that was stored in federation_metadata
    return await this.transport.send(item);
  }

  /* --------------------------------------------------------------
     INBOUND – called from inbox endpoint (POST /inbox)
     -------------------------------------------------------------- */
  async handleIncoming(emailData) {
    const payload = JSON.parse(emailData.body);
    if (!await this._verify(payload)) {
      throw new Error('Invalid federation signature');
    }

    switch (payload.federation_type) {
      case 'new_post':
        return await this._handleNewPost(payload.payload, emailData);
      case 'comment':
        return await this._handleComment(payload.payload, emailData);
      case 'delete_comment':
        return await this._handleDeleteComment(payload.payload, emailData);
      case 'delete_post':
        return await this._handleDeletePost(payload.payload, emailData);
      case 'discovery':
        return await this._handleDiscovery(payload.payload, emailData.from);
      default:
        throw new Error(`Unknown type ${payload.federation_type}`);
    }
  }

  /* --------------------------------------------------------------
     TRUST & CRYPTO
     -------------------------------------------------------------- */
  async establishTrust(domain, publicKey, level = 'verified') {
    await this.db.prepare(`
      INSERT OR REPLACE INTO federation_trust
        (domain, public_key, trust_level, last_seen)
      VALUES (?, ?, ?, ?)
    `).bind(domain, publicKey, level, new Date().toISOString()).run();
  }

  async _sign(data) {
    const payloadStr = JSON.stringify(data, Object.keys(data).sort());
    const privateKey = await this._privateKey();
    const { hash } = await hashPassword(payloadStr, privateKey);
    return { ...data, signature: hash };
  }

  async _verify(payload) {
    const { signature, ...rest } = payload;
    const str = JSON.stringify(rest, Object.keys(rest).sort());
    const domain = payload.payload?.origin?.domain ?? payload.payload?.domain;
    const trust = await this.db.prepare('SELECT public_key FROM federation_trust WHERE domain = ?')
      .bind(domain).first();
    if (!trust) return false;
    return await verifyPassword(str, signature, trust.public_key);
  }

  async _privateKey() {
    // Try env first (for testing), then config service
    if (this.env.FEDERATION_PRIVATE_KEY) {
      return this.env.FEDERATION_PRIVATE_KEY;
    }
    
    const configData = await this.config.getConfig();
    if (configData.federationPrivateKey) {
      return configData.federationPrivateKey;
    }
    
    throw new Error('Federation private key not configured. Run: scripts/gen-fed-keys.sh');
  }
  
  async _publicKey() {
    // For responses to /.well-known/deadlight
    const configData = await this.config.getConfig();
    if (configData.federationPublicKey) {
      return configData.federationPublicKey;
    }
    
    throw new Error('Federation public key not configured');
  }

  async getPublicKey() {
    // For testing/dev, derive from private key (symmetric for now - note: not secure for production; upgrade to asymmetric later)
    const privateKey = await this._privateKey();
    return privateKey;  // Returns 'dev-private-key' locally; use env.FEDERATION_PRIVATE_KEY in production
  }

  async _siteUrl() {
    // Use env variable first, fall back to config
    if (this.env.SITE_URL) return this.env.SITE_URL;
    
    const configData = await this.config.getConfig();
    return configData.siteUrl || 'https://deadlight.boo';
  }

  async _domain() {
    // Now async since _siteUrl is async
    const url = await this._siteUrl();
    return new URL(url).hostname;
  }
  
  /* --------------------------------------------------------------
     INBOUND HANDLERS
     -------------------------------------------------------------- */
  async _handleNewPost(postData, email, sourceDomain) {
    try {
      // Check for duplicates using federation metadata
      const existing = await this.db.prepare(`
        SELECT id FROM posts 
        WHERE json_extract(federation_metadata, '$.source_id') = ?
          AND json_extract(federation_metadata, '$.source_domain') = ?
      `).bind(postData.id?.toString() || 'unknown', sourceDomain).first();

      if (existing) {
        this.logger.info('Duplicate federated post ignored', { 
          sourceId: postData.id, 
          sourceDomain 
        });
        return { status: 'duplicate', postId: existing.id };
      }

      // Create federated post
      const federationMeta = JSON.stringify({
        source_id: postData.id || Date.now(),
        source_domain: sourceDomain,
        source_url: postData.source_url || postData.instanceUrl,
        received_at: new Date().toISOString(),
        author: postData.author || email.from,
        verified: !!postData.signature
      });

      const slug = `federated-${sourceDomain.replace(/\./g, '-')}-${postData.id || Date.now()}`;
      
      const result = await this.db.prepare(`
        INSERT INTO posts (
          title, slug, content, author_id, 
          post_type, federation_metadata,
          moderation_status, published, created_at
        ) VALUES (?, ?, ?, 1, 'federated', ?, 'pending', 0, ?)
      `).bind(
        postData.title || 'Untitled Federated Post',
        slug,
        postData.content || '',
        federationMeta,
        new Date().toISOString()
      ).run();

      this.logger.info('Federated post received', { 
        sourceDomain, 
        slug,
        postId: result.meta?.last_row_id 
      });
      
      return { 
        status: 'queued_for_moderation', 
        slug,
        postId: result.meta?.last_row_id 
      };
    } catch (error) {
      this.logger.error('Failed to handle federated post', { 
        error: error.message,
        sourceDomain 
      });
      throw error;
    }
  }

  async _handleComment(commentData, email, sourceDomain) {
    try {
      // Find the parent post
      const parentId = commentData.parent_id || commentData.thread_id;
      
      if (!parentId) {
        throw new Error('Comment missing parent_id');
      }

      const parent = await this.db.prepare(
        'SELECT id, comments_enabled FROM posts WHERE id = ?'
      ).bind(parentId).first();

      if (!parent) {
        throw new Error(`Parent post ${parentId} not found`);
      }

      if (!parent.comments_enabled) {
        throw new Error('Comments disabled on parent post');
      }

      // Check for duplicate
      const existing = await this.db.prepare(`
        SELECT id FROM posts 
        WHERE json_extract(federation_metadata, '$.source_id') = ?
          AND json_extract(federation_metadata, '$.source_domain') = ?
      `).bind(commentData.id?.toString() || 'unknown', sourceDomain).first();

      if (existing) {
        return { status: 'duplicate', commentId: existing.id };
      }

      // Create federated comment
      const federationMeta = JSON.stringify({
        source_id: commentData.id || Date.now(),
        source_domain: sourceDomain,
        source_url: commentData.source_url,
        received_at: new Date().toISOString(),
        author: commentData.author || email.from,
        verified: !!commentData.signature
      });

      const slug = `comment-${sourceDomain.replace(/\./g, '-')}-${commentData.id || Date.now()}`;

      const result = await this.db.prepare(`
        INSERT INTO posts (
          title, slug, content, author_id,
          post_type, parent_id, thread_id,
          federation_metadata, moderation_status,
          published, created_at
        ) VALUES (?, ?, ?, 1, 'comment', ?, ?, ?, 'pending', 0, ?)
      `).bind(
        `Comment from ${sourceDomain}`,
        slug,
        commentData.content || '',
        parentId,
        parentId,
        federationMeta,
        new Date().toISOString()
      ).run();

      this.logger.info('Federated comment received', { 
        sourceDomain, 
        parentId,
        commentId: result.meta?.last_row_id 
      });

      return { 
        status: 'queued_for_moderation', 
        slug,
        commentId: result.meta?.last_row_id 
      };
    } catch (error) {
      this.logger.error('Failed to handle federated comment', { 
        error: error.message,
        sourceDomain 
      });
      throw error;
    }
  }

  async _handleDeleteComment(deleteData, email, sourceDomain) {
    try {
      const { commentId, sourceUrl } = deleteData;

      // Find the comment by source metadata
      const comment = await this.db.prepare(`
        SELECT id FROM posts
        WHERE json_extract(federation_metadata, '$.source_id') = ?
          AND json_extract(federation_metadata, '$.source_domain') = ?
          AND post_type = 'comment'
      `).bind(commentId?.toString() || 'unknown', sourceDomain).first();

      if (!comment) {
        this.logger.warn('Comment not found for deletion', { commentId, sourceDomain });
        return { status: 'not_found', commentId };
      }

      // Delete the comment
      await this.db.prepare('DELETE FROM posts WHERE id = ?').bind(comment.id).run();

      this.logger.info('Federated comment deleted', { 
        localId: comment.id,
        sourceId: commentId,
        sourceDomain 
      });

      return { status: 'deleted', commentId: comment.id };
    } catch (error) {
      this.logger.error('Failed to handle comment deletion', { 
        error: error.message,
        sourceDomain 
      });
      throw error;
    }
  }

  async _handleDeletePost(deleteData, email, sourceDomain) {
    try {
      const { postId, sourceUrl } = deleteData;

      // Find the post by source metadata
      const post = await this.db.prepare(`
        SELECT id FROM posts
        WHERE json_extract(federation_metadata, '$.source_id') = ?
          AND json_extract(federation_metadata, '$.source_domain') = ?
          AND post_type = 'federated'
      `).bind(postId?.toString() || 'unknown', sourceDomain).first();

      if (!post) {
        this.logger.warn('Post not found for deletion', { postId, sourceDomain });
        return { status: 'not_found', postId };
      }

      // Delete the post (cascade should handle comments)
      await this.db.prepare('DELETE FROM posts WHERE id = ?').bind(post.id).run();

      this.logger.info('Federated post deleted', { 
        localId: post.id,
        sourceId: postId,
        sourceDomain 
      });

      return { status: 'deleted', postId: post.id };
    } catch (error) {
      this.logger.error('Failed to handle post deletion', { 
        error: error.message,
        sourceDomain 
      });
      throw error;
    }
  }

  async _handleDiscovery(discoveryData, sourceDomain) {
    try {
      await this.establishTrust(
        sourceDomain,
        discoveryData.public_key || '',
        'unverified'
      );

      this.logger.info('Discovery announcement received', { sourceDomain });
      return { status: 'trust_established', domain: sourceDomain };
    } catch (error) {
      this.logger.error('Failed to handle discovery', { 
        error: error.message,
        sourceDomain 
      });
      throw error;
    }
  }

  /* --------------------------------------------------------------
     METHOD FOR DOMAIN DISCOVERY
     -------------------------------------------------------------- */
  async discoverAndTrust(domain) {
    try {
      // Normalize domain to URL
      let url = domain;
      if (!url.startsWith('http')) url = 'https://' + url;
      url = new URL(url);
      const discoveryUrl = `${url.origin}/.well-known/deadlight`;

      // Fetch remote discovery endpoint
      const response = await fetch(discoveryUrl, {
        headers: {
          'User-Agent': 'Deadlight-Federation/1.0',
          'Accept': 'application/json',
        },
      });

      if (!response.ok) {
        throw new Error(`Discovery failed with status: ${response.status}`);
      }

      const data = await response.json();

      // Validate response
      if (!data.public_key || !data.domain) {
        throw new Error('Invalid discovery response: missing public_key or domain');
      }

      // Establish trust (unverified initially)
      await this.establishTrust(data.domain, data.public_key, 'unverified');

      // Log and return
      this.logger.info('Domain discovered and trust established', { domain: data.domain });
      return {
        success: true,
        domain: data.domain,
        public_key: data.public_key,
        capabilities: data.capabilities,
        version: data.version,
        software: data.software,
      };
    } catch (error) {
      this.logger.error('Domain discovery failed', { domain, error: error.message });
      throw error;
    }
  }

  async getConnectedDomains() {
    try {
      const result = await this.db.prepare(`
        SELECT domain, trust_level, last_seen
        FROM federation_trust
        WHERE trust_level IN ('verified', 'unverified')
        ORDER BY last_seen DESC
      `).all();

      return result.results || [];
    } catch (err) {
      console.error('Failed to fetch connected domains:', err);
      return [];
    }
  }

  async getThreadedComments(postId, limit = 50) {
    const res = await this.db.prepare(`
      SELECT 
        p.id, 
        p.content, 
        p.author_id, 
        p.created_at, 
        p.parent_id,
        p.thread_id,
        p.federation_metadata,
        u.username
      FROM posts p
      LEFT JOIN users u ON p.author_id = u.id
      WHERE p.post_type = 'comment' 
        AND (p.parent_id = ? OR p.thread_id = ?)
      ORDER BY p.created_at ASC
      LIMIT ?
    `).bind(postId, postId, limit).all();

    // Build threaded structure
    const comments = (res.results || []).map(row => {
      const meta = row.federation_metadata ? JSON.parse(row.federation_metadata) : {};
      
      // ✅ Use username from join, fallback to metadata, then Unknown
      const author = row.username || meta.author || 'Unknown';
      
      return {
        id: row.id,
        content: row.content,
        author: author,
        author_id: row.author_id,
        parent_id: row.parent_id,
        thread_id: row.thread_id,
        source_domain: meta.source_domain,
        source_url: meta.source_url,
        published_at: row.created_at,
        level: 0  // Will be calculated below
      };
    });

    // Calculate nesting levels for display
    const commentMap = new Map(comments.map(c => [c.id, c]));
    comments.forEach(comment => {
      if (comment.parent_id && comment.parent_id !== postId) {
        const parent = commentMap.get(comment.parent_id);
        if (parent) {
          comment.level = parent.level + 1;
        }
      }
    });

    return comments;
  }

  /* --------------------------------------------------------------
     SYNC & BULK OPERATIONS
     -------------------------------------------------------------- */
  async syncNetwork() {
    try {
      const domains = await this.getConnectedDomains();
      let imported = 0;
      const newPosts = [];

      for (const domain of domains) {
        try {
          // Fetch recent posts from federated instance
          const response = await fetch(`https://${domain.domain}/api/federation/outbox`, {
            headers: {
              'User-Agent': 'Deadlight-Federation/1.0',
              'Accept': 'application/json',
            },
          });

          if (!response.ok) continue;

          const data = await response.json();
          const posts = data.orderedItems || [];

          for (const item of posts) {
            // Check if we already have this post
            const existing = await this.db.prepare(`
              SELECT id FROM posts 
              WHERE json_extract(federation_metadata, '$.source_id') = ?
                AND json_extract(federation_metadata, '$.source_domain') = ?
            `).bind(item.object?.id || item.id, domain.domain).first();

            if (existing) continue;

            // Import the post
            const result = await this._handleNewPost(
              {
                id: item.object?.id || item.id,
                title: item.object?.name || 'Untitled',
                content: item.object?.content || '',
                author: item.actor,
                source_url: item.object?.id,
              },
              { from: domain.domain },
              domain.domain
            );

            if (result.status !== 'duplicate') {
              imported++;
              newPosts.push(result);
            }
          }
        } catch (error) {
          this.logger.error('Failed to sync with domain', { 
            domain: domain.domain, 
            error: error.message 
          });
        }
      }

      this.logger.info('Network sync completed', { 
        domains: domains.length, 
        imported 
      });

      return { imported, domains: domains.length, newPosts };
    } catch (error) {
      this.logger.error('Network sync failed', { error: error.message });
      throw error;
    }
  }
}