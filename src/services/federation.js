import { ProxyService } from './proxy.js';
import { Logger } from '../../../lib.deadlight/core/src/logging/logger.js';
import { hashPassword, verifyPassword } from '../../../lib.deadlight/core/src/auth/password.js';

// Transport abstraction for federation protocols
class Transport {
  constructor(config) {
    this.logger = new Logger({ context: 'federation-transport' });
  }
  async send(data) { throw new Error('send not implemented'); }
  async receive(data) { throw new Error('receive not implemented'); }
}

class EmailTransport extends Transport {
  constructor(proxyService) {
    super();
    this.proxyService = proxyService;
  }

  async send({ post, targetDomains, federationType = 'new_post', instanceUrl, domain, signPayload }) {
    const results = [];
    const payload = await this.createFederationPayload(post, federationType, instanceUrl, domain, signPayload);

    for (const targetDomain of targetDomains) {
      try {
        const emailData = {
          to: `blog@${targetDomain}`,
          from: `blog@${domain}`,
          subject: `[Deadlight Federation] ${federationType === 'new_post' ? 'New Post' : 'Discovery'} from ${domain}`,
          body: JSON.stringify(payload, null, 2),
          headers: {
            'X-Deadlight-Type': 'federation',
            'X-Deadlight-Version': '1.0',
            'Content-Type': 'application/json'
          }
        };
        const result = await this.proxyService.sendEmail(emailData);
        results.push({ domain: targetDomain, success: true, result });
        this.logger.info('Federation email sent', { postId: post?.id, targetDomain });
      } catch (error) {
        results.push({ domain: targetDomain, success: false, error: error.message });
        this.logger.error('Federation email failed', { postId: post?.id, targetDomain, error: error.message });
      }
    }
    return results;
  }

  async receive({ emailData, db, verifySignature }) {
    try {
      const payload = JSON.parse(emailData.body);
      const isValid = await verifySignature(payload);
      if (!isValid) throw new Error('Invalid federation signature');

      switch (payload.federation_type) {
        case 'new_post':
          return await this.handleNewPost(payload.payload, emailData, db);
        case 'comment':
          return await this.handleComment(payload.payload, emailData, db);
        case 'discovery_request':
          return await this.handleDiscoveryRequest(payload.payload, emailData, db);
        case 'discovery_response':
          return await this.handleDiscoveryResponse(payload.payload, emailData, db);
        default:
          throw new Error(`Unknown federation type: ${payload.federation_type}`);
      }
    } catch (error) {
      this.logger.error('Failed to process federation email', { from: emailData.from, error: error.message });
      throw error;
    }
  }

  async createFederationPayload(data, type, instanceUrl, domain, signPayload) {
    const payload = {
      deadlight_version: '1.0',
      federation_type: type,
      timestamp: new Date().toISOString(),
      payload: data
    };
    payload.signature = await signPayload(payload);
    return payload;
  }

  async handleNewPost(postData, emailData, db) {
    const { post, origin } = postData;
    const trust = await this.getTrustRelationship(origin.domain, db);
    if (!trust) {
      this.logger.warn('Received post from untrusted domain', { domain: origin.domain });
      return { status: 'rejected', reason: 'untrusted_domain' };
    }

    const existing = await db.prepare(`
      SELECT id FROM posts 
      WHERE federation_metadata LIKE ?
      LIMIT 1
    `).bind(`%"source_url":"${post.source_url}"%`).first();

    if (existing) {
      this.logger.info('Duplicate federated post ignored', { sourceUrl: post.source_url });
      return { status: 'duplicate', postId: existing.id };
    }

    const federationMetadata = {
      source_domain: origin.domain,
      source_url: post.source_url,
      original_id: post.id,
      author: post.author,
      received_at: new Date().toISOString(),
      received_via: 'email',
      sender_email: emailData.from
    };

    const insertResult = await db.prepare(`
      INSERT INTO posts 
      (title, content, slug, author_id, created_at, published, 
       post_type, federation_metadata, moderation_status)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).bind(
      post.title,
      post.content,
      `federated-${Date.now()}-${Math.random().toString(36).substring(2, 7)}`,
      1, // System user ID
      post.published_at,
      trust.trust_level === 'verified' ? 1 : 0,
      'federated',
      JSON.stringify(federationMetadata),
      trust.trust_level === 'verified' ? 'approved' : 'pending'
    ).run();

    this.logger.info('Federated post created', {
      postId: insertResult.lastRowId,
      sourceDomain: origin.domain,
      status: trust.trust_level === 'verified' ? 'published' : 'pending'
    });

    return { status: 'success', postId: insertResult.lastRowId, published: trust.trust_level === 'verified' };
  }

  async handleComment(commentData, emailData, db) {
    const { comment, origin } = commentData;
    const trust = await this.getTrustRelationship(origin.domain, db);
    if (!trust) {
      this.logger.warn('Received comment from untrusted domain', { domain: origin.domain });
      return { status: 'rejected', reason: 'untrusted_domain' };
    }

    // Find parent post
    const parentPost = await db.prepare(`
      SELECT id, thread_id FROM posts 
      WHERE federation_metadata LIKE ? 
      LIMIT 1
    `).bind(`%"source_url":"${comment.parent_url}"%`).first();

    if (!parentPost) {
      this.logger.warn('Comment parent post not found', { parentUrl: comment.parent_url });
      return { status: 'rejected', reason: 'parent_not_found' };
    }

    const federationMetadata = {
      source_domain: origin.domain,
      source_url: comment.source_url,
      original_id: comment.id,
      author: comment.author,
      received_at: new Date().toISOString(),
      received_via: 'email',
      sender_email: emailData.from,
      parent_url: comment.parent_url
    };

    const insertResult = await db.prepare(`
      INSERT INTO posts 
      (title, content, slug, author_id, created_at, published, 
       post_type, federation_metadata, moderation_status, parent_id, thread_id)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).bind(
      `Comment on ${comment.parent_url}`,
      comment.content,
      `comment-${Date.now()}-${Math.random().toString(36).substring(2, 7)}`,
      1, // System user ID
      comment.published_at,
      trust.trust_level === 'verified' ? 1 : 0,
      'comment',
      JSON.stringify(federationMetadata),
      trust.trust_level === 'verified' ? 'approved' : 'pending',
      parentPost.id,
      parentPost.thread_id || parentPost.id
    ).run();

    this.logger.info('Federated comment created', {
      commentId: insertResult.lastRowId,
      sourceDomain: origin.domain,
      parentId: parentPost.id,
      threadId: parentPost.thread_id || parentPost.id
    });

    return { status: 'success', commentId: insertResult.lastRowId };
  }

  async handleDiscoveryRequest(requestData, emailData, db, instanceUrl, domain, signPayload) {
    this.logger.info('Handling discovery request', { from: requestData.requesting_domain });

    const responsePayload = await this.createFederationPayload({
      domain,
      public_key: await this.getPublicKey(),
      instance_url: instanceUrl,
      capabilities: ['posts', 'comments', 'discovery'],
      version: '1.0',
      software: 'deadlight'
    }, 'discovery_response', instanceUrl, domain, signPayload);

    const emailData2 = {
      to: `blog@${requestData.requesting_domain}`,
      from: `blog@${domain}`,
      subject: `[Deadlight Federation] Discovery Response from ${domain}`,
      body: JSON.stringify(responsePayload, null, 2),
      headers: {
        'X-Deadlight-Type': 'federation',
        'X-Deadlight-Version': '1.0',
        'In-Reply-To': emailData.messageId
      }
    };

    await this.proxyService.sendEmail(emailData2);
    return { status: 'response_sent' };
  }

  async handleDiscoveryResponse(payload, emailData, db) {
    this.logger.info('Received discovery response', { from: payload.domain });
    await this.establishTrust(payload.domain, payload.public_key, 'unverified', db);
    return { status: 'processed' };
  }
}

class HttpTransport extends Transport {
  constructor(baseUrl) {
    super();
    this.baseUrl = baseUrl;
  }

  async send({ post, targetDomains, federationType = 'new_post' }) {
    const results = [];
    for (const domain of targetDomains) {
      try {
        const response = await fetch(`https://${domain}/federation/outbox`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ post, federation_type: federationType })
        });
        if (!response.ok) throw new Error(`HTTP ${response.status}`);
        results.push({ domain, success: true, result: await response.json() });
        this.logger.info('Federated post sent via HTTP', { postId: post.id, targetDomain: domain });
      } catch (error) {
        results.push({ domain, success: false, error: error.message });
        this.logger.error('Federated post failed via HTTP', { postId: post.id, targetDomain: domain, error: error.message });
      }
    }
    return results;
  }

  async receive({ postData, db }) {
    const keywords = await loadModerationKeywords(db);
    const { status, notes } = checkModeration(postData.content, keywords);

    await db.prepare(`
      INSERT INTO posts
        (source_domain, title, content, author_id, created_at, published,
         post_type, federation_metadata, moderation_status, moderation_notes)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).bind(
      postData.source_domain,
      postData.title,
      postData.content,
      1,
      postData.published_at,
      status === 'approved' ? 1 : 0,
      'federated',
      JSON.stringify({ source_url: postData.source_url, source_domain: postData.source_domain }),
      status,
      notes
    ).run();

    return {
      success: true,
      message: status === 'pending' ? 'Post received and pending moderation' : 'Post received and auto-approved'
    };
  }
}

export class FederationService {
  constructor(env, transportType = 'email') {
    this.db = env.DB;
    this.env = env; // Store raw env for variable access
    this.logger = new Logger({ context: 'federation' });
    this.proxyService = new ProxyService({ PROXY_URL: env.PROXY_URL });
    this.transport = transportType === 'email'
      ? new EmailTransport(this.proxyService)
      : new HttpTransport(env.SITE_URL || 'https://deadlight.boo');
    this.siteUrl = env.SITE_URL || 'https://deadlight.boo';
  }

  async getConnectedDomains() {
    const res = await this.db.prepare('SELECT domain, trust_level FROM federation_trust').all();
    return res.results || [];
  }

  async getFederatedPosts(limit = 50) {
    const res = await this.db.prepare(`
      SELECT id, title, content, created_at, federation_metadata
      FROM posts
      WHERE post_type = 'federated'
      ORDER BY created_at DESC
      LIMIT ?
    `).bind(limit).all();

    return (res.results || []).map(row => {
      const meta = row.federation_metadata ? JSON.parse(row.federation_metadata) : {};
      return {
        id: row.id,
        title: row.title,
        content: row.content,
        author: meta.author || 'Unknown',
        source_domain: meta.source_domain,
        source_url: meta.source_url,
        published_at: row.created_at
      };
    });
  }

  async sendFederatedPost(post, targetDomains) {
    return await this.transport.send({
      post,
      targetDomains,
      federationType: 'new_post',
      instanceUrl: this.siteUrl,
      domain: this.getDomain(),
      signPayload: this.signPayload.bind(this)
    });
  }

  async sendFederatedComment(comment, targetDomains) {
    return await this.transport.send({
      post: comment,
      targetDomains,
      federationType: 'comment',
      instanceUrl: this.siteUrl,
      domain: this.getDomain(),
      signPayload: this.signPayload.bind(this)
    });
  }

  async processIncomingFederation(data) {
    return await this.transport.receive({
      emailData: data,
      db: this.db,
      verifySignature: this.verifyFederationSignature.bind(this)
    });
  }

  async testFederation() {
    const domains = await this.getConnectedDomains();
    const dummy = {
      id: 0,
      title: 'Federation Test',
      content: 'Hello Fediverse!',
      author: 'system',
      published_at: new Date().toISOString(),
      source_url: this.siteUrl
    };
    this.logger.info('Running federation test', { domains });
    return await this.sendFederatedPost(dummy, [domains[0]?.domain || 'example.com']);
  }

  async syncNetwork() {
    const domains = await this.getConnectedDomains();
    let imported = 0;
    const newPosts = [];

    for (const { domain } of domains) {
      try {
        const outbox = await fetch(`https://${domain}/federation/outbox`);
        const { posts } = await outbox.json();
        for (const post of posts) {
          const res = await this.processIncomingFederation({ post });
          if (res.success) {
            imported++;
            newPosts.push(post);
          }
        }
      } catch (err) {
        this.logger.error('Sync error for domain', { domain, error: err.message });
      }
    }
    return { imported, domains: domains.length, newPosts };
  }

  async discoverDomain(domain) {
    const discoveryPayload = {
      requesting_domain: this.getDomain(),
      public_key: await this.getPublicKey(),
      capabilities: ['posts', 'comments', 'discovery']
    };
    return await this.transport.send({
      post: discoveryPayload,
      targetDomains: [domain],
      federationType: 'discovery_request',
      instanceUrl: this.siteUrl,
      domain: this.getDomain(),
      signPayload: this.signPayload.bind(this)
    });
  }

  async queueFederatedPost(postId, targetDomains) {
    this.logger.info('Queueing federated post', { postId, domains: targetDomains.length });
    const federationMetadata = {
      target_domains: targetDomains,
      queued_at: new Date().toISOString(),
      status: 'pending',
      retry_count: 0
    };
    await this.db.prepare(`
      UPDATE posts 
      SET federation_pending = 1, federation_metadata = ?, retry_count = 0
      WHERE id = ?
    `).bind(JSON.stringify(federationMetadata), postId).run();
    return { success: true, queued: targetDomains.length };
  }

  async processFederationQueue() {
    this.logger.info('Processing federation queue');
    const pendingPosts = await this.db.prepare(`
      SELECT * FROM posts 
      WHERE federation_pending = 1 
      AND published = 1 
      ORDER BY created_at ASC 
      LIMIT 10
    `).all();

    let processed = 0;
    for (const post of pendingPosts.results || []) {
      try {
        const metadata = JSON.parse(post.federation_metadata || '{}');
        const maxRetries = 3;
        if (metadata.retry_count >= maxRetries) {
          await this.db.prepare(`
            UPDATE posts 
            SET federation_pending = 0, 
                last_error = ?,
                last_attempt = ?
            WHERE id = ?
          `).bind('Max retries exceeded', new Date().toISOString(), post.id).run();
          this.logger.error('Max retries exceeded for federated post', { postId: post.id });
          continue;
        }

        const results = await this.sendFederatedPost(post, metadata.target_domains);
        metadata.sent_at = new Date().toISOString();
        metadata.status = 'sent';
        metadata.results = results;
        metadata.retry_count = (metadata.retry_count || 0) + 1;

        await this.db.prepare(`
          UPDATE posts 
          SET federation_pending = 0, 
              federation_sent_at = ?,
              federation_metadata = ?,
              retry_count = ?,
              last_attempt = ?
          WHERE id = ?
        `).bind(
          new Date().toISOString(),
          JSON.stringify(metadata),
          metadata.retry_count,
          new Date().toISOString(),
          post.id
        ).run();
        processed++;
      } catch (error) {
        const metadata = JSON.parse(post.federation_metadata || '{}');
        metadata.retry_count = (metadata.retry_count || 0) + 1;
        await this.db.prepare(`
          UPDATE posts 
          SET federation_metadata = ?, 
              retry_count = ?,
              last_error = ?,
              last_attempt = ?
          WHERE id = ?
        `).bind(
          JSON.stringify(metadata),
          metadata.retry_count,
          error.message,
          new Date().toISOString(),
          post.id
        ).run();
        this.logger.error('Failed to send federated post', { postId: post.id, error: error.message });
      }
    }
    return { processed };
  }

  async getTrustRelationship(domain, db = this.db) {
    return await db.prepare('SELECT * FROM federation_trust WHERE domain = ?').bind(domain).first();
  }

  async establishTrust(domain, publicKey, trustLevel = 'unverified', db = this.db) {
    const existing = await this.getTrustRelationship(domain, db);
    if (existing) {
      await db.prepare(`
        UPDATE federation_trust 
        SET public_key = ?, trust_level = ?, last_seen = ?
        WHERE domain = ?
      `).bind(publicKey, trustLevel, new Date().toISOString(), domain).run();
    } else {
      await db.prepare(`
        INSERT INTO federation_trust (domain, public_key, trust_level, last_seen)
        VALUES (?, ?, ?, ?)
      `).bind(domain, publicKey, trustLevel, new Date().toISOString()).run();
    }
    this.logger.info('Trust relationship established', { domain, trustLevel });
  }

  async sendDeleteComment(commentId, targetDomains) {
    const comment = await this.env.DB.prepare(`
      SELECT p.id, p.content, p.author_id, p.parent_id, p.thread_id, p.created_at, u.username as author
      FROM posts p
      LEFT JOIN users u ON p.author_id = u.id
      WHERE p.id = ? AND p.post_type = 'comment'
    `).bind(commentId).first();

    if (!comment) {
      this.logger.error('Comment not found for deletion', { commentId });
      return new Response('Comment not found', { status: 404 });
    }

    const activity = {
      '@context': 'https://www.w3.org/ns/activitystreams',
      type: 'Delete',
      actor: `${this.siteUrl}/user/${comment.author}`,
      object: `${this.siteUrl}/comment/${commentId}`,
      to: targetDomains.map(domain => `${domain}/inbox`)
    };

    const signature = await this.signActivity(activity);
    for (const domain of targetDomains) {
      await this.sendActivity(activity, signature, domain);
    }
  }

  async sendActivity(activity, signature, domain) {
    const url = `${domain}/inbox`;
    await fetch(url, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/activity+json',
        'Signature': signature
      },
      body: JSON.stringify(activity)
    }).catch(err => this.logger.error(`Failed to send to ${domain}:`, err));
  }

  async signActivity(activity) {
    const { signature, ...payloadToSign } = activity;
    return await this.signPayload(payloadToSign);
  }

  async verifyFederationSignature(payload) {
    try {
      const { signature, ...payloadToVerify } = payload;
      const payloadString = JSON.stringify(payloadToVerify, Object.keys(payloadToVerify).sort());
      const senderDomain = payload.payload?.origin?.domain || payload.payload?.domain;
      if (!senderDomain) return false;
      const trust = await this.getTrustRelationship(senderDomain);
      if (!trust) return false;
      return await verifyPassword(payloadString, signature, trust.public_key);
    } catch (error) {
      this.logger.error('Signature verification failed', { error: error.message });
      return false;
    }
  }

  async signPayload(payload) {
    const { signature, ...payloadToSign } = payload;
    const payloadString = JSON.stringify(payloadToSign, Object.keys(payloadToSign).sort());
    const privateKey = await this.getPrivateKey();
    const { hash, salt } = await hashPassword(payloadString, privateKey);
    return hash;
  }

  async getPrivateKey() {
    return this.env.FEDERATION_PRIVATE_KEY || 'default-key-for-dev'; // Use env directly, fallback for dev
  }

  async getPublicKey() {
    return this.env.FEDERATION_PUBLIC_KEY || 'default-public-key-for-dev'; // Use env directly, fallback for dev
  }

  getDomain() {
    try {
      return new URL(this.siteUrl).hostname;
    } catch {
      return 'deadlight.boo';
    }
  }

  async getThreadedComments(postId, limit = 50) {
    const res = await this.db.prepare(`
      SELECT id, content, author_id, created_at, federation_metadata
      FROM posts
      WHERE post_type = 'comment' AND (parent_id = ? OR thread_id = ?)
      ORDER BY created_at ASC
      LIMIT ?
    `).bind(postId, postId, limit).all();

    return (res.results || []).map(row => {
      const meta = row.federation_metadata ? JSON.parse(row.federation_metadata) : {};
      return {
        id: row.id,
        content: row.content,
        author: meta.author || 'Unknown',
        source_domain: meta.source_domain,
        source_url: meta.source_url,
        published_at: row.created_at
      };
    });
  }
}