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
    const payload = {
      post,
      federationType: 'new_post',
      instanceUrl: this._siteUrl(),
      domain: this._domain(),
    };
    const signed = await this._sign(payload);
    await this.queue.queueItem('federation', { ...signed, targetDomains });
  }

  async publishComment(comment, targetDomains) {
    const payload = {
      comment,
      federationType: 'comment',
      instanceUrl: this._siteUrl(),
      domain: this._domain(),
    };
    const signed = await this._sign(payload);
    await this.queue.queueItem('federation', { ...signed, targetDomains });
  }

  /* --------------------------------------------------------------
     PROCESSING – called by QueueService (see _processFederation)
     -------------------------------------------------------------- */
  async sendViaTransport(item) {
    // item is the JSON that was stored in federation_metadata
    return await this.transport.send(item);
  }

  /* --------------------------------------------------------------
     INBOUND – called from your inbox endpoint (POST /inbox)
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
      // add discovery, delete, etc.
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
    return this.env.FEDERATION_PRIVATE_KEY ?? 'dev-private-key';
  }

  _siteUrl() { return this.env.SITE_URL ?? 'https://deadlight.boo'; }
  _domain() { return new URL(this._siteUrl()).hostname; }

  /* --------------------------------------------------------------
     INBOUND HANDLERS (you can keep your existing logic)
     -------------------------------------------------------------- */
  async _handleNewPost(postData, email) {
    // duplicate check, moderation, insert → return {status, postId}
    // … (copy from your original handleNewPost)
  }

  async _handleComment(commentData, email) {
    // … (copy from original)
  }

  /* --------------------------------------------------------------
     DISCOVERY – NEW METHOD FOR DOMAIN DISCOVERY
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