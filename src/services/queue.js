// src/services/queue.js
import { Logger } from '../../../lib.deadlight/core/src/logging/logger.js';
import { PostModel } from '../../../lib.deadlight/core/src/db/models/post.js';
import { SettingsModel } from '../../../lib.deadlight/core/src/db/models/settings.js';

export class QueueService {
  constructor(env, proxyService, federationService, configService) {
    this.env = env;                     // Worker env (contains DB)
    this.db = env.DB;
    this.logger = new Logger({ context: 'queue' });
    this.proxy = proxyService;
    this.federation = federationService;
    this.config = configService;

    this.postModel = new PostModel(this.db);
    this.settingsModel = new SettingsModel(this.db);
  }

  /* --------------------------------------------------------------
     PUBLIC API – called from routes / cron
     -------------------------------------------------------------- */
  /** Queue any outbound item */
  async queueItem(type, payload) {
    try {
      switch (type) {
        case 'email_reply':
        case 'notification_email':
        case 'notification_sms':
          return await this._queueNotification(type, payload);
        case 'federation':
          return await this._queueFederation(payload);
        case 'proxy_action': 
          return await this._queueProxyAction(payload);
        default:
          throw new Error(`Unknown queue type: ${type}`);
      }
    } catch (e) {
      this.logger.error(`queueItem(${type}) failed`, { error: e.message });
      throw e;
    }
  }

  /** Process everything that is pending */
  async processAll() {
    const health = await this.proxy.healthCheck();
    if (!health.proxy_connected) {
      this.logger.info('Proxy offline – keeping queue');
      return { processed: 0, status: 'proxy_offline' };
    }

    const results = await Promise.allSettled([
      this._processEmailReplies(),
      this._processNotifications(),
      this._processFederation(),
      this._processProxyActions(),
    ]);

    return this._summarize(results);
  }

  /** Human-readable status for the admin dashboard */
  async getStatus() {
    const counts = await this._queuedCounts();
    const proxy = await this.proxy.healthCheck();
    return {
      queued: counts,
      proxy_connected: proxy.proxy_connected,
      circuit: this.proxy.getCircuitState(),
      last_check: new Date().toISOString(),
    };
  }

  /* --------------------------------------------------------------
     PRIVATE HELPERS
     -------------------------------------------------------------- */

  // ---- queue helpers -------------------------------------------------
  async _queueNotification(type, payload) {
    const messageType = type === 'notification_sms' ? 'sms' : 'email';
    await this.db.prepare(`
      INSERT INTO notifications
        (user_id, type, message_type, content, created_at)
      VALUES (?, 'system', ?, ?, ?)
    `).bind(
      payload.userId ?? null,
      messageType,
      JSON.stringify(payload),
      new Date().toISOString()
    ).run();

    this.logger.info(`Queued ${type}`, { payload });
    return { success: true };
  }

  async _queueFederation(payload) {
    const meta = JSON.stringify(payload);
    await this.db.prepare(`
      INSERT INTO posts
        (title, content, author_id, post_type, federation_metadata,
         federation_pending, created_at)
      VALUES ('Federated Item', '', 1, 'federated', ?, 1, ?)
    `).bind(meta, new Date().toISOString()).run();

    this.logger.info('Queued federation item');
    return { success: true };
  }
  async _queueProxyAction(payload) {
  await this.db.prepare(`
    INSERT INTO notifications
      (user_id, type, message_type, content, created_at)
    VALUES (?, 'system', 'email', ?, ?)
  `).bind(
    payload.userId ?? null,
    JSON.stringify({ ...payload, proxy_action: true }),  // Flag it as proxy action in JSON
    new Date().toISOString()
  ).run();

  this.logger.info(`Queued proxy action: ${payload.actionType}`, { payload });
  return { success: true, queued: true };
}

// Update _processProxyActions() to detect proxy actions by JSON flag
async _processProxyActions() {
  const pending = await this.db.prepare(`
    SELECT id, content
    FROM notifications
    WHERE type = 'system'
      AND message_type = 'email'
      AND is_read = FALSE
      AND (retry_count IS NULL OR retry_count < 3)
    LIMIT 20
  `).all();

  let processed = 0;
  for (const row of (pending.results ?? [])) {
    const data = JSON.parse(row.content);
    
    // Skip if not a proxy action
    if (!data.proxy_action) continue;
    
    const actionType = data.actionType;
    
    try {
      let result;
      
      switch (actionType) {
        case 'send_email':
          result = await this.proxy.sendEmail(data);
          break;
        case 'send_sms':
          result = await this.proxy.sendSms(data);
          break;
        default:
          this.logger.warn(`Unknown proxy action type: ${actionType}`);
          result = { skipped: true, reason: 'unknown_action_type' };
      }
      
      await this.db.prepare(`
        UPDATE notifications 
        SET is_read = TRUE, 
            content = JSON_SET(content, '$.result', ?)
        WHERE id = ?
      `).bind(JSON.stringify(result), row.id).run();
      
      processed++;
      this.logger.info(`Processed proxy action: ${actionType}`, { id: row.id });
      
      } catch (e) {
        await this._incrementRetry(row.id, e.message, 'notifications');
        this.logger.error(`Proxy action failed: ${actionType}`, { 
          id: row.id, 
          error: e.message 
        });
      }
    }
    return processed;
  }

  // ---- processing helpers -------------------------------------------
  async _processEmailReplies() {
    const pending = await this.db.prepare(`
      SELECT id, email_metadata
      FROM posts
      WHERE is_reply_draft = 1
        AND email_metadata LIKE '%"sent":false%'
        AND (retry_count IS NULL OR retry_count < 3)
      LIMIT 50
    `).all();

    let processed = 0;
    for (const row of (pending.results ?? [])) {
      const meta = JSON.parse(row.email_metadata);
      const email = {
        to: meta.to,
        from: meta.from ?? 'noreply@deadlight.boo',
        subject: meta.subject ?? 'Reply',
        body: meta.body,
        headers: { 'In-Reply-To': meta.message_id, References: meta.references },
      };

      try {
        const result = await this.proxy.sendEmail(email);
        await this._markReplySent(row.id, result);
        processed++;
      } catch (e) {
        await this._incrementRetry(row.id, e.message, 'posts');
      }
    }
    return processed;
  }

  async _processNotifications() {
    const pending = await this.db.prepare(`
      SELECT id, message_type, content
      FROM notifications
      WHERE message_type IN ('email','sms')
        AND is_read = FALSE
      LIMIT 20
    `).all();

    let processed = 0;
    for (const row of (pending.results ?? [])) {
      const data = JSON.parse(row.content);
      try {
        if (row.message_type === 'email') {
          await this.proxy.sendEmail(data);
        } else {
          await this.proxy.sendSms(data);
        }
        await this.db.prepare(`
          UPDATE notifications SET is_read = TRUE WHERE id = ?
        `).bind(row.id).run();
        processed++;
      } catch (e) {
        await this._incrementRetry(row.id, e.message, 'notifications');
      }
    }
    return processed;
  }

  async _processFederation() {
    const pending = await this.db.prepare(`
      SELECT id, federation_metadata
      FROM posts
      WHERE post_type = 'federated' AND federation_pending = 1
      LIMIT 20
    `).all();

    let processed = 0;
    for (const row of (pending.results ?? [])) {
      const payload = JSON.parse(row.federation_metadata);
      try {
        // The federation service knows how to sign & send
        const result = await this.federation.sendViaTransport(payload);
        await this._markFederationSent(row.id, result);
        processed++;
      } catch (e) {
        await this._incrementRetry(row.id, e.message, 'posts');
      }
    }
    return processed;
  }

  // ---- DB helpers ---------------------------------------------------
  async _markReplySent(postId, result) {
    const row = await this.db.prepare('SELECT email_metadata FROM posts WHERE id = ?')
      .bind(postId).first();

    const meta = JSON.parse(row.email_metadata);
    meta.sent = true;
    meta.date_sent = new Date().toISOString();
    meta.send_result = result;

    await this.db.prepare(`
      UPDATE posts SET email_metadata = ?, updated_at = ?
      WHERE id = ?
    `).bind(JSON.stringify(meta), new Date().toISOString(), postId).run();
  }

  async _markFederationSent(postId, result) {
    await this.db.prepare(`
      UPDATE posts
      SET federation_pending = 0,
          federation_sent_at = ?,
          federation_metadata = JSON_SET(federation_metadata, '$.send_result', ?)
      WHERE id = ?
    `).bind(new Date().toISOString(), JSON.stringify(result), postId).run();
  }

  async _incrementRetry(id, msg, table) {
    await this.db.prepare(`
      UPDATE ${table}
      SET retry_count = COALESCE(retry_count,0)+1,
          last_error = ?, last_attempt = ?, updated_at = ?
      WHERE id = ?
    `).bind(msg, new Date().toISOString(), new Date().toISOString(), id).run();
  }

  // ---- reporting ----------------------------------------------------
  async _queuedCounts() {
    const [replies, notifs, fed, proxyActions] = await Promise.all([
      this.db.prepare(`
        SELECT COUNT(*) AS c FROM posts
        WHERE is_reply_draft = 1 AND email_metadata LIKE '%"sent":false%'
      `).first(),
      // ✅ Exclude proxy actions from regular notifications
      this.db.prepare(`
        SELECT COUNT(*) AS c FROM notifications
        WHERE message_type IN ('sms') 
          AND is_read = FALSE
          AND (content NOT LIKE '%"proxy_action":true%' OR content IS NULL)
      `).first(),
      this.db.prepare(`
        SELECT COUNT(*) AS c FROM posts
        WHERE post_type = 'federated' AND federation_pending = 1
      `).first(),
      // ✅ Count proxy actions correctly
      this.db.prepare(`
        SELECT COUNT(*) AS c FROM notifications
        WHERE type = 'system' 
          AND message_type = 'email'
          AND content LIKE '%"proxy_action":true%'
          AND is_read = FALSE
      `).first(),
    ]);

    return {
      total: (replies?.c||0) + (notifs?.c||0) + (fed?.c||0) + (proxyActions?.c||0),
      email_replies: replies?.c||0,
      notifications: notifs?.c||0,
      federation: fed?.c||0,
      proxy_actions: proxyActions?.c||0,
    };
  }


  _summarize(settled) {
    const processed = settled
      .filter(r => r.status === 'fulfilled')
      .reduce((s, r) => s + (r.value ?? 0), 0);

    const errors = settled
      .filter(r => r.status === 'rejected')
      .map(r => r.reason?.message ?? 'unknown');

    return {
      processed,
      queued: this._queuedCounts(),
      status: errors.length ? 'partial_success' : 'success',
      errors,
      circuit_state: this.proxy.getCircuitState(),
    };
  }
}
