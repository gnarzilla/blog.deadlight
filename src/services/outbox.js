// src/services/outbox.js - Complete outbox queue management
import { ProxyService } from './proxy.js';
import { Logger } from '../../../lib.deadlight/core/src/logging/logger.js';
import { FederationService } from './federation.js';

export class OutboxService {
    constructor(env) {
        this.env = env;
        this.logger = new Logger({ context: 'outbox' });
        this.proxyService = new ProxyService({ PROXY_URL: env.PROXY_URL });
    }

    // Main queue processing method
    async processQueue() {
        try {
            this.logger.info('Starting outbox queue processing');

            // Check if proxy is available
            const healthCheck = await this.proxyService.healthCheck();
            if (!healthCheck.proxy_connected) {
                this.logger.info('Proxy offline, keeping operations queued');
                return { 
                    processed: 0, 
                    queued: await this.getQueuedCount(), 
                    status: 'proxy_offline',
                    message: 'Proxy is offline - operations remain queued'
                };
            }

            this.logger.info('Proxy is online, processing queued operations');

            // Process different types of queued operations
            const results = await Promise.allSettled([
                this.processPendingReplies(),
                this.processPendingFederatedPosts(),
                // Future: this.processPendingNewsletters(),
                // Future: this.processPendingNotifications(),
            ]);

            // Calculate total processed
            const totalProcessed = results.reduce((sum, result) => {
                if (result.status === 'fulfilled') {
                    return sum + (result.value || 0);
                }
                return sum;
            }, 0);

            // Log any failures
            results.forEach((result, index) => {
                if (result.status === 'rejected') {
                    this.logger.error(`Queue processor ${index} failed`, { 
                        error: result.reason?.message 
                    });
                }
            });

            const remainingQueued = await this.getQueuedCount();
            
            this.logger.info('Outbox processing completed', { 
                processed: totalProcessed, 
                queued: remainingQueued 
            });

            return { 
                processed: totalProcessed, 
                queued: remainingQueued,
                status: 'success',
                message: `Successfully processed ${totalProcessed} operations`
            };

        } catch (error) {
            this.logger.error('Outbox processing failed', { error: error.message });
            return { 
                processed: 0, 
                error: error.message, 
                status: 'error',
                message: `Processing failed: ${error.message}`
            };
        }
    }

    // Process pending email replies
    async processPendingReplies() {
        this.logger.info('Processing pending email replies');

        const pendingReplies = await this.getPendingReplies();
        let processed = 0;

        for (const reply of pendingReplies) {
            try {
                const metadata = JSON.parse(reply.email_metadata || '{}');
                
                // Prepare email data for proxy
                const emailData = {
                    to: metadata.to,
                    from: metadata.from || 'noreply@deadlight.boo',
                    subject: reply.title,
                    body: reply.content
                };

                this.logger.info('Sending queued reply', { 
                    replyId: reply.id, 
                    to: emailData.to, 
                    subject: emailData.subject 
                });

                // Send via proxy
                const result = await this.proxyService.sendEmail(emailData);
                
                // Mark as sent
                await this.markReplySent(reply.id, result);
                processed++;
                
                this.logger.info('Successfully sent queued reply', { 
                    replyId: reply.id, 
                    to: emailData.to 
                });

            } catch (error) {
                this.logger.error('Failed to send queued reply', { 
                    replyId: reply.id, 
                    error: error.message 
                });
                
                // Update retry count
                await this.incrementRetryCount(reply.id, error.message);
            }
        }

        return processed;
    }

    async queueMessage(type, data) {
        if (type === 'email') return this.queueEmailReply(data);
        if (type === 'notification') {
            await this.db.prepare(`
            INSERT INTO notifications (user_id, type, content, related_post_id)
            VALUES (?, ?, ?, ?)
            `).bind(data.user_id, data.type, data.content, data.post_id).run();
            return { success: true };
        }
        if (type === 'sms') {
            const smsMetadata = { to: data.to, message: data.message, queued_at: new Date().toISOString() };
            await this.db.prepare(`
                INSERT INTO notifications (user_id, type, content)
                VALUES (?, ?, ?)
            `).bind(data.user_id, 'sms', JSON.stringify(smsMetadata)).run();
            return { success: true };
        }
        throw new Error('Unsupported message type');
    }

    // Process federated posts (for decentralized social media)
    async processPendingFederatedPosts() {
        const fedSvc = new FederationService(this.env);
        const { processed } = await fedSvc.processFederationQueue();
        return processed;
    }

    // Database query helpers
    async getPendingReplies() {
        const result = await this.env.DB.prepare(`
            SELECT * FROM posts 
            WHERE is_reply_draft = 1 
            AND email_metadata LIKE '%"sent":false%'
            AND (retry_count IS NULL OR retry_count < 3)
            ORDER BY created_at ASC
            LIMIT 50
        `).all();
        
        return result.results || [];
    }

    async getPendingFederatedPosts() {
        try {
            const result = await this.env.DB.prepare(`
                SELECT * FROM posts 
                WHERE federation_pending = 1 
                AND published = 1
                ORDER BY created_at ASC
                LIMIT 20
            `).all();
            
            return result.results || [];
        } catch (error) {
            // Handle case where federation columns don't exist yet
            this.logger.info('Federation columns not found - skipping federated posts');
            return [];
        }
    }

    async markReplySent(replyId, sendResult = null) {
        const reply = await this.env.DB.prepare(
            'SELECT email_metadata FROM posts WHERE id = ?'
        ).bind(replyId).first();
        
        if (!reply) return;

        const metadata = JSON.parse(reply.email_metadata || '{}');
        metadata.sent = true;
        metadata.date_sent = new Date().toISOString();
        metadata.send_result = sendResult;

        await this.env.DB.prepare(`
            UPDATE posts 
            SET email_metadata = ?, updated_at = ? 
            WHERE id = ?
        `).bind(
            JSON.stringify(metadata),
            new Date().toISOString(),
            replyId
        ).run();
    }

    async markFederationSent(postId) {
        try {
            await this.env.DB.prepare(`
                UPDATE posts 
                SET federation_pending = 0, federation_sent_at = ? 
                WHERE id = ?
            `).bind(new Date().toISOString(), postId).run();
        } catch (error) {
            this.logger.info('Federation columns not found - skipping federation update');
        }
    }

    async incrementRetryCount(replyId, errorMessage) {
        try {
            // First, try to add retry_count column if it doesn't exist
            await this.env.DB.prepare(`
                ALTER TABLE posts ADD COLUMN retry_count INTEGER DEFAULT 0
            `).run().catch(() => {}); // Ignore if column exists

            await this.env.DB.prepare(`
                UPDATE posts 
                SET retry_count = COALESCE(retry_count, 0) + 1,
                    last_error = ?,
                    updated_at = ?
                WHERE id = ?
            `).bind(errorMessage, new Date().toISOString(), replyId).run();
        } catch (error) {
            this.logger.error('Failed to update retry count', { error: error.message });
        }
    }

    async getQueuedCount() {
        try {
            // Count pending replies
            const replies = await this.env.DB.prepare(`
                SELECT COUNT(*) as count FROM posts 
                WHERE is_reply_draft = 1 
                AND email_metadata LIKE '%"sent":false%'
                AND (retry_count IS NULL OR retry_count < 3)
            `).first();

            // Count pending federated posts (handle if columns don't exist)
            let federatedCount = 0;
            try {
                const federated = await this.env.DB.prepare(`
                    SELECT COUNT(*) as count FROM posts 
                    WHERE federation_pending = 1 
                    AND published = 1
                `).first();
                federatedCount = federated?.count || 0;
            } catch (error) {
                // Federation columns don't exist yet
                federatedCount = 0;
            }

            return (replies?.count || 0) + federatedCount;
        } catch (error) {
            this.logger.error('Error getting queue count', { error: error.message });
            return 0;
        }
    }

    // Queue new operations
    async queueEmailReply(replyData) {
        this.logger.info('Queuing email reply', { to: replyData.to });
        
        const metadata = {
            to: replyData.to,
            from: replyData.from,
            original_id: replyData.originalId,
            date_queued: new Date().toISOString(),
            sent: false
        };

        // This integrates with your existing inbox reply system
        // The reply is already stored as a draft - we just ensure metadata is correct
        return metadata;
    }

    async queueFederatedPost(postId, targetDomains, author) {
        this.logger.info('Queuing federated post', { postId, domains: targetDomains.length });
        
        try {
            const federationMetadata = {
                target_domains: targetDomains,
                author: author,
                date_queued: new Date().toISOString(),
                sent: false
            };

            await this.env.DB.prepare(`
                UPDATE posts 
                SET federation_pending = 1, federation_metadata = ? 
                WHERE id = ?
            `).bind(JSON.stringify(federationMetadata), postId).run();

            return { success: true, queued: targetDomains.length };
        } catch (error) {
            this.logger.error('Failed to queue federated post', { error: error.message });
            return { success: false, error: error.message };
        }
    }

    // Helper methods
    getBlogDomain() {
        try {
            return new URL(this.env.SITE_URL || 'https://deadlight.boo').hostname;
        } catch {
            return 'deadlight.boo';
        }
    }

    getBlogUrl() {
        return this.env.SITE_URL || 'https://deadlight.boo';
    }

    // Health check for the outbox system
    async getStatus() {
        const queuedCount = await this.getQueuedCount();
        const proxyHealth = await this.proxyService.healthCheck();
        
        return {
            queued_operations: queuedCount,
            proxy_connected: proxyHealth.proxy_connected,
            last_check: new Date().toISOString(),
            status: queuedCount > 0 ? 'pending' : 'clear'
        };
    }
}