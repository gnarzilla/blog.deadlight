// src/services/enhanced-outbox.js - Enhanced version that integrates with your existing services
import { ProxyService } from './proxy.js';
import { Logger } from '../../../lib.deadlight/core/src/logging/logger.js';
import { FederationService } from './federation.js';

export class EnhancedOutboxService {
    constructor(env) {
        this.env = env;
        this.db = env.DB;
        this.logger = new Logger({ context: 'enhanced-outbox' });
        this.proxyService = new ProxyService({ PROXY_URL: env.PROXY_URL });
        this.federationService = new FederationService(env);
    }

    // Enhanced queue processing that works with your existing schema
    async processQueue() {
        try {
            this.logger.info('Starting enhanced outbox queue processing');

            // Check if proxy is available first
            const healthCheck = await this.proxyService.healthCheck();
            if (!healthCheck.proxy_connected) {
                this.logger.info('Proxy offline, keeping operations queued');
                return { 
                    processed: 0, 
                    queued: await this.getQueuedCount(), 
                    status: 'proxy_offline',
                    message: 'Proxy is offline - operations remain queued',
                    circuit_state: this.proxyService.getCircuitState()
                };
            }

            this.logger.info('Proxy is online, processing queued operations');

            // Process different types using your existing schema
            const results = await Promise.allSettled([
                this.processEmailReplies(), // Your existing email reply system
                this.processFederationQueue(), // Your existing federation system  
                this.processNotificationQueue(), // Enhanced notifications
                this.processSmsQueue() // New SMS support
            ]);

            const summary = this.summarizeResults(results);
            
            this.logger.info('Enhanced outbox processing completed', summary);
            return summary;

        } catch (error) {
            this.logger.error('Enhanced outbox processing failed', { error: error.message });
            return { 
                processed: 0, 
                error: error.message, 
                status: 'error',
                message: `Processing failed: ${error.message}`,
                circuit_state: this.proxyService.getCircuitState()
            };
        }
    }

    // Process email replies using your existing system
    async processEmailReplies() {
        const pendingReplies = await this.db.prepare(`
            SELECT * FROM posts 
            WHERE is_reply_draft = 1 
            AND email_metadata LIKE '%"sent":false%'
            AND (retry_count IS NULL OR retry_count < 3)
            ORDER BY created_at ASC
            LIMIT 50
        `).all();

        const replies = pendingReplies.results || [];
        let processed = 0;

        for (const reply of replies) {
            try {
                const metadata = JSON.parse(reply.email_metadata || '{}');
                
                const emailData = {
                    to: metadata.to,
                    from: metadata.from || 'noreply@deadlight.boo',
                    subject: reply.title,
                    body: reply.content,
                    headers: {
                        'In-Reply-To': metadata.message_id,
                        'References': metadata.references
                    }
                };

                this.logger.info('Sending queued reply', { 
                    replyId: reply.id, 
                    to: emailData.to 
                });

                // Send via enhanced proxy service
                const result = await this.proxyService.sendEmail(emailData);
                
                // Update with your existing pattern
                await this.markReplySent(reply.id, result);
                processed++;
                
            } catch (error) {
                await this.incrementRetryCount(reply.id, error.message, 'email_reply');
                this.logger.error('Failed to send queued reply', { 
                    replyId: reply.id, 
                    error: error.message 
                });
            }
        }

        return processed;
    }

    // Use your existing federation service
    async processFederationQueue() {
        try {
            const result = await this.federationService.processFederationQueue();
            return result.processed || 0;
        } catch (error) {
            this.logger.error('Federation queue processing failed', { error: error.message });
            return 0;
        }
    }

    // Enhanced notification processing with SMS support
    async processNotificationQueue() {
        const pendingNotifications = await this.db.prepare(`
            SELECT * FROM notifications 
            WHERE message_type IN ('email', 'sms') 
            AND is_read = FALSE 
            ORDER BY created_at ASC 
            LIMIT 20
        `).all();

        const notifications = pendingNotifications.results || [];
        let processed = 0;

        for (const notification of notifications) {
            try {
                if (notification.message_type === 'email') {
                    await this.sendNotificationEmail(notification);
                } else if (notification.message_type === 'sms') {
                    await this.sendNotificationSms(notification);
                }
                
                // Mark as processed
                await this.db.prepare(`
                    UPDATE notifications 
                    SET is_read = TRUE 
                    WHERE id = ?
                `).bind(notification.id).run();
                
                processed++;
                
            } catch (error) {
                this.logger.error('Failed to send notification', { 
                    notificationId: notification.id, 
                    type: notification.message_type,
                    error: error.message 
                });
            }
        }

        return processed;
    }

    // New SMS queue processing
    async processSmsQueue() {
        // SMS messages stored as notifications with message_type = 'sms'
        const pendingSms = await this.db.prepare(`
            SELECT * FROM notifications 
            WHERE message_type = 'sms' 
            AND is_read = FALSE 
            ORDER BY created_at ASC 
            LIMIT 10
        `).all();

        const smsMessages = pendingSms.results || [];
        let processed = 0;

        for (const sms of smsMessages) {
            try {
                const smsData = JSON.parse(sms.content || '{}');
                
                const result = await this.proxyService.sendSms({
                    to: smsData.to,
                    message: smsData.message,
                    from: smsData.from || 'Deadlight'
                });

                await this.db.prepare(`
                    UPDATE notifications 
                    SET is_read = TRUE, content = ?
                    WHERE id = ?
                `).bind(
                    JSON.stringify({ ...smsData, sent: true, result }),
                    sms.id
                ).run();

                processed++;
                this.logger.info('SMS sent successfully', { smsId: sms.id });

            } catch (error) {
                this.logger.error('Failed to send SMS', { 
                    smsId: sms.id, 
                    error: error.message 
                });
            }
        }

        return processed;
    }

    // Enhanced queue counting that works with your schema
    async getQueuedCount() {
        try {
            // Count email replies (your existing system)
            const emailReplies = await this.db.prepare(`
                SELECT COUNT(*) as count FROM posts 
                WHERE is_reply_draft = 1 
                AND email_metadata LIKE '%"sent":false%'
                AND (retry_count IS NULL OR retry_count < 3)
            `).first();

            // Count federation posts (your existing system)
            let federationPosts = 0;
            try {
                const fedResult = await this.db.prepare(`
                    SELECT COUNT(*) as count FROM posts 
                    WHERE federation_pending = 1 
                    AND published = 1
                `).first();
                federationPosts = fedResult?.count || 0;
            } catch {
                // Federation columns might not exist yet
            }

            // Count pending notifications
            const notifications = await this.db.prepare(`
                SELECT COUNT(*) as count FROM notifications 
                WHERE message_type IN ('email', 'sms') 
                AND is_read = FALSE
            `).first();

            return {
                total: (emailReplies?.count || 0) + federationPosts + (notifications?.count || 0),
                email_replies: emailReplies?.count || 0,
                federation_posts: federationPosts,
                notifications: notifications?.count || 0
            };
        } catch (error) {
            this.logger.error('Error getting queue count', { error: error.message });
            return { total: 0, email_replies: 0, federation_posts: 0, notifications: 0 };
        }
    }

    // Helper methods that work with your existing patterns
    async markReplySent(replyId, sendResult) {
        const reply = await this.db.prepare(
            'SELECT email_metadata FROM posts WHERE id = ?'
        ).bind(replyId).first();
        
        if (!reply) return;

        const metadata = JSON.parse(reply.email_metadata || '{}');
        metadata.sent = true;
        metadata.date_sent = new Date().toISOString();
        metadata.send_result = sendResult;

        await this.db.prepare(`
            UPDATE posts 
            SET email_metadata = ?, updated_at = ? 
            WHERE id = ?
        `).bind(
            JSON.stringify(metadata),
            new Date().toISOString(),
            replyId
        ).run();
    }

    async incrementRetryCount(itemId, errorMessage, itemType = 'post') {
        try {
            await this.db.prepare(`
                UPDATE posts 
                SET retry_count = COALESCE(retry_count, 0) + 1,
                    last_error = ?,
                    last_attempt = ?,
                    updated_at = ?
                WHERE id = ?
            `).bind(
                errorMessage, 
                new Date().toISOString(),
                new Date().toISOString(), 
                itemId
            ).run();
        } catch (error) {
            this.logger.error('Failed to update retry count', { 
                itemId, 
                itemType,
                error: error.message 
            });
        }
    }

    // New notification methods
    async sendNotificationEmail(notification) {
        const content = JSON.parse(notification.content || '{}');
        
        const emailData = {
            to: content.to,
            from: content.from || 'notifications@deadlight.boo',
            subject: content.subject || 'Deadlight Notification',
            body: content.message
        };

        return await this.proxyService.sendEmail(emailData);
    }

    async sendNotificationSms(notification) {
        const content = JSON.parse(notification.content || '{}');
        
        const smsData = {
            to: content.to,
            message: content.message,
            from: content.from || 'Deadlight'
        };

        return await this.proxyService.sendSms(smsData);
    }

    // Queue new items using your existing patterns
    async queueSms(userId, phoneNumber, message) {
        const smsData = {
            to: phoneNumber,
            message: message,
            queued_at: new Date().toISOString()
        };

        await this.db.prepare(`
            INSERT INTO notifications (user_id, type, message_type, content, created_at)
            VALUES (?, ?, ?, ?, ?)
        `).bind(
            userId,
            'system',
            'sms',
            JSON.stringify(smsData),
            new Date().toISOString()
        ).run();

        return { success: true, message: 'SMS queued for delivery' };
    }

    async queueEmailNotification(userId, emailData) {
        await this.db.prepare(`
            INSERT INTO notifications (user_id, type, message_type, content, created_at)
            VALUES (?, ?, ?, ?, ?)
        `).bind(
            userId,
            'system',
            'email',
            JSON.stringify(emailData),
            new Date().toISOString()
        ).run();

        return { success: true, message: 'Email notification queued' };
    }

    // Results summary helper
    summarizeResults(results) {
        const totalProcessed = results.reduce((sum, result) => {
            if (result.status === 'fulfilled') {
                return sum + (result.value || 0);
            }
            return sum;
        }, 0);

        const errors = results.filter(result => result.status === 'rejected')
            .map(result => result.reason?.message);

        return {
            processed: totalProcessed,
            queued: this.getQueuedCount(),
            status: errors.length > 0 ? 'partial_success' : 'success',
            message: `Processed ${totalProcessed} operations${errors.length > 0 ? ' with some errors' : ''}`,
            errors,
            circuit_state: this.proxyService.getCircuitState()
        };
    }

    // Enhanced status method
    async getStatus() {
        const queueCount = await this.getQueuedCount();
        const proxyHealth = await this.proxyService.healthCheck();
        const circuitState = this.proxyService.getCircuitState();
        
        return {
            queued_operations: queueCount,
            proxy_connected: proxyHealth.proxy_connected,
            circuit_breaker: circuitState,
            last_check: new Date().toISOString(),
            status: queueCount.total > 0 ? 'pending' : 'clear',
            proxy_details: {
                blog_api: proxyHealth.blog_api,
                email_api: proxyHealth.email_api,
                failures: circuitState.failures
            }
        };
    }
}
