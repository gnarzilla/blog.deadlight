// src/services/federation-transport.js
import { Logger } from '../../../lib.deadlight/core/src/logging/logger.js';

export class EmailTransport {
  constructor(proxyService) {
    this.proxy = proxyService;
    this.logger = new Logger({ context: 'fed-transport' });
  }

  async send({ post, comment, federationType, instanceUrl, domain, targetDomains, signature }) {
    const results = [];

    for (const target of targetDomains) {
      const email = {
        to: `blog@${target}`,
        from: `blog@${domain}`,
        subject: `[Deadlight Federation] ${federationType} from ${domain}`,
        body: JSON.stringify({
          deadlight_version: '1.0',
          federation_type: federationType,
          timestamp: new Date().toISOString(),
          payload: post ?? comment,
          signature,
        }, null, 2),
        headers: {
          'X-Deadlight-Type': 'federation',
          'X-Deadlight-Version': '1.0',
          'Content-Type': 'application/json',
        },
      };

      try {
        const res = await this.proxy.sendEmail(email);
        results.push({ domain: target, success: true, result: res });
        this.logger.info('Federation email sent', { target });
      } catch (e) {
        results.push({ domain: target, success: false, error: e.message });
        this.logger.error('Federation email failed', { target, error: e.message });
      }
    }
    return results;
  }
}
