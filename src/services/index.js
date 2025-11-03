// src/services/index.js
import { ConfigService } from './config.js';        // ← class name
import { ProxyService } from './proxy.js';
import { QueueService } from './queue.js';
import { FederationService } from './federation.js';
import { ModerationService } from './moderation.js';

export function initServices(env) {
  // 1. Config – the *only* thing that touches the DB directly
  const config = new ConfigService(env.DB);

  // 2. Proxy – needs config (for PROXY_URL, etc.)
  const proxy = new ProxyService(config);

  // 3. Queue – needs env, proxy, and config; federation injected later
  const queue = new QueueService(env, proxy, null, config);

  // 4. Federation – full dependencies
  const federation = new FederationService(env, config, proxy, queue);

  // 5. Moderation – only needs config
  const moderation = new ModerationService(config);

  // Close the circular reference
  queue.federation = federation;

  return { config, proxy, queue, federation, moderation };
}