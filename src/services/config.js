// src/services/config.js
import { SettingsModel } from '../../../lib.deadlight/core/src/db/models/settings.js';

export class ConfigService {
  constructor(db) {
    this.db = db;
    this.settingsModel = new SettingsModel(db);
    this.cache = new Map();
    this.CACHE_TTL = 5 * 60 * 1000; // 5 min
  }

  // Full config object (used by blog.js, admin.js, etc.)
  async getConfig() {
    const cacheKey = 'full_config';
    const now = Date.now();

    if (this.cache.has(cacheKey) && (this.cache.get(cacheKey).ts + this.CACHE_TTL) > now) {
      return this.cache.get(cacheKey).data;
    }

    const raw = await this.settingsModel.getAll();
    const config = {
      title: raw.site_title || 'deadlight.boo',
      description: raw.site_description || 'A minimal blog framework',
      postsPerPage: parseInt(raw.posts_per_page) || 10,
      dateFormat: raw.date_format || 'M/D/YYYY',
      timezone: raw.timezone || 'UTC',
      enableRegistration: raw.enable_registration === true,
      requireLoginToRead: raw.require_login_to_read === true,
      maintenanceMode: raw.maintenance_mode === true,
      proxyUrl: raw.proxy_url || 'http://127.0.0.1:8080',
    };

    this.cache.set(cacheKey, { data: config, ts: now });
    return config;
  }

  // Existing methods
  async getSetting(key, fallback = null) {
    try {
      const val = await this.settingsModel.get(key);
      return val ?? fallback;
    } catch {
      return fallback;
    }
  }

  async updateSetting(key, value, type = 'string') {
    const result = await this.settingsModel.set(key, value, type);
    this.cache.clear(); // invalidate
    return result;
  }

  async getModerationKeywords() {
    const raw = await this.getSetting('moderation_keywords', '');
    if (!raw) return [];
    return raw.split(',').map(k => k.trim().toLowerCase()).filter(Boolean);
  }
}