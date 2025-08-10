// src/services/config.js - Update with better error handling
import { SettingsModel } from '../../../lib.deadlight/core/src/db/models/index.js';

class ConfigService {
  constructor() {
    this.cache = new Map();
    this.cacheExpiry = new Map();
    this.CACHE_TTL = 5 * 60 * 1000; // 5 minutes
  }

  async getConfig(db) {
    const cacheKey = 'site_config';
    const now = Date.now();
    
    // Return cached config if still valid
    if (this.cache.has(cacheKey) && this.cacheExpiry.get(cacheKey) > now) {
      return this.cache.get(cacheKey);
    }

    try {
      const settingsModel = new SettingsModel(db);
      const dbSettings = await settingsModel.getAll();
      
      console.log('Retrieved settings from DB:', dbSettings); // Debug log
      
      // Merge with defaults - ensure no undefined values
      const config = {
        title: dbSettings.site_title || 'deadlight.boo',
        description: dbSettings.site_description || 'A minimal blog framework',
        postsPerPage: parseInt(dbSettings.posts_per_page) || 10, // Ensure it's a number
        dateFormat: dbSettings.date_format || 'M/D/YYYY',
        timezone: dbSettings.timezone || 'UTC',
        enableRegistration: dbSettings.enable_registration || false,
        requireLoginToRead: dbSettings.require_login_to_read || false,
        maintenanceMode: dbSettings.maintenance_mode || false
      };

      console.log('Final config object:', config); // Debug log

      // Cache the result
      this.cache.set(cacheKey, config);
      this.cacheExpiry.set(cacheKey, now + this.CACHE_TTL);
      
      return config;
    } catch (error) {
      console.error('Error loading config from database:', error);
      
      // Return static fallback config with guaranteed values
      return {
        title: 'deadlight.boo',
        description: 'A minimal blog framework',
        postsPerPage: 10,
        dateFormat: 'M/D/YYYY',
        timezone: 'UTC',
        enableRegistration: false,
        requireLoginToRead: false,
        maintenanceMode: false
      };
    }
  }

  // Clear cache when settings are updated
  clearCache() {
    this.cache.clear();
    this.cacheExpiry.clear();
  }

  // Get a single setting with caching
  async getSetting(db, key, defaultValue = null) {
    try {
      const settingsModel = new SettingsModel(db);
      return await settingsModel.get(key, defaultValue);
    } catch (error) {
      console.error(`Error getting setting ${key}:`, error);
      return defaultValue;
    }
  }
}

// Export singleton
export const configService = new ConfigService();
