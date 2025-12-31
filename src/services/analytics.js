// src/services/analytics.js
import { Logger } from '../../../lib.deadlight/core/src/logging/logger.js';
import { DatabaseError } from '../../../lib.deadlight/core/src/db/base.js'; // Assuming you have a DatabaseError

export class AnalyticsService {
  constructor(db) {
    this.db = db;
    this.logger = new Logger({ context: 'AnalyticsService' });
  }

  // --- Internal Helper for SQL Date Intervals ---
  _getIntervalSql(intervalType, value) {
    // Using D1's strftime and datetime functions directly in the query string
    return `datetime('now', '-${value} ${intervalType}')`;
  }

  // --- Main Dashboard Analytics ---

  /**
   * Fetches the core analytics data for the admin dashboard.
   * Includes daily request stats, browser distribution, and active visitors.
   * @param {number} days - Number of days for daily stats and browser stats.
   * @param {number} activeMinutes - Number of minutes for active visitors.
   * @returns {Promise<{requestStats: Array, browserStats: Array, activeVisitors: number}>}
   */
  async getDashboardAnalytics(days = 7, activeMinutes = 5) {
    try {
      const [requestStatsResult, browserStatsResult, activeVisitorsResult] = await Promise.all([
        this.db.prepare(`
          SELECT 
            date(timestamp) as day,
            COUNT(*) as requests,
            COUNT(DISTINCT ip) as unique_visitors
          FROM analytics
          WHERE timestamp >= ${this._getIntervalSql('day', days)}
          GROUP BY date(timestamp)
          ORDER BY day DESC
        `).all(),
        this.db.prepare(`
          SELECT 
            CASE 
              WHEN user_agent LIKE '%Chrome%' THEN 'Chrome'
              WHEN user_agent LIKE '%Safari%' THEN 'Safari'
              WHEN user_agent LIKE '%Firefox%' THEN 'Firefox'
              ELSE 'Other'
            END as browser,
            COUNT(*) as count
          FROM analytics
          WHERE timestamp >= ${this._getIntervalSql('day', days)}
          GROUP BY browser
          ORDER BY count DESC
        `).all(),
        this.db.prepare(`
          SELECT COUNT(DISTINCT ip) as active
          FROM analytics
          WHERE timestamp >= ${this._getIntervalSql('minute', activeMinutes)}
        `).first()
      ]);

      return {
        requestStats: requestStatsResult.results || [],
        browserStats: browserStatsResult.results || [],
        activeVisitors: activeVisitorsResult?.active || 0,
      };
    } catch (error) {
      this.logger.error('Failed to get dashboard analytics', { error: error.message, stack: error.stack });
      throw new DatabaseError(`Failed to retrieve dashboard analytics: ${error.message}`, 'ANALYTICS_FETCH_ERROR');
    }
  }

  // --- Full Analytics Page Data ---

  /**
   * Fetches a summary of analytics for a given number of days.
   * @param {number} days - Number of days to include in the summary.
   * @returns {Promise<object>}
   */
  async getSummary(days = 7) {
    try {
      const summary = await this.db.prepare(`
        SELECT 
          COUNT(*) as total_requests,
          COUNT(DISTINCT ip) as unique_visitors,
          AVG(duration) as avg_duration,
          MAX(duration) as max_duration,
          SUM(CASE WHEN status >= 400 THEN 1 ELSE 0 END) as error_count
        FROM analytics
        WHERE date(timestamp) >= ${this._getIntervalSql('day', days)}
      `).first();
      return summary || { // Ensure default values if no data
        total_requests: 0, 
        unique_visitors: 0, 
        avg_duration: 0, 
        max_duration: 0,
        error_count: 0 
      };
    } catch (error) {
      this.logger.error('Failed to get analytics summary', { error: error.message, stack: error.stack });
      throw new DatabaseError(`Failed to retrieve analytics summary: ${error.message}`, 'ANALYTICS_FETCH_ERROR');
    }
  }

  /**
   * Fetches hourly traffic data for a given number of days.
   * Uses the 'hour_bucket' column.
   * @param {number} days - Number of days to include in the hourly traffic.
   * @returns {Promise<Array>}
   */
  async getHourlyTraffic(days = 1) {
    try {
      const hourlyTraffic = await this.db.prepare(`
        SELECT 
          hour_bucket as hour,
          COUNT(*) as requests,
          COUNT(DISTINCT ip) as unique_visitors
        FROM analytics
        WHERE date(timestamp) >= ${this._getIntervalSql('day', days)}
        GROUP BY hour_bucket
        ORDER BY hour_bucket
      `).all();
      return hourlyTraffic.results || [];
    } catch (error) {
      this.logger.error('Failed to get hourly traffic', { error: error.message, stack: error.stack });
      throw new DatabaseError(`Failed to retrieve hourly traffic: ${error.message}`, 'ANALYTICS_FETCH_ERROR');
    }
  }

  /**
   * Fetches top paths (most requested URLs) for a given number of days.
   * @param {number} days - Number of days to include.
   * @param {number} limit - Maximum number of top paths to return.
   * @returns {Promise<Array>}
   */
  async getTopPaths(days = 7, limit = 10) {
    try {
      const topPaths = await this.db.prepare(`
        SELECT 
          path,
          COUNT(*) as hit_count,
          AVG(duration) as avg_duration,
          COUNT(DISTINCT ip) as unique_visitors
        FROM analytics
        WHERE date(timestamp) >= ${this._getIntervalSql('day', days)}
        GROUP BY path
        ORDER BY hit_count DESC
        LIMIT ?
      `).bind(limit).all();
      return topPaths.results || [];
    } catch (error) {
      this.logger.error('Failed to get top paths', { error: error.message, stack: error.stack });
      throw new DatabaseError(`Failed to retrieve top paths: ${error.message}`, 'ANALYTICS_FETCH_ERROR');
    }
  }

  /**
   * Fetches country statistics (requests and unique visitors per country).
   * @param {number} days - Number of days to include.
   * @param {number} limit - Maximum number of countries to return.
   * @returns {Promise<Array>}
   */
  async getCountryStats(days = 7, limit = 20) {
    try {
      const countryStats = await this.db.prepare(`
        SELECT 
          country,
          COUNT(*) as requests,
          COUNT(DISTINCT ip) as unique_visitors
        FROM analytics
        WHERE date(timestamp) >= ${this._getIntervalSql('day', days)}
          AND country IS NOT NULL 
          AND country != 'unknown'
        GROUP BY country
        ORDER BY requests DESC
        LIMIT ?
      `).bind(limit).all();
      return countryStats.results || [];
    } catch (error) {
      this.logger.error('Failed to get country stats', { error: error.message, stack: error.stack });
      throw new DatabaseError(`Failed to retrieve country statistics: ${error.message}`, 'ANALYTICS_FETCH_ERROR');
    }
  }

  // --- Debug/Check Endpoints ---

  /**
   * Checks if the analytics table exists.
   * @returns {Promise<boolean>}
   */
  async checkAnalyticsTableExists() {
    try {
      const tableCheck = await this.db.prepare(`
        SELECT name FROM sqlite_master 
        WHERE type='table' AND name='analytics'
      `).first();
      return !!tableCheck;
    } catch (error) {
      this.logger.error('Failed to check analytics table existence', { error: error.message, stack: error.stack });
      throw new DatabaseError(`Failed to check analytics table: ${error.message}`, 'ANALYTICS_CHECK_ERROR');
    }
  }

  /**
   * Gets the schema for the analytics table.
   * @returns {Promise<string|null>}
   */
  async getAnalyticsTableSchema() {
    try {
      const schema = await this.db.prepare(`
        SELECT sql FROM sqlite_master 
        WHERE type='table' AND name='analytics'
      `).first();
      return schema?.sql || null;
    } catch (error) {
      this.logger.error('Failed to get analytics table schema', { error: error.message, stack: error.stack });
      throw new DatabaseError(`Failed to get analytics schema: ${error.message}`, 'ANALYTICS_CHECK_ERROR');
    }
  }

  /**
   * Gets column information for the analytics table.
   * @returns {Promise<Array>}
   */
  async getAnalyticsTableColumns() {
    try {
      const columns = await this.db.prepare(`
        PRAGMA table_info(analytics)
      `).all();
      return columns.results || [];
    } catch (error) {
      this.logger.error('Failed to get analytics table columns', { error: error.message, stack: error.stack });
      throw new DatabaseError(`Failed to get analytics columns: ${error.message}`, 'ANALYTICS_CHECK_ERROR');
    }
  }

  /**
   * Gets the total row count for the analytics table.
   * @returns {Promise<number>}
   */
  async getAnalyticsRowCount() {
    try {
      const countResult = await this.db.prepare(`
        SELECT COUNT(*) as count FROM analytics
      `).first();
      return countResult?.count || 0;
    } catch (error) {
      this.logger.error('Failed to get analytics row count', { error: error.message, stack: error.stack });
      throw new DatabaseError(`Failed to get analytics row count: ${error.message}`, 'ANALYTICS_CHECK_ERROR');
    }
  }

  /**
   * Gets the most recent analytics entries.
   * @param {number} limit - Number of entries to return.
   * @returns {Promise<Array>}
   */
  async getRecentAnalyticsEntries(limit = 5) {
    try {
      const recentEntries = await this.db.prepare(`
        SELECT * FROM analytics ORDER BY timestamp DESC LIMIT ?
      `).bind(limit).all();
      return recentEntries.results || [];
    } catch (error) {
      this.logger.error('Failed to get recent analytics entries', { error: error.message, stack: error.stack });
      throw new DatabaseError(`Failed to get recent analytics entries: ${error.message}`, 'ANALYTICS_FETCH_ERROR');
    }
  }

  // --- Static Utilities ---

  /**
   * Fills in missing hours for hourly traffic data (0-23).
   * @param {Array<object>} hourlyData - The raw hourly traffic data.
   * @returns {Array<object>} Sorted hourly data with all hours present.
   */
  static fillMissingHours(hourlyData) {
    const hoursMap = new Map();
    for (let i = 0; i < 24; i++) {
      hoursMap.set(i, { hour: i, requests: 0, unique_visitors: 0 });
    }
    // Ensure hour is a number before using it as a map key
    (hourlyData || []).forEach(hour => {
      if (typeof hour.hour === 'number') {
        hoursMap.set(hour.hour, hour);
      }
    });
    return Array.from(hoursMap.values()).sort((a, b) => a.hour - b.hour);
  }
}