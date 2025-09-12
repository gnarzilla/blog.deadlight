// src/middleware/analytics.js - D1-based version
export async function analyticsMiddleware(request, env, ctx, next) {
  // Skip analytics for health checks
  const url = new URL(request.url);
  if (url.pathname.startsWith('/api/health') || 
      url.pathname.startsWith('/api/status')) {
    return next();
  }

  const startTime = Date.now();
  
  const analytics = {
    path: url.pathname,
    method: request.method,
    userAgent: request.headers.get('user-agent'),
    ip: request.headers.get('cf-connecting-ip') || request.headers.get('x-forwarded-for'),
    referer: request.headers.get('referer'),
    country: request.cf?.country || 'unknown',
    timestamp: new Date().toISOString()
  };

  try {
    const response = await next();
    const duration = Date.now() - startTime;
    
    // Log analytics to D1 asynchronously
    if (ctx && ctx.waitUntil && env.DB) {
      ctx.waitUntil(
        logAnalyticsToD1(env, {
          ...analytics,
          status: response.status,
          duration
        })
      );
    }

    // Add timing header
    const newHeaders = new Headers(response.headers);
    newHeaders.set('X-Response-Time', `${duration}ms`);
    
    return new Response(response.body, {
      status: response.status,
      statusText: response.statusText,
      headers: newHeaders
    });
    
  } catch (error) {
    const duration = Date.now() - startTime;
    
    if (ctx && ctx.waitUntil && env.DB) {
      ctx.waitUntil(
        logAnalyticsToD1(env, {
          ...analytics,
          status: 500,
          duration,
          error: error.message
        })
      );
    }
    
    throw error;
  }
}

async function ensureAnalyticsTable(env) {
  try {
    await env.DB.prepare(`
      CREATE TABLE IF NOT EXISTS analytics (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
        path TEXT NOT NULL,
        method TEXT NOT NULL,
        status INTEGER,
        duration INTEGER,
        ip TEXT,
        country TEXT,
        user_agent TEXT,
        referer TEXT,
        error TEXT,
        date_bucket TEXT GENERATED ALWAYS AS (date(timestamp)) STORED,
        hour_bucket INTEGER GENERATED ALWAYS AS (strftime('%H', timestamp)) STORED
      )
    `).run();
    
    // Create indexes
    await env.DB.prepare(`
      CREATE INDEX IF NOT EXISTS idx_analytics_timestamp ON analytics(timestamp);
    `).run();
    
    await env.DB.prepare(`
      CREATE INDEX IF NOT EXISTS idx_analytics_path ON analytics(path);
    `).run();
    
  } catch (error) {
    console.error('Failed to create analytics table:', error);
  }
}

export async function getTopPaths(env, days = 7, limit = 10) {
  const startDate = new Date();
  startDate.setDate(startDate.getDate() - days);
  
  const results = await env.DB.prepare(`
    SELECT 
      path,
      COUNT(*) as hit_count,
      AVG(duration) as avg_duration,
      COUNT(DISTINCT ip) as unique_visitors
    FROM analytics
    WHERE datetime(timestamp) >= datetime(?)
    GROUP BY path
    ORDER BY hit_count DESC
    LIMIT ?
  `).bind(startDate.toISOString(), limit).all();
  
  return results.results;
}

export async function getHourlyTraffic(env, days = 1) {
  const startDate = new Date();
  startDate.setDate(startDate.getDate() - days);
  
  const results = await env.DB.prepare(`
    SELECT 
      hour_bucket as hour,
      COUNT(*) as requests,
      COUNT(DISTINCT ip) as unique_visitors
    FROM analytics
    WHERE datetime(timestamp) >= datetime(?)
    GROUP BY hour_bucket
    ORDER BY hour_bucket
  `).bind(startDate.toISOString()).all();
  
  return results.results;
}

export async function getCountryStats(env, days = 7) {
  const startDate = new Date();
  startDate.setDate(startDate.getDate() - days);
  
  const results = await env.DB.prepare(`
    SELECT 
      country,
      COUNT(*) as requests,
      COUNT(DISTINCT ip) as unique_visitors
    FROM analytics
    WHERE datetime(timestamp) >= datetime(?) AND country != 'unknown'
    GROUP BY country
    ORDER BY requests DESC
    LIMIT 20
  `).bind(startDate.toISOString()).all();
  
  return results.results;
}

async function logAnalyticsToD1(env, data) {
  try {
    // Ensure table exists
    await ensureAnalyticsTable(env);
    
    // Insert analytics record
    await env.DB.prepare(`
      INSERT INTO analytics (
        path, method, status, duration, 
        ip, country, user_agent, referer, error
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).bind(
      data.path,
      data.method,
      data.status,
      data.duration,
      data.ip,
      data.country,
      data.userAgent,
      data.referer,
      data.error || null
    ).run();
    
  } catch (error) {
    console.error('Failed to log analytics:', error);
  }
}

export async function getAnalyticsSummary(env, days = 7) {
  try {
    await ensureAnalyticsTable(env);
    
    const startDate = new Date();
    startDate.setDate(startDate.getDate() - days);
    
    const result = await env.DB.prepare(`
      SELECT 
        COUNT(*) as total_requests,
        COUNT(DISTINCT ip) as unique_visitors,
        AVG(duration) as avg_duration,
        MAX(duration) as max_duration,
        SUM(CASE WHEN status >= 400 THEN 1 ELSE 0 END) as error_count
      FROM analytics
      WHERE timestamp >= ?
    `).bind(startDate.toISOString()).first();
    
    return result || {
      total_requests: 0,
      unique_visitors: 0,
      avg_duration: 0,
      max_duration: 0,
      error_count: 0
    };
  } catch (error) {
    console.error('Analytics summary error:', error);
    return {
      total_requests: 0,
      unique_visitors: 0,
      avg_duration: 0,
      max_duration: 0,
      error_count: 0
    };
  }
}