// middleware/analytics.js
export async function analyticsMiddleware(request, env, ctx, next) {
  const startTime = Date.now();
  const url = new URL(request.url);
  
  const analytics = {
    path: url.pathname,
    method: request.method,
    startTime,
    userAgent: request.headers.get('user-agent'),
    ip: request.headers.get('cf-connecting-ip') || request.headers.get('x-forwarded-for'),
    referer: request.headers.get('referer'),
    country: request.cf?.country || 'unknown'
  };

  try {
    // Continue with the request
    const response = await next(request, env, ctx);
    
    // Log analytics after response
    const duration = Date.now() - startTime;
    
    // Use ctx.waitUntil if available, otherwise just await
    const logPromise = logAnalytics(env, {
      ...analytics,
      status: response.status,
      duration,
      timestamp: new Date().toISOString()
    });
    
    if (ctx && ctx.waitUntil) {
      ctx.waitUntil(logPromise);
    } else {
      // Fallback for when ctx isn't available (like in development)
      logPromise.catch(err => console.error('Analytics logging failed:', err));
    }

    // Add timing header
    const newResponse = new Response(response.body, response);
    newResponse.headers.set('X-Response-Time', `${duration}ms`);
    
    return newResponse;
  } catch (error) {
    // Log error analytics
    const duration = Date.now() - startTime;
    const logPromise = logAnalytics(env, {
      ...analytics,
      status: 500,
      duration,
      error: error.message,
      timestamp: new Date().toISOString()
    });
    
    if (ctx && ctx.waitUntil) {
      ctx.waitUntil(logPromise);
    } else {
      logPromise.catch(err => console.error('Analytics logging failed:', err));
    }
    
    throw error;
  }
}

async function logAnalytics(env, data) {
  try {
    // Only log if we have a storage mechanism
    if (!env.RATE_LIMIT && !env.DB) {
      console.log('Analytics:', data);
      return;
    }
    
    // Option 1: Store in KV with daily buckets
    if (env.RATE_LIMIT) {
      const key = `analytics:${new Date().toISOString().split('T')[0]}:${Date.now()}`;
      await env.RATE_LIMIT.put(key, JSON.stringify(data), {
        expirationTtl: 30 * 24 * 60 * 60 // 30 days
      });
    }
    
    // Option 2: Store in D1 (if you have an analytics table)
    // if (env.DB) {
    //   await env.DB.prepare(`
    //     INSERT INTO analytics (path, method, status, duration, ip, country, timestamp)
    //     VALUES (?, ?, ?, ?, ?, ?, ?)
    //   `).bind(
    //     data.path, data.method, data.status, data.duration, 
    //     data.ip, data.country, data.timestamp
    //   ).run();
    // }
    
  } catch (error) {
    console.error('Failed to log analytics:', error);
  }
}