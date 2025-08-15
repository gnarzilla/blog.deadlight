// Utility to extract client IP from request
function getClientIP(request) {
  return request.headers.get('cf-connecting-ip') || 
         request.headers.get('x-real-ip') || 
         request.headers.get('x-forwarded-for') || 
         'unknown';
}

// Create the logs table if it doesn't exist
const initLogsTable = async (db) => {
  await db.prepare(`
    CREATE TABLE IF NOT EXISTS request_logs (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
      path TEXT NOT NULL,
      method TEXT NOT NULL,
      duration INTEGER NOT NULL,
      status_code INTEGER,
      user_agent TEXT,
      ip TEXT,
      referer TEXT,
      country TEXT,
      error TEXT
    )
  `).run();
};

// Separate function to log the completed request
export const logRequest = async (request, response, env) => {
  try {
    const duration = Date.now() - request.timing.startTime;
    const analytics = request.analytics || {};
    
    await env.DB.prepare(`
      INSERT INTO request_logs (
        path,
        method,
        duration,
        status_code,
        user_agent,
        ip,
        referer,
        country,
        error
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).bind(
      analytics.path,
      analytics.method,
      duration,
      response?.status || 500,
      analytics.userAgent,
      analytics.ip,
      analytics.referer,
      analytics.country,
      response?.ok ? null : (response?.statusText || 'Unknown error')
    ).run();

  } catch (error) {
    console.error('Error logging request:', error);
  }
};

export const loggingMiddleware = async (request, env, next) => {
  const startTime = Date.now();
  const url = new URL(request.url);
  
  try {
    // Initialize logs table if needed
    await initLogsTable(env.DB);
    
    // Collect request data (avoid body)
    const requestData = {
      path: url.pathname,
      method: request.method,
      userAgent: request.headers.get('user-agent'),
      ip: getClientIP(request),
      referer: request.headers.get('referer') || '',
      country: request.headers.get('cf-ipcountry') || 'unknown'
    };
    
    // Add analytics data to request (no body access)
    request.analytics = requestData;
    request.timing = { startTime };
    
    // Call the next middleware/handler
    const response = await next();
    
    // Log the completed request
    const duration = Date.now() - startTime;
    
    if (response && typeof response.status === 'number') {
      await logRequest(request, response, env);
    } else {
      await logRequest(request, { status: 500, ok: false, statusText: 'Invalid response' }, env);
      console.warn('Response undefined or invalid, logged with status 500', { path: requestData.path });
    }
    
    return response;
    
  } catch (error) {
    console.error('Logging middleware error:', error);
    const fallbackResponse = await next();
    return fallbackResponse || new Response('Internal Server Error', { status: 500 });
  }
};