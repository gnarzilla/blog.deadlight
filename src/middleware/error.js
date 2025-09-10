// src/middleware/error.js - Updated to use existing request_logs table
export const errorMiddleware = async (request, env, ctx, next) => {
  // Handle both old (3 params) and new (4 params) signature
  if (typeof ctx === 'function' && !next) {
    // Old signature: (request, env, next)
    next = ctx;
    ctx = null;
  }
  
  try {
    const response = await next();
    return response;
  } catch (error) {
    console.error('Application error:', {
      message: error.message,
      stack: error.stack,
      url: request.url,
      method: request.method
    });
    
    // Log error to existing request_logs table
    if (ctx && ctx.waitUntil) {
      ctx.waitUntil(
        logErrorToRequestLogs(env, {
          error: error.message,
          stack: error.stack,
          path: request.url,
          method: request.method,
          timestamp: new Date().toISOString()
        })
      );
    }
    
    const errorMap = {
      'Unauthorized': { status: 401, message: 'Unauthorized access' },
      'Not Found': { status: 404, message: 'Resource not found' },
      'Invalid request data': { status: 400, message: 'Invalid request data' },
      'default': { status: 500, message: 'Internal server error' }
    };

    const errorResponse = errorMap[error.message] || errorMap.default;
    
    // Check for development mode
    const isDevelopment = env.ENVIRONMENT !== 'production';
    const responseBody = isDevelopment 
      ? `Error: ${error.message}\n\nStack: ${error.stack}`
      : errorResponse.message;

    return new Response(responseBody, { 
      status: errorResponse.status,
      headers: { 'Content-Type': 'text/plain' }
    });
  }
};

// Log errors to the existing request_logs table
async function logErrorToRequestLogs(env, errorData) {
  try {
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
      errorData.path,
      errorData.method,
      0, // duration
      500, // status_code
      '', // user_agent
      '', // ip
      '', // referer
      '', // country
      `${errorData.error}: ${errorData.stack}`
    ).run();
  } catch (e) {
    console.error('Failed to log error:', e);
  }
}