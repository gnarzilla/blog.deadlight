// src/utils/getCurrentUser.js

export async function getCurrentUser(request, env) {
  try {
    // Get session cookie
    const cookie = request.headers.get('Cookie');
    if (!cookie) return null;
    
    const sessionMatch = cookie.match(/session=([^;]+)/);
    if (!sessionMatch) return null;
    
    const sessionId = sessionMatch[1];
    
    // Get session from KV storage
    const sessionData = await env.KV.get(`session:${sessionId}`);
    if (!sessionData) return null;
    
    const session = JSON.parse(sessionData);
    
    // Check if session is expired
    if (new Date(session.expires) < new Date()) {
      // Clean up expired session
      await env.KV.delete(`session:${sessionId}`);
      return null;
    }
    
    // Get full user data from database
    const user = await env.DB.prepare('SELECT * FROM users WHERE id = ?')
      .bind(session.userId)
      .first();
    
    return user;
    
  } catch (error) {
    console.error('Error getting current user:', error);
    return null;
  }
}

// Helper functions that might be useful
export async function requireAuth(request, env) {
  const user = await getCurrentUser(request, env);
  if (!user) {
    return Response.redirect('/login', 302);
  }
  return user;
}

export async function requireAdmin(request, env) {
  const user = await getCurrentUser(request, env);
  if (!user || !user.is_admin) {
    return new Response('Unauthorized', { status: 403 });
  }
  return user;
}