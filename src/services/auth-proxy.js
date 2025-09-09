// blog.deadlight/src/services/auth-proxy.js
export class ProxyAuthService {
  constructor(proxyUrl = 'http://localhost:8080') {
    this.proxyUrl = proxyUrl;
  }
  
  async login(username, password) {
    const response = await fetch(`${this.proxyUrl}/api/auth/login`, {
      method: 'POST',
      headers: { 
        'Content-Type': 'application/json',
        'X-Real-IP': this.getRealIP() // For rate limiting
      },
      body: JSON.stringify({ username, password })
    });
    
    const data = await response.json();
    
    if (!response.ok) {
      if (response.status === 429) {
        throw new Error('Too many login attempts. Please try again later.');
      } else if (response.status === 401) {
        throw new Error('Invalid credentials');
      }
      throw new Error(data.error || 'Login failed');
    }
    
    // Store token in cookie or localStorage
    this.storeToken(data.token);
    
    return {
      success: true,
      token: data.token,
      userId: data.user_id
    };
  }
  
  async verify(token) {
    const response = await fetch(`${this.proxyUrl}/api/auth/verify`, {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${token}`,
        'Content-Type': 'application/json'
      }
    });
    
    if (!response.ok) {
      return { valid: false };
    }
    
    const data = await response.json();
    return {
      valid: true,
      userId: data.user_id,
      username: data.username
    };
  }
  
  async logout() {
    const token = this.getToken();
    if (!token) return;
    
    await fetch(`${this.proxyUrl}/api/auth/logout`, {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${token}`,
        'Content-Type': 'application/json'
      }
    });
    
    this.clearToken();
  }
  
  // Helper methods
  getRealIP() {
    // In Cloudflare Workers, get the real IP
    if (typeof globalThis.CF_CONNECTING_IP !== 'undefined') {
      return globalThis.CF_CONNECTING_IP;
    }
    return '127.0.0.1';
  }
  
  storeToken(token) {
    if (typeof localStorage !== 'undefined') {
      localStorage.setItem('deadlight-token', token);
    }
    // Also set cookie for server-side
    document.cookie = `deadlight-token=${token}; path=/; max-age=3600; SameSite=Strict`;
  }
  
  getToken() {
    if (typeof localStorage !== 'undefined') {
      return localStorage.getItem('deadlight-token');
    }
    // Fallback to cookie
    const match = document.cookie.match(/deadlight-token=([^;]+)/);
    return match ? match[1] : null;
  }
  
  clearToken() {
    if (typeof localStorage !== 'undefined') {
      localStorage.removeItem('deadlight-token');
    }
    document.cookie = 'deadlight-token=; path=/; expires=Thu, 01 Jan 1970 00:00:00 GMT';
  }
}

// Export singleton instance
export const authService = new ProxyAuthService();
