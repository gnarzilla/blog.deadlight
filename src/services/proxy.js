// src/services/proxy.js
export class ProxyService {
  constructor(configService) {
    this.config = configService;

    this.circuit = {
      failures: 0,
      lastFailure: null,
      state: 'CLOSED',
      max: 3,
      reset: 30000, // 30 seconds
    };

    this.cache = { data: null, ts: null, ttl: 5000 };
  }

  // --- Circuit Breaker ---
  isCircuitOpen() {
    if (this.circuit.state === 'OPEN') {
      if (this.circuit.lastFailure && Date.now() - this.circuit.lastFailure > this.circuit.reset) {
        this.circuit.state = 'HALF_OPEN';
        return false;
      }
      return true;
    }
    return false;
  }

  recordSuccess() {
    this.circuit.failures = 0;
    this.circuit.state = 'CLOSED';
  }

  recordFailure() {
    this.circuit.failures++;
    this.circuit.lastFailure = Date.now();
    if (this.circuit.failures >= this.circuit.max) {
      this.circuit.state = 'OPEN';
    }
  }

  getCircuitState() {
    return {
      state: this.circuit.state,
      failures: this.circuit.failures,
      isOpen: this.isCircuitOpen(),
      lastFailure: this.circuit.lastFailure,
    };
  }

  // --- Low-level request ---
  async _req(endpoint, opts = {}, retries = 2) {
    const base = (await this.config.getConfig()).proxyUrl;
    if (this.isCircuitOpen()) throw new Error('Circuit breaker is OPEN');

    const url = `${base}${endpoint}`;

    for (let i = 0; i <= retries; i++) {
      try {
        const ctrl = new AbortController();
        const tid = setTimeout(() => ctrl.abort(), 8000);
        const res = await fetch(url, {
          signal: ctrl.signal,
          headers: { 'Content-Type': 'application/json', 'User-Agent': 'Deadlight/4.0' },
          ...opts,
        });
        clearTimeout(tid);

        if (!res.ok) throw new Error(`${res.status} ${await res.text()}`);

        this.recordSuccess();
        return await res.json();
      } catch (e) {
        if (i === retries) {
          this.recordFailure();
          throw e;
        }
        await new Promise(r => setTimeout(r, 2 ** i * 1000));
      }
    }
  }

  // --- Public API ---
  async healthCheck() {
    try {
      const data = await this._req('/api/health');
      return { proxy_connected: true, ...data };
    } catch {
      return { proxy_connected: false };
    }
  }

  async sendEmail(data) {
    return this._req('/api/email/send', { method: 'POST', body: JSON.stringify(data) });
  }

  async sendSms(data) {
    return this._req('/api/sms/send', { method: 'POST', body: JSON.stringify(data) });
  }

  
  async verify(token) {
    if (!token) return { valid: false };

    try {
      const base = (await this.config.getConfig()).proxyUrl;
      const url = `${base}/api/auth/verify`;

      const response = await fetch(url, {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json',
          'User-Agent': 'Deadlight-Blog/4.0',
        },
      });

      if (!response.ok) {
        console.warn('Proxy verify failed with status:', response.status);
        return { valid: false };
      }

       const data = await response.json();
       return {
         valid: true,
         userId: data.user_id,
         username: data.username,
         isAdmin: data.is_admin || false,
       };
    } catch (err) {
      // Network errors, timeouts, etc. → treat as invalid
      console.warn('Proxy verify failed (network):', err.message);
       return { valid: false };
     }
   }

  // Auth methods
  async login(username, password) {
      const baseUrl = await this.getBaseUrl();
      const response = await fetch(`${baseUrl}/api/auth/login`, {
      method: 'POST',
      headers: { 
          'Content-Type': 'application/json',
          'X-Real-IP': this.getRealIP()
      },
      body: JSON.stringify({ username, password })
      });
      
      const data = await response.json();
    
      if (!response.ok) {
      if (response.status === 429) throw new Error('Too many login attempts. Please try again later.');
      if (response.status === 401) throw new Error('Invalid credentials');
      throw new Error(data.error || 'Login failed');
      }
    
      this.storeToken(data.token);
    
      return { success: true, token: data.token, userId: data.user_id };
  }

  async logout() {
      const token = this.getToken();
      if (!token) return;
    
      const baseUrl = await this.getBaseUrl();
      await fetch(`${baseUrl}/api/auth/logout`, {
      method: 'POST',
      headers: {
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json'
      }
      });
    
      this.clearToken();
  }
}