// src/routes/federation.js
import { FederationService } from '../services/federation.js';

export const federationRoutes = {
  // Well-known discovery endpoint (public)
  '/.well-known/deadlight': {
    GET: async (request, env) => {
      const federationService = new FederationService(env);
      return new Response(JSON.stringify({
        version: "1.0",
        instance: federationService.getDomain(),
        software: "deadlight",
        federation: {
          protocols: ["deadlight-email", "activitypub"],
          inbox: `${env.SITE_URL}/api/federation/inbox`,
          outbox: `${env.SITE_URL}/api/federation/outbox`,
          email_bridge: `blog@${federationService.getDomain()}`,
          public_key: await federationService.getPublicKey()
        },
        features: ["email_bridge", "proxy_management", "real_time_analytics", "threaded_comments"],
        capabilities: ["posts", "comments", "discovery", "proxy_status"]
      }), {
        headers: { 'Content-Type': 'application/json' }
      });
    }
  },

  // Public outbox for federation discovery
  '/api/federation/outbox': {
    GET: async (request, env) => {
      const federationService = new FederationService(env);
      const url = new URL(request.url);
      const limit = parseInt(url.searchParams.get('limit')) || 20;
      
      const posts = await federationService.getFederatedPosts(limit);
      
      return new Response(JSON.stringify({
        instance: federationService.getDomain(),
        posts: posts.map(post => ({
          id: post.id,
          title: post.title,
          content: post.content.substring(0, 500) + (post.content.length > 500 ? '...' : ''),
          author: post.author,
          published_at: post.published_at,
          source_url: `${env.SITE_URL}/post/${post.id}`,
          full_url: `${env.SITE_URL}/post/${post.id}`
        }))
      }), {
        headers: { 'Content-Type': 'application/json' }
      });
    }
  },

  // Connect to federation domain (admin only)
  '/api/federation/connect': {
    POST: async (request, env) => {
      try {
        const body = await request.json();
        const { domain, auto_discover = true } = body;
        
        if (!domain) {
          return new Response(JSON.stringify({
            success: false,
            error: 'Domain parameter required'
          }), {
            status: 400,
            headers: { 'Content-Type': 'application/json' }
          });
        }

        console.log(`Attempting to connect to federation domain: ${domain}`);
        
        // Validate domain format
        if (!/^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/.test(domain)) {
          return new Response(JSON.stringify({
            success: false,
            error: 'Invalid domain format'
          }), {
            status: 400,
            headers: { 'Content-Type': 'application/json' }
          });
        }

        const federationService = new FederationService(env);
        
        // Test connection first
        const testResult = await federationService.testConnection(domain);
        if (!testResult.success) {
          return new Response(JSON.stringify({
            success: false,
            error: 'Failed to connect to domain: ' + testResult.error
          }), {
            status: 400,
            headers: { 'Content-Type': 'application/json' }
          });
        }

        // Add to connected domains
        const result = await federationService.addDomain(domain, {
          auto_discover,
          verified: true,
          connected_at: new Date().toISOString()
        });

        return new Response(JSON.stringify({
          success: true,
          domain: domain,
          result: result
        }), {
          headers: { 'Content-Type': 'application/json' }
        });

      } catch (error) {
        console.error('Federation connect error:', error);
        return new Response(JSON.stringify({
          success: false,
          error: 'Internal server error: ' + error.message
        }), {
          status: 500,
          headers: { 'Content-Type': 'application/json' }
        });
      }
    }
  },

  // Federation inbox (protected - requires API auth)
  '/api/federation/inbox': {
    POST: async (request, env) => {
      const federationService = new FederationService(env);
      const data = await request.json();
      
      try {
        const result = await federationService.processIncomingFederation(data);
        return new Response(JSON.stringify(result), {
          headers: { 'Content-Type': 'application/json' }
        });
      } catch (error) {
        return new Response(JSON.stringify({
          success: false,
          error: error.message
        }), {
          status: 400,
          headers: { 'Content-Type': 'application/json' }
        });
      }
    }
  },

  // Federation queue management (admin only)
  '/api/federation/queue': {
    GET: async (request, env) => {
      const federationService = new FederationService(env);
      const result = await federationService.processFederationQueue();
      return new Response(JSON.stringify(result), {
        headers: { 'Content-Type': 'application/json' }
      });
    },
    
    POST: async (request, env) => {
      const { postId, targetDomains } = await request.json();
      const federationService = new FederationService(env);
      const result = await federationService.queueFederatedPost(postId, targetDomains);
      return new Response(JSON.stringify(result), {
        headers: { 'Content-Type': 'application/json' }
      });
    }
  },

  // Test federation endpoint (admin only)
  '/api/federation/test/*': {
    GET: async (request, env) => {
      try {
        // Extract domain from URL path
        const url = new URL(request.url);
        const pathParts = url.pathname.split('/');
        const domain = pathParts[pathParts.length - 1];
        
        if (!domain || domain === 'test') {
          return new Response(JSON.stringify({
            status: 'failed',
            error: 'Domain parameter required'
          }), {
            status: 400,
            headers: { 'Content-Type': 'application/json' }
          });
        }

        // Get protocol preference from query params
        const useHttp = url.searchParams.get('protocol') === 'http';
        const protocol = useHttp ? 'http' : 'https';
        
        // Determine port based on domain and protocol
        let port = '';
        if (domain.includes('emilyssidepc') || domain.includes('mulley-mooneye')) {
          port = useHttp ? ':8080' : ':8080'; // Your local server setup
        }
        
        // Test different federation endpoints
        const testEndpoints = [
          `${protocol}://${domain}${port}/api/federation/status`,
          `${protocol}://${domain}${port}/.well-known/nodeinfo`,
          `${protocol}://${domain}${port}/api/health`
        ];

        console.log(`Testing federation connection to domain: ${domain}`);
        
        let lastError;
        for (const testUrl of testEndpoints) {
          try {
            console.log(`Attempting connection to: ${testUrl}`);
            
            const response = await fetch(testUrl, {
              method: 'GET',
              headers: {
                'Accept': 'application/json',
                'User-Agent': 'Deadlight-Federation-Test/1.0'
              },
              signal: AbortSignal.timeout(10000) // 10 second timeout
            });
            
            console.log(`Response status: ${response.status}`);
            
            if (response.ok) {
              let responseData;
              try {
                responseData = await response.json();
              } catch (parseError) {
                responseData = { message: 'Server responded but not with JSON' };
              }
              
              return new Response(JSON.stringify({
                status: 'verified',
                domain: domain,
                protocol: protocol,
                endpoint: testUrl,
                response: responseData,
                timestamp: new Date().toISOString()
              }), {
                headers: { 'Content-Type': 'application/json' }
              });
            } else {
              lastError = `HTTP ${response.status}: ${response.statusText}`;
              console.log(`Endpoint ${testUrl} failed: ${lastError}`);
            }
            
          } catch (fetchError) {
            lastError = fetchError.message;
            console.log(`Endpoint ${testUrl} error: ${lastError}`);
            
            // If HTTPS failed due to SSL issues, try HTTP
            if (fetchError.message.includes('SSL') && protocol === 'https') {
              const httpUrl = testUrl.replace('https://', 'http://');
              console.log(`SSL error detected, trying HTTP: ${httpUrl}`);
              
              try {
                const httpResponse = await fetch(httpUrl, {
                  method: 'GET',
                  headers: {
                    'Accept': 'application/json',
                    'User-Agent': 'Deadlight-Federation-Test/1.0'
                  },
                  signal: AbortSignal.timeout(10000)
                });
                
                if (httpResponse.ok) {
                  let responseData;
                  try {
                    responseData = await httpResponse.json();
                  } catch (parseError) {
                    responseData = { message: 'Server responded but not with JSON' };
                  }
                  
                  return new Response(JSON.stringify({
                    status: 'verified',
                    domain: domain,
                    protocol: 'http',
                    endpoint: httpUrl,
                    response: responseData,
                    note: 'HTTPS failed, HTTP succeeded',
                    timestamp: new Date().toISOString()
                  }), {
                    headers: { 'Content-Type': 'application/json' }
                  });
                }
              } catch (httpError) {
                console.log(`HTTP fallback also failed: ${httpError.message}`);
              }
            }
          }
        }

        // All endpoints failed
        return new Response(JSON.stringify({
          status: 'failed',
          domain: domain,
          error: lastError || 'All federation endpoints unreachable',
          attempted_endpoints: testEndpoints,
          timestamp: new Date().toISOString()
        }), {
          status: 500,
          headers: { 'Content-Type': 'application/json' }
        });

      } catch (error) {
        console.error('Federation test handler error:', error);
        return new Response(JSON.stringify({
          status: 'failed',
          error: 'Internal server error: ' + error.message
        }), {
          status: 500,
          headers: { 'Content-Type': 'application/json' }
        });
      }
    }
  }
}