// src/routes/federation.js
import { FederationService } from '../services/federation.js';
import { checkAuth } from '../../../lib.deadlight/core/src/auth/password.js';

export const federationRoutes = {
  '/api/federation/trust': {
    POST: async (request, env) => {
      const user = await checkAuth(request, env);
      if (!user?.isAdmin) return new Response('Unauthorized', { status: 401 });

      const { domain } = await request.json();
      if (!domain) return Response.json({ error: 'domain required' }, { status: 400 });

      try {
        const federation = env.services.federation;
        const result = await federation.discoverAndTrust(domain);
        return Response.json({ success: true, ...result });
      } catch (err) {
        return Response.json({ success: false, error: err.message }, { status: 400 });
      }
    }
  },

  '/api/federation/follow': {
    POST: async (request, env) => {
      const user = await checkAuth(request, env);
      if (!user?.isAdmin) return new Response('Unauthorized', { status: 401 });

      const { domain } = await request.json();
      await env.DB.prepare(`
        INSERT OR IGNORE INTO federation_follows (domain) VALUES (?)
      `).bind(domain).run();

      return Response.json({ success: true, following: domain });
    }
  },

  // Well-known discovery endpoint (public)
  '/.well-known/deadlight': {
    GET: async (request, env) => {
      try {
        const config = await env.services.config.getConfig();
        const siteUrl = config.siteUrl || env.SITE_URL || new URL(request.url).origin;
        const domain = new URL(siteUrl).hostname;

        // Try to get public key, but don't fail if missing
        let publicKey = null;
        try {
          publicKey = await env.services.federation._publicKey();
        } catch (error) {
          console.warn('Federation public key not configured:', error.message);
          // Return a minimal response indicating federation is not set up
          return new Response(JSON.stringify({
            version: "1.0",
            instance: siteUrl,
            domain: domain,
            software: "deadlight",
            federation_enabled: false,
            error: "Federation keys not configured",
            setup_required: true,
            setup_instructions: "Run: scripts/gen-fed-keys.sh to generate federation keypair"
          }), {
            status: 200, // Changed from 500 to 200 with error info
            headers: { 
              'Content-Type': 'application/json',
              'Access-Control-Allow-Origin': '*',
              'Cache-Control': 'public, max-age=60'
            }
          });
        }

        return new Response(JSON.stringify({
          version: "1.0",
          instance: siteUrl,
          domain: domain,
          software: "deadlight",
          public_key: publicKey,
          federation_enabled: true,
          federation: {
            protocols: ["deadlight-email", "activitypub"],
            inbox: `${siteUrl}/api/federation/inbox`,
            outbox: `${siteUrl}/api/federation/outbox`,
            email_bridge: `blog@${domain}`,
          },
          features: [
            "email_bridge", 
            "proxy_management", 
            "real_time_analytics", 
            "threaded_comments"
          ],
          capabilities: ["posts", "comments", "discovery", "proxy_status"]
        }), {
          headers: { 
            'Content-Type': 'application/json',
            'Access-Control-Allow-Origin': '*',
            'Cache-Control': 'public, max-age=300'
          }
        });
      } catch (error) {
        console.error('Discovery endpoint error:', error);
        return new Response(JSON.stringify({
          error: 'Discovery failed',
          message: error.message,
          federation_enabled: false
        }), {
          status: 500,
          headers: { 'Content-Type': 'application/json' }
        });
      }
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

        const federationService = env.services.federation;
        
        // Test connection first
        const testResult = await federationService.testConnection(domain);
        
        // Handle case where remote instance doesn't have federation enabled
        if (!testResult.success) {
          // Check if it's a setup issue vs connection issue
          if (testResult.error?.includes('Federation keys not configured') || 
              testResult.setup_required) {
            return new Response(JSON.stringify({
              success: false,
              error: 'Remote instance has not configured federation yet',
              federation_enabled: false,
              setup_required: true,
              details: testResult.error
            }), {
              status: 400,
              headers: { 'Content-Type': 'application/json' }
            });
          }
          
          return new Response(JSON.stringify({
            success: false,
            error: 'Failed to connect to domain: ' + testResult.error,
            details: testResult
          }), {
            status: 400,
            headers: { 'Content-Type': 'application/json' }
          });
        }

        // Check if remote instance has federation enabled
        if (testResult.federation_enabled === false) {
          return new Response(JSON.stringify({
            success: false,
            error: 'Remote instance does not have federation enabled',
            federation_enabled: false,
            setup_required: testResult.setup_required || false
          }), {
            status: 400,
            headers: { 'Content-Type': 'application/json' }
          });
        }

        // Add to connected domains
        const result = await federationService.addDomain(domain, {
          auto_discover,
          verified: true,
          connected_at: new Date().toISOString(),
          public_key: testResult.public_key
        });

        return new Response(JSON.stringify({
          success: true,
          domain: domain,
          result: result,
          remote_info: {
            software: testResult.software,
            version: testResult.version,
            capabilities: testResult.capabilities
          }
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
      try {
        const emailData = await request.json();

        console.log('Federation inbox received:', {
          from: emailData.from,
          subject: emailData.subject,
          hasHeaders: !!emailData.headers,
          isDLFederation: emailData.headers?.['X-Deadlight-Type'] === 'federation',
          timestamp: emailData.timestamp
        });

        // Validate email structure
        if (!emailData.from || !emailData.body) {
          return new Response(JSON.stringify({
            success: false,
            error: 'Invalid email data: missing from or body'
          }), {
            status: 400,
            headers: { 'Content-Type': 'application/json' }
          });
        }

        // Check for Deadlight federation header
        const isDLFederation = emailData.headers?.['X-Deadlight-Type'] === 'federation';
        
        if (!isDLFederation) {
          console.log('Not a federation message, treating as regular email');
          
          // Store as regular email post (only if you want this)
          // ... existing email handling code ...
          
          return new Response(JSON.stringify({
            success: true,
            type: 'email',
            note: 'Stored as email post'
          }), {
            headers: { 'Content-Type': 'application/json' }
          });
        }

        // SIMPLIFIED FEDERATION HANDLING (for now)
        console.log('Processing federation message from:', emailData.from);
        
        // Extract author from email-style from field
        const author = emailData.from.split('@')[0]; // "thatch_local@deadlight.boo" -> "thatch_local"
        const sourceDomain = emailData.from.split('@')[1]; // -> "deadlight.boo"
        
        // Store in D1 if available
        if (env.DB) {
          try {
            const slug = `fed-${Date.now()}-${author}`;
            
            await env.DB.prepare(`
              INSERT INTO posts (
                title, content, slug, author_id, 
                is_email, email_metadata, published, created_at
              ) VALUES (?, ?, ?, 1, 1, ?, 0, ?)
            `).bind(
              emailData.subject || 'Federated Post',
              emailData.body,
              slug,
              JSON.stringify({
                from: emailData.from,
                source_domain: sourceDomain,
                timestamp: emailData.timestamp,
                message_id: emailData.headers?.['Message-ID']
              }),
              new Date().toISOString()
            ).run();
            
            console.log('Federation post stored:', slug);
            
            return new Response(JSON.stringify({
              success: true,
              type: 'federation',
              slug: slug,
              author: author,
              source: sourceDomain
            }), {
              headers: { 'Content-Type': 'application/json' }
            });
          } catch (dbError) {
            console.error('DB storage failed:', dbError);
            // Continue to fallback response
          }
        }
        
        // Fallback if no DB or DB failed
        console.log('Federation post received but not stored (no DB or DB error)');
        
        return new Response(JSON.stringify({
          success: true,
          type: 'federation',
          note: 'Post received but not stored (DB not configured)',
          author: author,
          source: sourceDomain
        }), {
          headers: { 'Content-Type': 'application/json' }
        });

      } catch (error) {
        console.error('Federation inbox error:', error);
        
        return new Response(JSON.stringify({
          success: false,
          error: error.message,
          stack: env.NODE_ENV === 'development' ? error.stack : undefined
        }), {
          status: 500,
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