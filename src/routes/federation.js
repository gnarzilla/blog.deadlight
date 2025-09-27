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

  // Federation connection management (admin only)
  '/api/federation/connect': {
    GET: async (request, env) => {
      const federationService = new FederationService(env);
      const connections = await federationService.getConnectedDomains();
      
      return new Response(JSON.stringify({
        connections: connections.map(conn => ({
          domain: conn.domain,
          trust_level: conn.trust_level,
          last_seen: conn.last_seen,
          capabilities: conn.capabilities ? JSON.parse(conn.capabilities) : []
        }))
      }), {
        headers: { 'Content-Type': 'application/json' }
      });
    },
    
    POST: async (request, env) => {
      const { domain, auto_discover = true } = await request.json();
      const federationService = new FederationService(env);
      
      if (auto_discover) {
        try {
          const discoveryUrl = `https://${domain}/.well-known/deadlight`;
          const response = await fetch(discoveryUrl);
          
          if (response.ok) {
            const instanceInfo = await response.json();
            await federationService.establishTrust(
              domain, 
              instanceInfo.federation.public_key, 
              'unverified'
            );
            
            await federationService.discoverDomain(domain);
            
            return new Response(JSON.stringify({
              success: true,
              domain,
              instance_info: instanceInfo,
              status: 'discovery_sent'
            }), {
              headers: { 'Content-Type': 'application/json' }
            });
          }
        } catch (error) {
          // Fall back to manual connection
        }
      }
      
      await federationService.discoverDomain(domain);
      
      return new Response(JSON.stringify({
        success: true,
        domain,
        status: 'discovery_sent_manual'
      }), {
        headers: { 'Content-Type': 'application/json' }
      });
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
  '/api/federation/test': {
    POST: async (request, env) => {
      const federationService = new FederationService(env);
      const result = await federationService.testFederation();
      return new Response(JSON.stringify(result), {
        headers: { 'Content-Type': 'application/json' }
      });
    }
  }
};