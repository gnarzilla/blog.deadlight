// src/routes/static.js

// Minimal 404 response helper
const minimal404 = () => new Response(null, { 
  status: 404,
  headers: { 'Content-Length': '0' }
});

export const staticRoutes = {
  '/favicon.ico': {
    GET: async (request, env) => {
      try {
        const asset = await env.ASSETS.fetch(new URL('/favicon.ico', request.url));
        
        if (asset.status === 200) {
          return new Response(await asset.arrayBuffer(), {
            headers: {
              'Content-Type': 'image/x-icon',
              'Cache-Control': 'public, max-age=31536000'
            }
          });
        }
        
        // Text-based SVG fallback
        const svgFavicon = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 32 32"><rect width="32" height="32" fill="#1a1a1a"/><text x="16" y="22" text-anchor="middle" fill="#fff" font-family="monospace" font-size="16" font-weight="bold">DL</text></svg>`;
        
        return new Response(svgFavicon, {
          headers: {
            'Content-Type': 'image/svg+xml',
            'Cache-Control': 'public, max-age=86400'
          }
        });
        
      } catch (error) {
        // Return text SVG on error
        const svgFavicon = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 32 32"><rect width="32" height="32" fill="#1a1a1a"/><text x="16" y="22" text-anchor="middle" fill="#fff" font-family="monospace" font-size="16" font-weight="bold">DL</text></svg>`;
        return new Response(svgFavicon, {
          headers: {
            'Content-Type': 'image/svg+xml',
            'Cache-Control': 'public, max-age=3600'
          }
        });
      }
    }
  },

  '/apple-touch-icon.png': {
    GET: async (request, env) => {
      try {
        const asset = await env.ASSETS.fetch(new URL('/apple-touch-icon.png', request.url));
        
        if (asset.status === 200) {
          return new Response(await asset.arrayBuffer(), {
            headers: {
              'Content-Type': 'image/png',
              'Cache-Control': 'public, max-age=31536000'
            }
          });
        }
        
        return minimal404();
      } catch (error) {
        return minimal404();
      }
    }
  },

  // Catch common static file requests with minimal 404s
  '/robots.txt': {
    GET: async (request, env) => {
      try {
        const asset = await env.ASSETS.fetch(new URL('/robots.txt', request.url));
        if (asset.status === 200) {
          return new Response(await asset.text(), {
            headers: {
              'Content-Type': 'text/plain',
              'Cache-Control': 'public, max-age=86400'
            }
          });
        }
        return minimal404();
      } catch (error) {
        return minimal404();
      }
    }
  },

  '/manifest.json': {
    GET: async (request, env) => {
      try {
        const asset = await env.ASSETS.fetch(new URL('/manifest.json', request.url));
        if (asset.status === 200) {
          return new Response(await asset.text(), {
            headers: {
              'Content-Type': 'application/json',
              'Cache-Control': 'public, max-age=86400'
            }
          });
        }
        return minimal404();
      } catch (error) {
        return minimal404();
      }
    }
  }
};