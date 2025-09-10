// src/routes/router.js - New unified router
export class Router {
  constructor() {
    this.routes = new Map();
    this.globalMiddleware = [];
    this.routeMiddleware = new Map(); // Store route-specific middleware
  }
  
  // Add global middleware
  use(middleware) {
    if (typeof middleware !== 'function') {
      throw new Error('Middleware must be a function');
    }
    this.globalMiddleware.push(middleware);
    return this;
  }

  // Register route with optional middleware
  register(path, handlers, middleware = []) {
    const routePattern = path.replace(/\/:(\w+)/g, '/(?<$1>[^/]+)');
    const regex = new RegExp(`^${routePattern}$`);
    
    this.routes.set(routePattern, {
      pattern: regex,
      handlers,
      path // Store original path for debugging
    });
    
    // Store route-specific middleware
    if (middleware.length > 0) {
      this.routeMiddleware.set(routePattern, middleware);
    }
  }

  // Register multiple routes with shared middleware
  group(middleware, routeRegistrar) {
    const groupRouter = {
      register: (path, handlers) => {
        this.register(path, handlers, middleware);
      }
    };
    routeRegistrar(groupRouter);
  }

  async handle(request, env, ctx) {
    const url = new URL(request.url);
    const pathname = url.pathname;
    
    // Find matching route
    let matchedRoute = null;
    let routeMiddleware = [];
    let params = {};
    
    for (const [pattern, route] of this.routes) {
      const match = pathname.match(route.pattern);
      if (match) {
        const handler = route.handlers[request.method];
        if (handler) {
          matchedRoute = handler;
          params = match.groups || {};
          routeMiddleware = this.routeMiddleware.get(pattern) || [];
          break;
        }
      }
    }

    if (!matchedRoute) {
      return new Response('Not Found', { status: 404 });
    }

    // Enhance request with route info
    request.params = params;
    request.query = Object.fromEntries(url.searchParams);
    request.matchedPath = pathname;

    // Build complete middleware chain
    const middlewareChain = [
      ...this.globalMiddleware,
      ...routeMiddleware
    ];

    // Create executor that runs the middleware chain
    const execute = async (index = 0) => {
      if (index < middlewareChain.length) {
        const middleware = middlewareChain[index];
        return await middleware(request, env, ctx, () => execute(index + 1));
      }
      // All middleware passed, execute the route handler
      return await matchedRoute(request, env, ctx);
    };

    try {
      return await execute();
    } catch (error) {
      // Let error middleware handle it if it exists
      throw error;
    }
  }
}