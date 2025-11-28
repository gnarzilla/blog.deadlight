// src/routes/index.js
export class Router {
  constructor() {
    this.routes = new Map();
    this.middlewares = [];
  }
  
  use(middleware) {
    if (typeof middleware !== 'function') {
      throw new Error('Middleware must be a function');
    }
    this.middlewares.push(middleware);
    return this;
  }

  // Enhanced register method with optional middleware
  register(path, handlers, routeMiddleware = []) {
    console.log('Registering route:', path);
    const routePattern = path.replace(/\/:(\w+)/g, '/(?<$1>[^/]+)');
    this.routes.set(routePattern, {
      pattern: new RegExp(`^${routePattern}$`),
      handlers,
      middleware: Array.isArray(routeMiddleware) ? routeMiddleware : [routeMiddleware]
    });
  }

  // Register multiple routes with shared middleware
  group(middleware, registerFunc) {
    const groupRouter = {
      register: (path, handlers) => {
        this.register(path, handlers, middleware);
      }
    };
    registerFunc(groupRouter);
  }

  async handle(request, env, ctx) {
    const url = new URL(request.url);
    const pathname = url.pathname;
    
    console.log('Handling request for path:', pathname);
    console.log('Available routes:', Array.from(this.routes.keys()));

    // Find matching route
    let matchedRoute = null;
    let routeMiddleware = [];
    let params = {};
    
    for (const [_, route] of this.routes) {
      const match = pathname.match(route.pattern);
      if (match) {
        const handler = route.handlers[request.method];
        if (handler) {
          matchedRoute = handler;
          params = match.groups || {};
          routeMiddleware = route.middleware || [];
          break;
        }
      }
    }

    if (!matchedRoute) {
      throw new Error('Not Found');
    }

    // Enhance request with route info
    request.params = params;
    request.query = Object.fromEntries(url.searchParams);

    // Combine global and route-specific middleware
    const allMiddleware = [...this.middlewares, ...routeMiddleware];
    
    // Build the chain from the inside out
    let handler = (req, env, ctx) => matchedRoute(req, env, ctx);
    
    for (let i = allMiddleware.length - 1; i >= 0; i--) {
      const middleware = allMiddleware[i];
      const nextHandler = handler;
      handler = async (req, env, ctx) => {
        return await middleware(req, env, ctx, async () => {
          return await nextHandler(req, env, ctx);
        });
      };
    }

    // Execute the chain with ctx
    return await handler(request, env, ctx);
  }
}