# Deadlight Edge Blog - Secure, Modular Blog Platform with Integrated Proxy Management

🌐 Live Demo: [deadlight.boo](https://deadlight.boo) | [Separate Instance Deployment](https://thatch-dt.deadlight.boo) | [Other Separate Instance](https://threat-level-midnight.deadlight.boo)

A modular, security-hardened blog platform built on Cloudflare Workers with integrated multi-protocol proxy server management. Features real-time proxy control, email federation capabilities, and everything you need for a truly self-sovereign digital presence.

---

![Main Blog - Dual Screen](https://github.com/gnarzilla/blog.deadlight/blob/374775bddc1948b7fd8cae9bb37ac89dd07b463f/src/assets/blog_dual_nolog.png)

---
### Table of Contents
1.  [Key Features](#key-features)
2.  [Architecture](#architecture-&-design)
3.  [Features](#features)
4.  [Roadmap](#roadmap)
5.  [Getting Started](#getting-started)
6.  [Usage](#usage)
7.  [Extending Deadlight](#extending-deadlight)
8.  [Project Structure](#project-structure)
9.  [License](#license)
10. [Support](#support) 

---

![Admin Dash - Dual Screen](https://github.com/gnarzilla/blog.deadlight/blob/374775bddc1948b7fd8cae9bb37ac89dd07b463f/src/assets/admin_dual.png)

![Proxy/Analytics - Dual Screen](https://github.com/gnarzilla/blog.deadlight/blob/374775bddc1948b7fd8cae9bb37ac89dd07b463f/src/assets/proxy_anal_dual.png)

## Key Features

### **Performance & Content**
- **Near-zero latency**: Deployed on Cloudflare Workers to deliver content globally in milliseconds.
- **D1 Database**: Uses D1 (SQLite at the edge) for fast, low-cost data access.
- **Full Markdown support**: Write posts using a simple, intuitive syntax.
- **SEO-friendly**: Generates clean URLs and post excerpts for better discoverability.

### **Security & Administration**
- **CSRF & Rate Limiting**: All forms and endpoints are protected against common attacks.
- **Enhanced Authentication**: Secure JWT implementation with role-based access control (admin, editor, viewer).
- **Robust Framework**: Includes a comprehensive validation framework, structured logging, and secure headers for a hardened application.
- **User Management**: A dashboard with a user management interface and activity logging.

### Proxy Integration 
- **Real-time Control**: Manage your local infrastructure from any browser.
- **Email Protocol Bridge**: Connect Cloudflare Workers to your self-hosted email server via SMTP/IMAP.
- **Decentralized Federation**: Test blog-to-blog communication and federation with other domains via email protocols.
- **Privacy Proxy**: Manage SOCKS5 proxy access directly from the dashboard.

---

## **Architecture & Design**:
Deadlight is designed as a modular, full-stack application built for maximum flexibility and performance.
- **Modular Architecture**: Shared lib.deadlight library and reusable components enable a clean separation of concerns and a multi-app ecosystem.
- **Text-First**: A deliberate design choice to focus on clean, markdown-based content and avoid the complexities of media management.
- **Project Structure**: A clear directory structure that organizes the main application, shared libraries, and core functionality.

```
deadlight/
├── blog.deadlight/          # Main blog application
│   └── src/
|         ├── assets/        # Static site media
|         ├── config.js
|         ├── index.js       # Main entry & routing
|         ├── middleware/    # Application-level middleware
|         │   ├── analytics.js
|         │   ├── auth.js
|         │   ├── error.js
|         │   └── logging.js
|         ├── routes/        # Route handlers for all endpoints
|         │   ├── admin.js
|         │   ├── auth.js
|         │   ├── blog.js
|         │   ├── inbox.js
|         │   ├── index.js
|         │   ├── proxy.js
|         │   ├── static.js
|         │   ├── styles.js
|         │   └── user.js
|         ├── services/      # Extenal service integration
|         │   ├── config.js
|         │   ├── outbox.js
|         │   └── proxy.js
|         ├── styles/
|         ├── templates/     # HTML templates for all pages
|         │   ├── admin/
|         │   ├── auth/
|         │   ├── base.js
|         │   ├── blog/
|         │   ├── landing.js
|         │   └── user/
|         └── utils/
└── lib.deadlight/          # Shared library
    └── core/
        ├── auth/           # Authentication system
        ├── db/             # Database layer
        ├── security/       # Security features
        └── ...
```

## **Roadmap**
- Post comments - active
- Proxy integration - testing
- email bridge/federation - testing
- plugin system - active
- Integrated locoalized (private) analytice collection and dashboard - beta
- **Active Development**: Full email client/server integration, production deployment guides.

## Quick Start

### Prerequisites
- Cloudflare account (free tier works)
- Node.js 20+
- Wrangler CLI (`npm install -g wrangler`)

### Deploy in 5 minutes

```bash
git clone https://github.com/gnarzilla/blog.deadlight
cd blog.deadlight
npm install

# Create your D1 database:
wrangler d1 create your-db-name

# Initialize the database:
# Local development
wrangler d1 execute your-db-name --local --file=migrations/20250815_schema.sql

# Production
wrangler d1 execute your-db-name --remote --file=migrations/20250815_schema.sql

# Create KV namespace for rate limiting
wrangler kv:namespace create "RATE_LIMIT"

```

### Configure your domain and bindings in wrangler.toml:
```toml
name = "your-domain.tld"
main = "src/index.js"
compatibility_date = "2023-10-20"

# Main domain (landing page)
[[routes]]
pattern = "your-domain.tld/*"
zone_id = "your-zone-id"

# All subdomains (including blog and user subdomains)
[[routes]]
pattern = "*.your-domain.tld/*"
zone_id = "your-zone-ida"

[observability.logs]
enabled = true

[build]
command = "npm install"

# Non-sensitive vars here
[vars]
SITE_URL = "https://your-domain.tld"
ENABLE_QUEUE_PROCESSING = "true"  

[assets]
directory = "./src/static"
binding = "ASSETS"

[[d1_databases]]
binding = "DB"
database_name = "your-db-name"
database_id = "your-database-id"

[[kv_namespaces]]
binding = "RATE_LIMIT"
id = "your-kv-namespace-id"

[env.production]
name = "your-domain"

[env.production.vars]
PROXY_URL = "https://proxy.your-domain.tld"
SITE_URL = "https://your-domanin.tld"
ENABLE_QUEUE_PROCESSING = "true"  # Explicitly set for production

# Copy bindings to production env
[[env.production.d1_databases]]
binding = "DB"
database_name = "your-db-name"
database_id = "your-db-id"

[[env.production.kv_namespaces]]
binding = "RATE_LIMIT"
id = "your-kv-namespace-id"

```

### Configure your local environment in package.json

```json
  GNU nano 7.2                           package.json                                    
{
  "name": "your-worker",
  "version": "1.1.0",
  "description": "Edge-first blog framework",
  "main": "src/index.js",
  "type": "module",
  "dependencies": {
    "marked": "^11.2.0",
    "xss": "^1.0.15"
  },
  "scripts": {
    "build": "node scripts/generate-test-user.js > scripts/seed-db.sql",
    "seed-db": "wrangler d1 execute blog_content --local --file=./scripts/seed-db.sql",
    "seed-db:remote": "wrangler d1 execute blog_content --file=./scripts/seed-db.sql",
    "deploy": "npm run build && wrangler deploy",
    "deploy:full": "npm run build && npm run seed-db:remote && wrangler deploy",
    "dev": "npm run build && npm run seed-db && wrangler dev",
    "setup": "npm run build && npm run seed-db && npm run dev",
    "cleanup": "node scripts/cleanup.js",
    "deploy:clean": "npm run delpoy && npm run cleanup"
  }
}
```

## Set production secrets:

### Generate a secure JWT secret
```bash
openssl rand -base64 32
wrangler secret put JWT_SECRET
```

### Deploy:
```bash
wrangler deploy
```

### Create your admin user:
```bash
# Generate secure credentials
$chmod +x scripts/gen-admin/seed-dev.sh
$ ./scripts/gen-admin/seed-dev.sh -v
Enter admin username: admin
Enter admin email: admin@your-domain.tld
Enter admin password:
Duplicate check result: 0 existing user(s) found.

 ⛅️ wrangler 4.27.0 (update available 4.28.1)
─────────────────────────────────────────────
🌀 Executing on local database thatch-db (05792bea-8178-4509-8927-bc79bfeb8340) from .wrangler/state/v3/d1:
🌀 To execute on your remote database, add a --remote flag to your wrangler command.
🚣 2 commands executed successfully.
Admin user created.

# Or manually via SQL
wrangler d1 execute blog_content_new --remote --command "INSERT INTO users (username, password_hash, role) VALUES ('admin', 'your-hash-here', 'admin')"

# Add to production database
wrangler d1 execute blog_content --remote --command "INSERT INTO users (username, password, salt) VALUES ('admin', 'hash-here', 'salt-here')"
```

## Configuration

Edit `src/config.js` to customize:

- Site title and description
- Posts per page
- Date formatting
- Theme defaults
- Security settings

Settings can be changed dynamically after deployment at `your-blog.tld/admin/settings`

### Customize styling
Edit theme variables in `src/routes/styles.js`. The CSS uses variables for easy customization.

### Add custom routes
1. Create route handler in src/routes/
2. Register in src/index.js
3. Add templates as needed

### Adjust security settings
- Rate limits: Edit lib.deadlight/core/src/security/ratelimit.js
- Validation rules: Edit lib.deadlight/core/src/security/validation.js
- Security headers: Edit lib.deadlight/core/src/security/headers.js

## Future Considerations
```
-📊 Analytics service (privacy-first)
-💬 Comments system (no tracking)
-📱 Mobile app API
-🔌 Plugin system
```


## API Documentation
### Public Endpoints
- GET / - Home page with posts
- GET /post/:id - Individual post
- GET /login - Login form
- POST /login - Authenticate

### Protected Endpoints (require auth)
- GET /admin - Admin dashboard
- GET /admin/add - New post form
- POST /admin/add - Create post
- GET /admin/edit/:id - Edit post form
- POST /admin/edit/:id - Update post
- POST /admin/delete/:id - Delete post
- GET /admin/users - User management
- POST /admin/users/add - Create user
- POST /admin/users/delete/:id - Delete user

## Security Headers
All responses include:

- X-Content-Type-Options: nosniff
- X-Frame-Options: DENY
- X-XSS-Protection: 1; mode=block
- Referrer-Policy: strict-origin-when-cross-origin
- Content-Security-Policy (configurable)

## License
MIT - Use this however you want!

## Acknowledgments
Maintained with ❤️ Rage and Diet Mountain Dew

## Support

☕  [Support is greatly appreciated! Buy me a coffee](coff.ee/gnarzillah)
_
