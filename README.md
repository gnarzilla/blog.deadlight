# Deadlight Edge Blog - Secure, Modular Blog Platform with Integrated Proxy Management

🌐 Live Demo: [deadlight.boo](https://deadlight.boo) | [Separate Instance Deployment](https://thatch-dt.deadlight.boo) | [Other Separate Instance](https://threat-level-midnight.deadlight.boo)

A modular, security-hardened blog platform built on Cloudflare Workers with integrated multi-protocol proxy server management. Features real-time proxy control, email federation capabilities, localized real-time analytics. [Getting Started with Deadlight](https://deadlight.boo/post/getting-started)

[Use case examples](https://thatch-dt.deadlight.boo/post/use-cases)

---

![Main Blog - Dual Screen](https://github.com/gnarzilla/blog.deadlight/blob/374775bddc1948b7fd8cae9bb37ac89dd07b463f/src/assets/blog_dual_nolog.png)

---
### Table of Contents
1.  [Key Features](#key-features)
2.  [Architecture](#architecture)
3.  [Quick Start](#quick-start)
4.  [Configuration](#congifuration)
5.  [API Documentation](#api-documentation)
6.  [Roadmap](#roadmap)
7.  [License](#license)
8.  [Support](#support) 

---

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
- **Privacy Proxy**: Manage proxy access directly from the dashboard.


![Admin Dash - Dual Screen](https://github.com/gnarzilla/blog.deadlight/blob/374775bddc1948b7fd8cae9bb37ac89dd07b463f/src/assets/admin_dual.png)

![Proxy/Analytics - Dual Screen](https://github.com/gnarzilla/blog.deadlight/blob/374775bddc1948b7fd8cae9bb37ac89dd07b463f/src/assets/proxy_anal_dual.png)

---

## **Architecture**:
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

## Quick Start

### Prerequisites
- Cloudflare account (free tier works)
- Node.js 20+
- Wrangler CLI (`npm install -g wrangler`)

```bash
git clone https://github.com/gnarzilla/blog.deadlight
cd blog.deadlight
npm install

# Create your D1 database:
wrangler d1 create your-db-name

# Initialize the database:
# Local development
wrangler d1 execute your-db-name --local --file=migrations/20250911_schema.sql

# Production
wrangler d1 execute your-db-name --remote --file=migrations/20250911_schema.sql

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
zone_id = "your-zone-id"

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

[env.production]
name = "your-domain"

[env.production.vars]
PROXY_URL = "https://proxy.your-domain.tld"
SITE_URL = "https://your-domain.tld"
ENABLE_QUEUE_PROCESSING = "true"  # Explicitly set for production

# Copy bindings to production env
[[env.production.d1_databases]]
binding = "DB"
database_name = "your-db-name"
database_id = "your-db-id"

```

### Deploy

```bash
$ wrangler deploy --env=production

 ⛅️ wrangler 4.27.0 (update available 4.37.1)
─────────────────────────────────────────────
[custom build] Running: npm install
[custom build]
[custom build] up to date, audited 8 packages in 2s
[custom build]
[custom build]
[custom build] found 0 vulnerabilities
[custom build]
🌀 Building list of assets...
✨ Read 33 files from the assets directory /home/thatch/blog.deadlight/deadlight.boo/src/assets
🌀 Starting asset upload...
🌀 Found 2 new or modified static assets to upload. Proceeding with upload...
+ /admin_dual.png
+ /BlogProxyTunnel.png
Uploaded 1 of 2 assets
Uploaded 2 of 2 assets
✨ Success! Uploaded 2 files (30 already uploaded) (2.09 sec)

Total Upload: 449.87 KiB / gzip: 90.54 KiB
Worker Startup Time: 8 ms
Your Worker has access to the following bindings:
Binding                                                    Resource
env.DB (your-db-name)                                      D1 Database
env.ASSETS                                                 Assets
env.PROXY_URL ("http://localhost:8080")                    Environment Variable
env.SITE_URL ("https://your-domain.tld")                   Environment Variable
env.ENABLE_QUEUE_PROCESSING ("true")                       Environment Variable
env.USE_PROXY_AUTH (true)                                  Environment Variable
env.DISABLE_RATE_LIMITING (true)                           Environment Variable

Uploaded your-domain.tld (9.43 sec)
Deployed your-domain.tld triggers (1.84 sec)
  your-domain.tld/* (zone id: your-cloudflare-zoneid)
  *.your-domain.tld/* (zone id: your-cloudflare-zoneid)
Current Version ID: <hidden>
```
Your site is now accessible at your-domain.tld. Create an admin account to manage administrative settings at `your-domain.tld/admin` and proxy dashboard at `your-domain.tld/admin/proxy`.


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

## API Documentation

### Public Monitoring Endpoints

These endpoints do not require authentication and are safe to expose for uptime checks and monitoring.

GET /api/health

Returns a minimal heartbeat response.

Response:

{
  "status": "ok",
  "timestamp": "2025-09-15T12:00:00.000Z",
  "version": "5.0.0"
}


---

GET /api/status

Returns detailed service/component status.

Response:

{
  "status": "operational",
  "components": {
    "database": "healthy",
    "proxy": "healthy",
    "worker": "healthy"
  },
  "timestamp": "2025-09-15T12:01:00.000Z"
}

database → DB connection check

proxy → health check against env.PROXY_URL

worker → always reported from current worker context


---

### Blog API Endpoints

These expose blog content as JSON. Useful for headless consumption (mobile apps, static site builders, integrations).

GET /api/blog/status

Returns blog service status and enabled features.

Response:

{
  "status": "running",
  "version": "5.0.0",
  "features": [
    "email_integration",
    "federation",
    "proxy_support"
  ]
}


---

GET /api/blog/posts?limit=10&offset=0

Fetches a paginated list of published posts.

Response:

{
  "posts": [
    {
      "id": 1,
      "title": "Hello Deadlight",
      "slug": "hello-deadlight",
      "content": "...",
      "author_id": 1,
      "published": true,
      "created_at": "2025-09-15T10:00:00.000Z"
    }
  ],
  "total": 1,
  "limit": 10,
  "offset": 0
}


---

### Email Integration Endpoints

These routes enable email → blog workflows and inbox/reply handling.
Authentication is required (middleware sets request.user).

POST /api/email/receive

Receives a single email payload. If sent to blog@ or flagged as is_blog_post, the email becomes a draft blog post.

Request:

{
  "from": "alice@example.com",
  "to": "blog@deadlight.boo",
  "subject": "My First Email Post",
  "body": "Hello world!\nThis is an email-to-blog test.",
  "timestamp": "2025-09-15T09:00:00.000Z",
  "federation": {
    "enabled": true,
    "auto_federate": true
  }
}

Response (blog post created):

{
  "status": "success",
  "message": "Email converted to blog post",
  "blog_post_id": "42",
  "blog_url": "https://deadlight.boo/posts/my-first-email-post",
  "federation_status": "queued"
}

Response (stored as inbox email):

{
  "status": "success",
  "message": "Email received and stored",
  "email_id": 1337
}


---

POST /api/email/fetch

Bulk import multiple emails (e.g. from IMAP/POP3).

Request:

{
  "emails": [
    {
      "from": "bob@example.com",
      "to": "me@deadlight.boo",
      "subject": "Quick update",
      "body": "Just checking in.",
      "date": "2025-09-14T18:30:00.000Z"
    }
  ]
}

Response:

{
  "success": true,
  "inserted": 1,
  "total": 1
}


---

GET /api/email/pending-replies

Lists queued reply drafts that have not been marked as sent.

Response:

{
  "success": true,
  "replies": [
    {
      "id": 5,
      "to": "bob@example.com",
      "from": "deadlight.boo@gmail.com",
      "subject": "Re: Quick update",
      "body": "Thanks for your message!",
      "original_id": 1337,
      "queued_at": "2025-09-15T10:15:00.000Z"
    }
  ],
  "count": 1
}


---

POST /api/email/pending-replies

Marks a queued reply as sent.

Request:

{
  "id": 5
}

Response:

{
  "success": true,
  "id": 5,
  "sent_at": "2025-09-15T11:00:00.000Z"
}


---

### Legacy & Admin Endpoints

These routes remain for backward compatibility and administrative use:

/post/:id → view a single blog post (HTML)

/admin/* → administrative panel (HTML forms)



---

### Federation Workflow

Although federation does not yet expose direct endpoints, it is triggered automatically by:

POST /api/email/receive → if federation.auto_federate=true

Federation service (FederationService) queues distribution to connected domains.


Future documentation should include explicit federation endpoints once they are stabilized.



---


### Public Endpoints
- GET / - Home page with posts
- GET /post/:id - Individual post
- GET /login - Login form
- POST /login - Authenticate
- GET /api/health          → {"status":"ok","timestamp":"...","version":"5.0.0"}
- GET /api/status          → {"status":"operational","components":{...}}
- GET /api/blog/status     → {"status":"running","features":["email_integration","federation","proxy_support"]}
- GET /api/blog/posts      → list of published posts (JSON, supports limit/offset)

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

### Email & Federation
- POST /api/email/receive  → ingest email (JSON body), optional auto-federation
- POST /api/email/fetch    → bulk import emails (JSON body {emails: [...]})
- GET  /api/email/pending-replies → list queued reply drafts
- POST /api/email/pending-replies → mark reply as sent

## Security Headers
All responses include:

- X-Content-Type-Options: nosniff
- X-Frame-Options: DENY
- X-XSS-Protection: 1; mode=block
- Referrer-Policy: strict-origin-when-cross-origin
- Content-Security-Policy (configurable)

## **Roadmap**
- Post comments - active
- Proxy integration - testing
- email bridge/federation - testing
- plugin system - active
- Integrated locoalized (private) analytics collection and dashboard - active
- **Active Development**: Full email client/server integration, production deployment guides, automatic sitemmap.xml generation

## License
MIT - Use this however you want!

## Support

☕  [Support is greatly appreciated! Buy me a coffee](coff.ee/gnarzillah)
_
