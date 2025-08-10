_# Deadlight Edge Bootstrap v4 - Secure, Modular Blog Platform with Integrated Proxy Management

🌐 Live Demo: [deadlight.boo](https://deadlight.boo)

A production-ready, security-hardened blog platform built on Cloudflare Workers with integrated multi-protocol proxy server management. Features real-time proxy control, email federation capabilities, and everything you need for a truly self-sovereign digital presence.

![Main Blog - Dark Mode](https://github.com/gnarzilla/deadlight/blob/main/src/assets/blog_bl_ylog_hero.png)

### Serverless deployment via Cloudflare Workers free-tier in minutes (B.Y.O.D. - Bring your own domain)

1. Clone the repo
2. Create D1 database
3. Set up KV namespace
4. Deploy via Wrangler

![Main Blog - Light Mode - Logged Out](https://github.com/gnarzilla/deadlight/blob/main/src/assets/blog_wh_nolog.png)

![Login - Light Mode](https://github.com/gnarzilla/deadlight/blob/main/src/assets/login_wh.png)

![Main Blog - Light Mode - Logged In](https://github.com/gnarzilla/deadlight/blob/main/src/assets/blog_wh_ylog.png)

![Create New Post - Dark Mode](https://github.com/gnarzilla/deadlight/blob/main/src/assets/addPost_bl.png)

![Main Blog - Dark Mode - Logged In](https://github.com/gnarzilla/deadlight/blob/main/src/assets/blog_bl_ylog.png)

![Main Blog - Light Mode - Logged In](https://github.com/gnarzilla/deadlight/blob/main/src/assets/blog_wh_log.png)

## Admin Dashboard, Settings & User Management

![Admin Dash - Light Mode](https://github.com/gnarzilla/deadlight/blob/main/src/assets/admindash_wh.png)

![Login - Dark Mode](https://github.com/gnarzilla/deadlight/blob/main/src/assets/settings_bl.png)

![Admin Dash - Dark Mode](https://github.com/gnarzilla/deadlight/blob/main/src/assets/admindash_bl.png)

![User Management - Light Mode](https://github.com/gnarzilla/deadlight/blob/main/src/assets/user_management_wh.png)

## Features

### v3 Highlights

🔐 **Security Focused**
- CSRF protection on all forms
- Rate limiting (configurable per endpoint)
- Input validation and sanitization
- Security headers middleware
- XSS prevention built-in

📦 **Modular Architecture**
- Shared `lib.deadlight` library
- Reusable components across projects
- Clean separation of concerns
- Ready for multi-app ecosystems

🛡️ **Enhanced Authentication**
- Improved JWT implementation
- Role-based access control (admin/editor/viewer)
- Secure session management
- Password complexity validation

📊 **Better Admin Experience**
- Dashboard with real-time stats
- User management interface
- Improved error handling
- Activity logging

🏗️ **Developer Experience**
- Comprehensive validation framework
- Structured logging system
- Database models with error handling
- Clean route organization

### Core Features (from v2):

+ Near-zero cold start latency (~<5 ms typical)
+ Multi-user authentication with JWT
+ Full Markdown support
+ Dark/Light theme switching
+ D1 Database (SQLite at the edge)
+ SEO-friendly URLs
+ Smart pagination
+ Post excerpts
+ Request logging (privacy-respecting)

## Integrated Proxy Server Management (NEW in v4)

![Proxy Dashboard](https://github.com/gnarzilla/deadlight/blob/main/src/assets/ProxyDash.png)

**Real-time control of your local proxy server through the web interface:**

- 🔄 **Live Status Monitoring** - Real-time connection tracking and health checks
- 📧 **Email Protocol Bridge** - SMTP/IMAP integration for self-hosted email
- 🌐 **Federation Testing** - Domain-to-domain communication via email protocols  
- 🔒 **Privacy Proxy** - SOCKS5 proxy management through web dashboard
- ⚡ **Instant Deployment** - Global web interface managing local infrastructure

**Architecture:**
Web Dashboard (Global CDN) ←→ REST API ←→ proxy.deadlight (Your Hardware)
blog.deadlight HTTP/JSON Multi-Protocol Bridge

**What this enables:**
- Deploy your blog globally via Cloudflare
- Manage your local proxy server from any browser
- Bridge modern web apps to legacy TCP protocols (SMTP, IMAP, SOCKS)
- Test email federation between blog instances
- Complete infrastructure sovereignty

### Market Comparison

```markdown
| Feature           | WordPress | Ghost | Deadlight   |
| ----------------- | --------- | ----- | ----------- |
| Self-host on edge | ❌        | ❌   |    ✅       |
| Proxy integration | ❌        | ❌   |    ✅       |  
| Email federation  | ❌        | ❌   |    ✅       |
| Real-time control | ❌        | ⚠️   |    ✅       |
| Protocol bridge   | ❌        | ❌   |    ✅       |
| Zero tracking     | ⚠️        | ✅   |    ✅       |
```

## Quick Start

### Prerequisites
- Cloudflare account (free tier works)
- Node.js 20+
- Wrangler CLI (`npm install -g wrangler`)

### Deploy in 5 minutes

**Clone and install:**
```bash
git clone https://github.com/gnarzilla/deadlight.boo.git
cd deadlight.boo
npm install
```
### Create your D1 database:
```bash
wrangler d1 create your-db-name
```

## Initialize the database:

### Local development

```wrangler d1 execute your-db-name --local --file=schema.sql```

### Production

```wrangler d1 execute your-db-name --remote --file=schema.sql```

### Create KV namespace for rate limiting

```wrangler kv:namespace create "RATE_LIMIT"```

### Configure your domain and bindings in wrangler.toml:
```toml
name = "yourdomain.com"
main = "src/index.js"
compatibility_date = "2023-10-20"

[[routes]]
pattern = "yourdomain.com/*"
zone_id = "your-zone-id"

pattern = "proxy.yourdomain.com/*"
zone_id = "your-zone-id"

[[d1_databases]]
binding = "DB"
database_name = "your-db-name"
database_id = "your-database-id-here"

[[kv_namespaces]]
binding = "RATE_LIMIT"
id = "your-kv-namespace-id"

[build]
command = "npm install"

[vars]
JWT_SECRET = "your-jwt-secret"
X_API_KEY = "your-x-api-key"
PROXY_URL = "http://localhost:8080" # For local development. For production http://[your-ip-address]:8080 Use curl ifconfig.me to determine local IP

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
Enter admin email: admin@deadlight.boo
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
## Project Structure:
```
deadlight/
├── blog.deadlight/          # Main blog application
│   └── src/
│       ├── index.js         # Main entry & routing
│       ├── config.js        # Site configuration
│       ├── routes/          # Route handlers
│       │   ├── admin.js     # Admin routes (CRUD + users)
│       │   ├── auth.js      # Login/logout with CSRF
│       │   ├── blog.js      # Public blog routes
│       │   ├── inbox.js     # Inbox routing
│       │   └── styles.js    # CSS delivery
│       ├── templates/       # HTML templates
│       └── utils/           # App-specific utilities
│
└── lib.deadlight/          # Shared library
    └── core/
        ├── auth/           # Authentication system
        │   ├── jwt.js      # JWT handling
        │   ├── password.js # Bcrypt hashing
        │   └── errors.js   # Auth errors
        ├── db/             # Database layer
        │   ├── models/     # Data models
        │   └── migrations.js
        ├── security/       # Security features
        │   ├── validation.js # Input validation
        │   ├── ratelimit.js  # Rate limiting
        │   ├── headers.js    # Security headers
        │   └── middleware.js
        ├── logging/        # Logging system
        └── markdown/       # Markdown processing
```

## Proxy Integration Setup

### Prerequisites
- Linux/macOS system for running proxy.deadlight
- GCC and development tools (`build-essential` on Ubuntu)
- GLib 2.0+ development libraries

### Quick Start
```bash
# Terminal 1: Build and start the proxy server
git clone https://github.com/your-repo/proxy.deadlight.git
cd proxy.deadlight/v4.0
make
./bin/deadlight -c deadlight.conf.example

# Terminal 2: Start the blog with proxy integration  
cd ../blog.deadlight
wrangler dev
```
Access http://localhost:8787/admin/proxy for real-time proxy management.

What you can do:
- Test blog API connectivity
- Monitor email system status
- Test federation with other domains
- Send test emails through proxy bridge
- View live connection logs

## Security Features

### Authentication & Authorization
- JWT-based sessions with secure cookies
- Role-based access control (admin, editor, viewer)
- Secure password hashing with bcrypt
- Session expiration and renewal

### Request Security
- CSRF protection on all state-changing operations
- Rate limiting with configurable windows
- Input validation and sanitization
- XSS prevention in templates
- Security headers (CSP, X-Frame-Options, etc.)

### Data Protection
- Parameterized queries (no SQL injection)
- HTML escaping in outputs
- Markdown sanitization
- Secure cookie flags


## Configuration

Edit `src/config.js` to customize:

- Site title and description
- Posts per page
- Date formatting
- Theme defaults
- Security settings

### Customize styling
Edit theme variables in src/routes/styles.js. The CSS uses variables for easy customization.

### Add custom routes
1. Create route handler in src/routes/
2. Register in src/index.js
3. Add templates as needed

### Adjust security settings
- Rate limits: Edit lib.deadlight/core/src/security/ratelimit.js
- Validation rules: Edit lib.deadlight/core/src/security/validation.js
- Security headers: Edit lib.deadlight/core/src/security/headers.js

## Current Status & Roadmap

### ✅ Production Ready (v4)
- **proxy.deadlight integration** - Full web-based proxy management
- **Email protocol bridge** - SMTP/IMAP connectivity for Cloudflare Workers
- **Federation testing** - Blog-to-blog communication via email
- **Real-time monitoring** - Live proxy status and connection tracking

### 🚧 Active Development  
- **comm.deadlight** - Full email client/server integration
- **Production deployment** - VPS deployment guides for proxy server
- **Enhanced federation** - Automatic blog post distribution via email
- **SOCKS5 authentication** - Username/password proxy access

## Future Considerations
```
-📊 Analytics service (privacy-first)
-💬 Comments system (no tracking)
-🖼️ Media management with R2
-📱 Mobile app API
-🔌 Plugin system
-🌐 ActivityPub support
```

## Migration from v2
1. Export your posts: wrangler d1 execute blog_content --local --command "SELECT * FROM posts"
2. Update your wrangler.toml with new bindings
3. Run the v3 schema: wrangler d1 execute blog_content_new --local --file=schema.sql
4. Import your data (script coming soon)
5. Test locally before deploying

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

## Contributing
This is an open source project! Contributions welcome:
```
🐛 Report bugs via issues
💡 Suggest features
🔧 Submit PRs for fixes
📖 Improve documentation
🎨 Create themes
🌍 Add translations
🔒 Security audit
```

## License
MIT - Use this however you want!

## Acknowledgments
Built with Cloudflare Workers, D1, and KV
Security patterns inspired by OWASP guidelines
Thanks to the Cloudflare Workers community
Maintained with ❤️ and Diet Mountain Dew

## Support

☕  [Support is greatly appreciated! Buy me a coffee](coff.ee/gnarzillah)
_