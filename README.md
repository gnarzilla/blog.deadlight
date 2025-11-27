# Deadlight Blog | Edge-Native Publishing for Resilient Networks
[Key Features](#key-features) · [Quick Start](#quick-start) · [Use Cases](#use-cases) · [Configuration](#configuration) · [Architecture](#architecture) · [The Deadlight Ecosystem](#the-deadlight-ecosystem) · [Roadmap](#roadmap) · [License](#license)

> Built for the 80% of the internet that isn't fiber and datacenters. **3–8 KB pages · Zero JS required · Deployable from a PinePhone**

### Live Demos

|  [![LIVE](https://deadlight.boo/favicon.ico)](https://deadlight.boo)  [deadlight.boo](https://deadlight.boo)  |  [![zero-JS](https://thatch-dt.deadlight.boo/favicon.ico)](https://thatch-dt.deadlight.boo) [zero-JS instance](https://thatch-dt.deadlight.boo)  |  [![Mesh](https://meshtastic.deadlight.boo/favicon.ico)](https://meshtastic.deadlight.boo) [LoRa gateway blog](https://meshtastic.deadlight.boo)  |
|----------------------------------------|--------------------------------------|--------------------------|

![Landing Page Tri-Instance View](src/assets/landing.gif)

---

## Why this exists

Most blogging platforms assume you have reliable connectivity, cheap power, and modern browsers. **The rest of the planet doesn't.**

| The internet most people actually have | Why Ghost/WordPress/Substack die here | How Deadlight just works |
|----------------------------------------|--------------------------------------|--------------------------|
| **300–3000 ms latency**<br>(Starlink, LoRa, HF, mesh) | 400 KB of JS + hydration before you see text | <10 KB semantic HTML + optional CSS. Loads before the first satellite ACK |
| **Connectivity drops for hours** | Needs 30–60s of stable link to render a post | Fully readable offline after first visit. New posts need ~4 seconds of uplink |
| **Text-only clients**<br>(Meshtastic, packet radio, lynx) | 99% of modern blogs are JavaScript-only | 100% functional in w3m, links, or a 300-baud terminal |
| **Power is scarce**<br>(solar Pi, phone in the desert) | Always-on containers burn watts for nothing | Zero compute when idle. D1 + Workers sleep completely |
| **Hostile networks**<br>(DPI, censorship, no DNS) | Third-party analytics + CDN beacons = instant fingerprint | Zero external requests by default. Prevents fingerprinting and bypasses DNS blackouts |
| **You might post over email, SMS, or LoRa** | Normal dashboards require browser + stable link | Admin dashboard works over SMTP/IMAP. Post from a burner address if needed |

**Deadlight isn't trying to be the coolest blog platform.**  
**It's trying to be the last one that still works when everything else is on fire.**

---

## It actually works

[This isn't vaporware. Deadlight is production-deployed and **literally running over LoRa mesh networks right now.**.]: # 

### Live Deployments

- **[deadlight.boo](https://deadlight.boo)** – Full-featured instance with admin dashboard
- **[thatch-dt.deadlight.boo](https://thatch-dt.deadlight.boo)** – Zero-JS minimal theme (perfect for lynx/slow links)
- **[meshtastic.deadlight.boo](https://meshtastic.deadlight.boo)** – Blog published over LoRa mesh
- **[threat-level-midnight.deadlight.boo](https://threat-level-midnight.deadlight.boo)** – Federation testing instance

### Tested On

- PinePhone (Mobian/PostmarketOS)
- Raspberry Pi Zero 2W / 3B+ / 4
- Android (Termux)
- Standard x86_64 Linux/macOS/Windows

### Proof Points

```bash
# Total page weight for a typical post
curl -s https://thatch-dt.deadlight.boo/post/use-cases | wc -c
# → 7,432 bytes (including HTML structure)

# Time to first byte over satellite internet (600ms RTT)
curl -w "%{time_total}\n" -o /dev/null -s https://deadlight.boo
# → 0.847s (compare to 8–15s for typical JS-heavy blogs)

# Works in text-only browsers
lynx -dump https://thatch-dt.deadlight.boo/post/use-cases | head -20
# → Fully readable, zero layout breakage
```

---

## Quick Start

### Standard Deployment (any platform)

```bash
git clone https://github.com/gnarzilla/blog.deadlight
cd blog.deadlight
npm install

# Authenticate with Cloudflare
npx wrangler login

# Create database
npx wrangler d1 create my-blog
npx wrangler d1 execute my-blog --remote --file=migrations/20250911_schema.sql

# Create admin user
./scripts/gen-admin/seed-dev.sh -r

# Set secrets
openssl rand -base64 32 | npx wrangler secret put JWT_SECRET
echo "https://your-domain.pages.dev" | npx wrangler secret put SITE_URL

# Deploy
npx wrangler deploy
```

**Your blog is now global, costs pennies, and survives apocalypse-level connectivity.**

### ARM64-Friendly Quick Start (Raspberry Pi, PinePhone, Android/Termux)

Wrangler's local D1 emulator fails on ARM due to TCMalloc issues. Skip it entirely and bootstrap remotely:

```bash
# 1. Install prerequisites
# Raspberry Pi OS / Debian / Ubuntu:
sudo apt update && sudo apt install nodejs npm git jq openssl

# Android (Termux):
pkg update && pkg install nodejs git jq openssl-tool

# 2. Clone repo
git clone https://github.com/gnarzilla/blog.deadlight
cd blog.deadlight
npm install
cd lib.deadlight && npm install && cd ..

# 3. Authenticate
npx wrangler login

# 4. Create & bootstrap remote database (skip local entirely)
npx wrangler d1 create my-blog
npx wrangler d1 execute my-blog --remote --file=migrations/20250911_schema.sql

# 5. Create admin user (remote-only)
./scripts/gen-admin/seed-dev.sh -v -r

# 6. Set secrets
openssl rand -base64 32 | npx wrangler secret put JWT_SECRET
echo "https://your-domain.tld" | npx wrangler secret put SITE_URL

# 7. Fix assets path in wrangler.toml if needed
# Change: directory = "src/static" → directory = "src/assets"

# 8. Deploy from your phone
npx wrangler deploy
```

---

## Architecture

Deadlight is designed for maximum resilience with minimum complexity.

### Technology Stack

- **Cloudflare Workers** – Globally distributed compute that sleeps when idle
- **D1 (SQLite at the edge)** – Fast, low-cost persistence with no cold starts
- **Markdown → HTML** – Clean semantic output, zero client-side rendering
- **JWT auth** – Role-based access control (admin/editor/viewer)
- **Zero third-party requests** – No analytics beacons, no fingerprinting

### Project Structure

```
deadlight/
├── blog.deadlight/          # Main blog application
│   └── src/
│       ├── assets/          # Static media
│       ├── config.js        # Runtime configuration
│       ├── index.js         # Main entry & routing
│       ├── middleware/      # Auth, analytics, error handling, logging
│       ├── routes/          # All endpoint handlers
│       │   ├── admin.js
│       │   ├── auth.js
│       │   ├── blog.js
│       │   ├── inbox.js     # Email bridge endpoints
│       │   ├── proxy.js     # Proxy management dashboard
│       │   └── ...
│       ├── services/        # External service integration
│       ├── templates/       # HTML templates (no build step)
│       └── utils/
└── lib.deadlight/           # Shared library
    └── core/
        ├── auth/            # Authentication system
        ├── db/              # Database models & queries
        ├── security/        # CSRF, rate limiting, headers
        └── ...
```

### Core Design Principles

1. **Text-first** – No media management complexity. Markdown posts, HTML output.
2. **Stateless by default** – Every request is self-contained. No session stickiness required.
3. **Offline-first reading** – After first load, posts are readable without connectivity.
4. **Protocol-agnostic administration** – Manage via browser, curl, or SMTP. Your choice.
5. **Zero external dependencies at runtime** – No CDN requests, no tracking pixels, no font servers.

### Security

All responses include hardened headers:
- `X-Content-Type-Options: nosniff`
- `X-Frame-Options: DENY`
- `X-XSS-Protection: 1; mode=block`
- `Referrer-Policy: strict-origin-when-cross-origin`
- Configurable Content-Security-Policy

All mutable actions protected by:
- CSRF tokens (per-session + per-request)
- Rate limiting (configurable per endpoint)
- Input validation and sanitization
- Role-based authorization checks

---

## The Deadlight Ecosystem

The blog is one component of a larger resilience stack:

```
┌─────────────────────────────────────────────┐
│           edge.deadlight                    │  ← Umbrella platform
│  (orchestrates everything below)            │
└─────────────────────────────────────────────┘
           │
           ├──────────────────┬──────────────────┬─────────────────
           ▼                  ▼                  ▼
   ┌───────────────┐  ┌───────────────┐  ┌──────────────────┐
   │blog.deadlight │  │proxy.deadlight│  │meshtastic        │
   │               │  │               │  │  .deadlight      │
   │ Content layer │  │Protocol bridge│  │                  │
   │ (this repo)   │  │SMTP/IMAP/SOCKS│  │LoRa ↔ Internet   │
   │               │  │VPN gateway    │  │bridge            │
   │ JavaScript    │  │ C             │  │ C (proxy fork)   │
   └───────────────┘  └───────────────┘  └──────────────────┘
           │                  │                  │
           └──────────────────┴──────────────────┘
                              │
                              ▼
                   ┌─────────────────────┐
                   │   lib.deadlight     │
                   │                     │
                   │ Shared libraries:   │
                   │ • Auth & JWT        │
                   │ • DB models (D1)    │
                   │ • Security utils    │
                   │ • UI components     │
                   └─────────────────────┘
```

### How They Work Together

**Scenario 1: Blogging over LoRa**
1. Write post on phone connected to Meshtastic node
2. Send via SMTP (could be over LoRa → meshtastic.deadlight gateway)
3. Gateway forwards to blog.deadlight inbox endpoint
4. Post published globally via Cloudflare Workers

**Scenario 2: Self-hosted email + edge blog**
1. Run proxy.deadlight locally (bridges SMTP/IMAP)
2. Configure blog.deadlight to use your proxy for outbound email
3. Receive replies to blog posts in your self-hosted inbox
4. Respond via normal email client
5. Blog federates with other Deadlight instances

**Scenario 3: Disaster response team**
1. Deploy blog.deadlight for team updates
2. Team members post via satellite email when web is down
3. Public reads blog over intermittent 2G/3G
4. Zero server infrastructure required on-site

### Repository Links

- **[blog.deadlight](https://github.com/gnarzilla/blog.deadlight)** (you are here)
- **[proxy.deadlight](https://github.com/gnarzilla/proxy.deadlight)** – Protocol bridge & VPN gateway
- **[meshtastic.deadlight](https://github.com/gnarzilla/meshtastic.deadlight)** – LoRa ↔ Internet gateway
- **[lib.deadlight](https://github.com/gnarzilla/lib.deadlight)** – Shared edge-native libraries
- **[edge.deadlight](https://github.com/gnarzilla/edge.deadlight)** – Umbrella platform

---

## Key Features

### For Readers
- **Near-zero latency** – Cloudflare's global edge network
- **Works offline** – Readable after first visit, even without connectivity
- **Text-only compatible** – Full functionality in lynx, w3m, links
- **No JavaScript required** – Optional progressive enhancement only
- **No tracking** – Zero third-party requests by default

### For Publishers
- **Markdown authoring** – Simple, portable, version-controllable
- **Post via email** – SMTP → new article (alpha, testing)
- **Global distribution** – Instant worldwide availability
- **Private analytics** – Per-instance, no external beacons
- **Role-based access** – Admin/editor/viewer permissions

### For Operators
- **Zero always-on costs** – Workers sleep when idle
- **Deploy from a phone** – Full Termux/ARM64 support
- **Proxy integration** – Manage local infrastructure from dashboard
- **Federation ready** – Blog-to-blog communication (alpha)
- **Audit-friendly** – ~8 npm dependencies, readable in an afternoon

---

## Configuration

### Basic Setup

Edit `src/config.js` after deployment:

```javascript
export const CONFIG = {
  siteName: 'My Resilient Blog',
  siteDescription: 'Publishing from the edge of connectivity',
  postsPerPage: 10,
  theme: 'minimal', // or 'default'
  enableComments: false, // coming soon
  enableFederation: false // alpha
};
```

Or configure dynamically at `your-blog.tld/admin/settings` after authentication.

### Advanced Configuration

See `wrangler.toml` for:
- Custom domain routing
- D1 database bindings
- Environment variables
- Asset handling

See [docs/SAMPLE_wrangler.md](docs/SAMPLE_wrangler.md) for full examples.

### Security Settings

Adjust in shared library `lib.deadlight/core/security/`:
- **Rate limits** – `ratelimit.js` (default: 100 req/hour per IP)
- **Validation rules** – `validation.js` (input sanitization)
- **Security headers** – `headers.js` (CSP, HSTS, etc.)

---

## Administration

### Creating Your First Admin User

```bash
# Interactive mode (local or remote)
./scripts/gen-admin/seed-dev.sh -v

# Force remote (for ARM64 deployments)
./scripts/gen-admin/seed-dev.sh -v -r

# Manual via SQL (if needed)
npx wrangler d1 execute my-blog --remote --command \
  "INSERT INTO users (username, password_hash, role) 
   VALUES ('admin', 'bcrypt-hash-here', 'admin')"
```

### Admin Dashboard

Access at `your-blog.tld/admin`:
- Create/edit/delete posts
- Manage users and permissions
- Configure site settings
- View analytics (private, per-instance)
- Control proxy settings (if proxy.deadlight is running)

### Publishing Workflows

**Via Web Dashboard** (standard)
```
your-blog.tld/admin/posts/new
→ Write Markdown
→ Publish
```

**Via Email** (alpha, requires proxy.deadlight)
```
From: you@domain.tld
To: inbox@your-blog.tld
Subject: New Post Title

Post content in Markdown...
```

**Via API** (for automation)
```bash
curl -X POST https://your-blog.tld/api/posts \
  -H "Authorization: Bearer $JWT_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"title":"My Post","content":"# Hello\n\nWorld"}'
```

See [docs/API.md](docs/API.md) for full endpoint documentation.

---

## Roadmap

### Production-Ready 
- Core blogging (posts, pages, archives)
- Markdown rendering with XSS protection
- User authentication & role-based access
- Admin dashboard
- Private analytics
- Rate limiting & CSRF protection
- ARM64 deployment support

### Alpha / Testing 
- Post-by-email (SMTP inbox processing)
- Blog-to-blog federation via email protocols
- Full proxy.deadlight dashboard integration
- Comment system

### Planned 
- **2025 Q4** – Stable post-by-email + comments
- **2026 Q1** – Full proxy dashboard integration
- **2026 Q2** – Meshtastic-native posting client and Visual Edge Network Topology integration.
- **Eventually** – ActivityPub federation, plugin architecture

### Help Wanted
Open to contributions via issues or PRs. Priority areas:
- Testing email workflows on various providers
- Documentation improvements
- Accessibility enhancements
- Translations (i18n)

---

## API Documentation

### Authentication
```bash
# Login
curl -X POST https://your-blog.tld/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"secret"}'
# → Returns JWT token

# Use token
curl https://your-blog.tld/api/posts \
  -H "Authorization: Bearer YOUR_JWT_TOKEN"
```

### Posts
```bash
# List posts
GET /api/posts?page=1&limit=10

# Get single post
GET /api/posts/:id

# Create post (requires auth)
POST /api/posts
{
  "title": "My Post",
  "content": "# Hello\n\nMarkdown content...",
  "published": true
}

# Update post (requires auth)
PUT /api/posts/:id

# Delete post (requires auth)
DELETE /api/posts/:id
```

Full API documentation: [docs/API.md](docs/API.md)

---

## Use Cases

### Disaster Response Teams
- Deploy once, access globally
- Post updates via satellite email when web is down
- Public reads over intermittent 2G/3G
- Zero on-site server infrastructure

### Mesh Network Communities
- Run blog over LoRa using meshtastic.deadlight gateway
- Post from phone over Meshtastic mesh
- Content caches at edge for fast local access
- Optional internet gateway for wider distribution

### Off-Grid Operations
- Solar-powered Raspberry Pi as local admin interface
- Sync posts when satellite uplink available
- Zero ongoing power consumption (Workers sleep when idle)
- Works with intermittent connectivity

### Privacy-Focused Publishing
- No third-party trackers or analytics
- Optional Tor/I2P access via proxy.deadlight
- Self-hosted email via SMTP bridge
- Federation without corporate platforms

### Activists in Hostile Networks
- Post via burner email addresses
- No always-on server to raid or subpoena
- Cloudflare's DDoS protection included
- Can operate behind VPN/proxy

---

## Why You Might Choose Deadlight

**Choose Deadlight if you:**
- Need a blog that works over terrible connectivity
- Want zero always-on server costs
- Value privacy and minimal third-party dependencies
- Need to deploy/manage from a phone or low-power device
- Want to integrate blogging with mesh networks or amateur radio
- Need text-only client compatibility
- Want a platform you can actually audit and understand

**Look elsewhere if you:**
- Need rich media galleries (Deadlight is deliberately text-first)
- Want out-of-the-box social media integrations
- Need a WordPress plugin ecosystem
- Require a visual page builder
- Want a fully GUI-based setup with no terminal required

---

## Support

**[Support on Ko-fi](https://ko-fi.com/gnarzilla)**

Other ways to help:
-  Star the repo
-  File bug reports
-  Improve documentation
-  Submit PRs
-  Tell others who might need this

---

## License

See [docs/LICENSE](docs/LICENSE) for details.

---

## Contact

- **GitHub:** [@gnarzilla](https://github.com/gnarzilla)
- **Email:** gnarzilla@deadlight.boo
- **Blog:** [deadlight.boo](https://deadlight.boo)

---

EOF







