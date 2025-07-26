# Deadlight Edge Bootstrap v2 - Modern Blog Engine for Cloudflare Workers

A minimalist, edge-native blog platform built on Cloudflare Workers. Features a clean architecture, instant global deployment, and everything you need for a modern blog. The WordPress alternative that actually respects your readers.

🌐 Live Demo: [blog.deadlight.boo](https://blog.deadlight.boo)

<img width="2222" height="1239" alt="image" src="https://github.com/user-attachments/assets/05862ed5-d3cc-4c7f-9aff-8d01ed093237" />

<img width="2224" height="1241" alt="image" src="https://github.com/user-attachments/assets/f6f0b745-387a-4e1e-b4a5-0df3d8987c63" />

## Admin Dashboard

<img width="2224" height="1243" alt="image" src="https://github.com/user-attachments/assets/6ff729b5-2e31-4190-bc6b-96bd1a92d514" />

## Dynamic Settings

<img width="2223" height="1239" alt="image" src="https://github.com/user-attachments/assets/d8addda7-f93a-4dd1-b2d7-272d9328dc90" />


## Features
### Core

### What's new in v2:

📄 Individual post pages with SEO-friendly URLs

📑 Smart pagination system

✂️ Post excerpts with manual control

👥 Multi-user management

📊 Built-in request logging (no privacy-invading analytics)

🏗️ Completely refactored architecture

### Core features:

+ Zero cold starts (edge computing!)
+ Multi-user authentication with JWT
+ Full Markdown support
+ Dark/Light theme switching
+ D1 Database (SQLite at the edge)
+ Takes ~5 minutes to deploy your own instance

## Quick Start

### Prerequisites
Cloudflare account (free tier works)
Node.js 16+
Wrangler CLI (npm install -g wrangler)
Deploy in 5 minutes

Clone and install:
```
bash

git clone https://github.com/gnarzilla/deadlight-edge-v2.git
cd deadlight-edge-v2
npm install

# Create your D1 database:
wrangler d1 create blog_content
bash
```

Update wrangler.toml with your database ID:
```
toml
[[d1_databases]]
binding = "DB"
database_name = "blog_content"
database_id = "your-database-id-here"
```

Initialize the database:
```
bash
# Local development
wrangler d1 execute blog_content --local --file=schema.sql

# Production
wrangler d1 execute blog_content --remote --file=schema.sql
```

Configure your domain in wrangler.toml:
```
toml
[[routes]]
pattern = "yourdomain.com/*"
zone_id = "your-zone-id"
```

Set production secrets:

```
bash
# Generate a secure JWT secret
openssl rand -base64 32
wrangler secret put JWT_SECRET
```

Deploy:
```
bash
wrangler deploy
```
Create your admin user:
```
bash
# Generate secure credentials
node scripts/generate-user.js

# Add to production database
wrangler d1 execute blog_content --remote --command "INSERT INTO users (username, password, salt) VALUES ('admin', 'hash-here', 'salt-here')"
Project Structure
```
```
text
deadlight-edge-v2/
├── src/
│   ├── index.js             # Main entry point
│   ├── config.js            # Configuration
│   ├── routes/              # Route handlers
│   │   ├── admin.js         # Admin routes (CRUD + users)
│   │   ├── auth.js          # Login/logout
│   │   ├── blog.js          # Public blog routes
│   │   └── styles.js        # CSS delivery
│   ├── templates/           # HTML templates
│   │   ├── base.js          # Layout wrapper
│   │   ├── blog/            # Blog templates
│   │   └── admin/           # Admin templates
│   ├── middleware/          # Request/response processing
│   │   ├── auth.js          # Authentication checks
│   │   ├── error.js         # Error handling
│   │   └── logging.js       # Request logging
│   └── utils/               # Utilities
│       ├── auth.js          # Password hashing
│       ├── jwt.js           # Token handling
│       └── markdown.js      # Markdown rendering
├── scripts/                 # Build/deploy scripts
├── schema.sql              # Database schema
└── wrangler.toml           # Cloudflare config
```

## Development
```
bash
# Local development with hot reload
npm run dev

# Build and test
npm run build

# Deploy to production
npm run deploy
```

## Configuration

Edit src/config.js to customize:
+ Site title and description
+ Posts per page
+ Date format
+ Theme defaults
+ Common Tasks
+ Add a new user

```
bash
# Visit https://your-site/admin/add-user when logged in
# Or use the script:
node scripts/create-user.js username password
```

## Custom styling
Edit the theme files in src/routes/styles.js. CSS variables make it easy to maintain consistency.

## Add new pages
Create a new route in the appropriate file following the existing patterns.

## Roadmap

Next Up

📊 Admin dashboard - Statistics and quick actions

🏷️ Tags/Categories - Better content organization

🔍 Search - Full-text search across posts

📰 RSS/Atom feeds - For the feed reader fans


Considering

🖼️ R2 image storage - Direct upload with optimization

📧 Email notifications - New post alerts

💬 Privacy-first comments - No tracking, no ads

🔌 Plugin system - Extend without forking

📱 PWA support - Offline reading


Blue Sky Ideas

📬 Webmail integration - Your blog + email at the edge

🌐 ActivityPub - Join the fediverse

🎨 Theme marketplace - Share your designs


## Migration from v1
Export your posts from v1
Update your wrangler.toml with the new structure
Run the migration script (coming soon)
Deploy and test


## Contributing
This is an open source project! Contributions welcome:

🐛 Report bugs via issues

💡 Suggest features

🔧 Submit PRs for fixes

📖 Improve documentation

🎨 Create themes

🌍 Add translations

## License
MIT - Use this however you want!

## Acknowledgments

Built with Cloudflare Workers, D1, and minimal dependencies

Inspired by the bloat of modern web platforms

Special thanks to the edge computing community

Maintained with ❤️ and Diet Mountain Dew
