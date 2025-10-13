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
