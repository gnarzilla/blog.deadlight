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