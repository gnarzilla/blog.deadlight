## Appendix A: Component Deep Dive

### blog.deadlight (This Repository)

**Purpose:** Content delivery & federation hub  
**Stack:** Cloudflare Workers, D1, Markdown  
**Binary Size:** N/A (serverless)  
**Memory:** ~128 MB (Workers limit)  
**Protocols:** HTTP/S, WebSocket (future)

**Key Integration Points:**
- `POST /api/email/send` → Queues notification for proxy
- `POST /federation/announce` → Notifies federated instances  
- `GET /api/posts/:id` → Serves content to federation

**See Also:** [Full README](#) | [API Docs](docs/API.md) | [Architecture](docs/ARCHITECTURE.md)

### proxy.deadlight

**Purpose:** Protocol bridging & stateful connections  
**Stack:** C17, GLib, OpenSSL  
**Binary Size:** 17 MB (Docker), 8 MB (native)  
**Memory:** ~50 MB  
**Protocols:** HTTP/S, SOCKS4/5, WebSocket, SMTP/IMAP bridge, VPN

**Why it exists:** Bridges stateless (Workers) with stateful (SMTP, VPN, LoRa)

**See Also:** [proxy.deadlight README](https://github.com/gnarzilla/proxy.deadlight)

### meshtastic.deadlight

**Purpose:** LoRa mesh ↔ Internet gateway  
**Stack:** C (fork of proxy.deadlight)  
**Hardware:** Requires Meshtastic-compatible radio (LoRa, nRF52)

**Why it exists:** Enables posting to blog.deadlight over LoRa mesh networks

**See Also:** [meshtastic.deadlight README](https://github.com/gnarzilla/meshtastic.deadlight)

### lib.deadlight

**Purpose:** Shared code (prevents duplication across components)  
**Stack:** JavaScript (Workers), TypeScript (future)

**Contains:**
- Auth (JWT generation/validation)
- Database models (D1 schema)
- Queue service (used by blog for federation)
- Security (rate limiting, CSRF)

**See Also:** [lib.deadlight README](https://github.com/gnarzilla/lib.deadlight)

### edge.deadlight

**Purpose:** Orchestration layer (umbrella project)  
**Stack:** Documentation + deployment scripts

**Use when:** Running multi-instance deployments or full-stack setups

**See Also:** [edge.deadlight README](https://github.com/gnarzilla/edge.deadlight)
