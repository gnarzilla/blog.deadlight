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

### Component Roles

| Component | Purpose | When You Need It |
|-----------|---------|------------------|
| **blog.deadlight** | Content storage & delivery | Always (core component) |
| **lib.deadlight** | Shared code (auth, queuing, DB) | Always (dependency) |
| **proxy.deadlight** | Protocol bridging | Email posting, federation, self-hosted SMTP |
| **meshtastic.deadlight** | LoRa ↔ Internet gateway | Mesh network publishing |
| **edge.deadlight** | Orchestration layer | Multi-instance deployments |

## Architecture: Blog + Proxy Integration

### Sequence: User Posts Comment
```mermaid
sequenceDiagram
    participant U as User
    participant B as blog.deadlight
    participant D as D1 Queue
    participant C as Cron (5 min)
    participant P as proxy.deadlight
    participant M as MailChannels
    participant R as Recipient

    U->>B: POST /api/comments (new comment)
    B->>D: Queue notification {to, subject, body}
    B->>U: 200 OK (comment saved)
    
    Note over D: Queue persisted<br/>even if proxy offline
    
    C->>B: Trigger (every 5 min)
    B->>P: GET /api/health (via Tailscale)
    
    alt Proxy Online
        P->>B: 200 OK
        B->>D: Fetch queued items
        B->>P: POST /api/email/send {payload}
        P->>M: POST /tx/v1/send (HTTPS, port 443)
        M->>R: Deliver email
        P->>B: 202 Accepted
        B->>D: Mark delivered
    else Proxy Offline
        P--xB: Timeout
        B->>D: Keep in queue (retry later)
    end
```

**Key insight:** The blog never directly touches SMTP. The proxy translates HTTP → Email API → SMTP. This is why residential networks (port 25 blocked) still work.
