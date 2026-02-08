### Architecture Overview

### Integration Patterns

#### Why the Blog Needs Queuing

Cloudflare Workers are **stateless** (no persistent connections). The proxy is **stateful** (maintains SMTP sessions, VPN tunnels). They can't directly communicate.

**Solution:** Queue-based resilience
```
User clicks "Send notification"
         ↓
Blog queues in D1 database (always succeeds)
         ↓
Cron job (every 5 min) checks queue
         ↓
IF proxy reachable → flush queue
IF proxy offline → keep queued (retry later)
```

**This is why blog.deadlight has a QueueService** - it enables federation and email features without requiring the proxy to be always-on.

#### Why the Blog Needs Federation Endpoints

The `/federation/*` routes aren't just for ActivityPub wannabes - they enable:

1. **Tag-based discovery:** Instances auto-discover peers via hashtags
2. **Pull-based content:** Spam-resistant (instances request what they want)
3. **Multi-protocol delivery:** HTTP primary, email fallback, LoRa future
4. **Subdomain communities:** `politics.deadlight.boo` aggregates all #politics posts

**This is why blog.deadlight has a federation layer** - it enables decentralized community organization.

#### How Federation Posts Are Authenticated

Each Deadlight instance has an Ed25519 identity keypair:

1. **Key generation:** `vault.deadlight` generates keypair (or use `openssl`)
2. **Public key publication:** Add to DNS TXT record or `/.well-known/deadlight`
3. **Post signing:** Outbound posts include signature in `X-Deadlight-Signature` header
4. **Verification:** Receiving instance fetches sender's public key, verifies signature

**Without vault.deadlight:** Keys stored in environment variables or config file
**With vault.deadlight:** Keys stored encrypted, never touch disk in plaintext

#### Why the Proxy Uses Port 443 (Not 25)

Residential ISPs block port 25 (SMTP). Traditional email delivery fails.

**Solution:** HTTP-to-Email bridge via transactional APIs
```
blog.deadlight → Queue notification
     ↓
proxy.deadlight → HTTP POST to MailChannels (port 443)
     ↓
MailChannels → Recipient's inbox (proper SPF/DKIM)
```

**This is why email posting works** - the proxy translates between protocols so the blog never needs port 25.

### Federation Architecture

Deadlight instances can federate via two transports:

**Primary: Direct HTTPS**

Instance A Instance B
│ │
│ POST /api/federation/inbox │
│─────────────────────────────>│
│ {"from":"user@instanceA", │
│ "body":"...", │
│ "headers":{ │
│ "X-Deadlight-Type": │
│ "federation"}} │
│ │
│<─────────────────────────────│
│ {"success":true, │
│ "slug":"fed-1234-user"} │


**Fallback: Email via MailChannels**
- Used when HTTPS delivery fails
- Sends to `federation@target-domain.tld`
- Requires target instance to process email inbox
- Ensures delivery even during connectivity issues

**Discovery Protocol**
```bash
curl https://target-instance.tld/.well-known/deadlight
{
  "version": "1.0",
  "instance": "https://target-instance.tld",
  "domain": "target-instance.tld",
  "software": "deadlight",
  "federation_enabled": true,
  "inbox": "https://target-instance.tld/api/federation/inbox",
  "outbox": "https://target-instance.tld/api/federation/outbox"
}
```
