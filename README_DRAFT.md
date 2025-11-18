# Deadlight – The blog platform for when the internet barely works

Most blogging tools are built for fiber and data centers.  
Deadlight is built for the rest of the planet.

https://deadlight.boo (main demo) • https://thatch-dt.deadlight.boo (zero-JS instance) • https://meshtastic.deadlight.boo (LoRa gateway blog)

![deadlight running in termux on a pinephone](https://github.com/user-attachments/assets/YOUR_GIF_HERE.gif)
*Yes, the entire thing is developed and deployed from a phone.*

| The internet most people actually have (2025 → 2040) | Why Ghost / WordPress / Substack / Next.js die here | How Deadlight just works |
|------------------------------------------------------|------------------------------------------------------|---------------------------|
| 300–3000 ms latency (Starlink, LoRa, HF, mesh)       | 400 KB of JS + hydration before you see text         | <10 KB semantic HTML + optional CSS. Loads before the first satellite ACK |
| Connectivity that drops for hours or days            | Needs 30–60 s of stable link just to render a post   | Fully readable offline after first visit. New posts need only ~4 seconds of uplink |
| Text-only clients (Meshtastic, packet radio, lynx)   | 99 % of modern blogs are JavaScript-only             | 100 % functional in w3m, links, or a 300-baud terminal |
| Power is scarce (solar Pi, phone in the desert)      | Always-on containers burn watts for nothing          | Zero compute when idle. D1 + Workers sleep completely |
| Hostile networks (DPI, censorship, no DNS)           | Third-party analytics + CDN beacons = instant fingerprint | Zero external requests by default. Analytics are private to the instance |
| You might have to post over email, SMS, or LoRa      | Normal dashboards require a browser + stable link    | Admin dashboard works over SMTP/IMAP. Post from a burner address if you have to |

Deadlight is part of a larger ecosystem (edge.deadlight) that also includes a C-based VPN/proxy gateway and an Internet-over-LoRa bridge, but the blog itself is deliberately minimal, auditable, and stupidly resilient.

## Why people are quietly moving to Deadlight

- Runs with zero always-on servers – Cloudflare Workers + D1 = no electricity bill when nobody is reading
- Works over Meshtastic/LoRa – a single post is 3–8 KB. That’s <10 seconds at 5 kbps
- No JavaScript required to read – try it: `curl https://thatch-dt.deadlight.boo/post/use-cases`
- Can be updated over email – SMTP → new article. No browser needed
- No trackers, no analytics beacons, no fingerprinting by default
- ~8 npm dependencies total – you can read the entire codebase in one sitting
- Deployable from a phone in Termux (yes, really)

## Live demos

- https://deadlight.boo – full-featured instance with admin dashboard
- https://thatch-dt.deadlight.boo – zero-JS, minimal theme (perfect for lynx / slow links)
- https://threat-level-midnight.deadlight.boo – isolated test deployment
- https://meshtastic.deadlight.boo – blog that is literally published over LoRa mesh

## Quick start (works on Raspberry Pi, PinePhone, Android Termux, or any laptop)

```bash
git clone https://github.com/gnarzilla/blog.deadlight
cd blog.deadlight
npm install

npx wrangler login
npx wrangler d1 create my-blog
npx wrangler d1 execute my-blog --remote --file=migrations/20250911_schema.sql

# Create admin user (remote, no local D1 needed)
./scripts/gen-admin/seed-dev.sh -r

# Secrets
openssl rand -base64 32 | wrangler secret put JWT_SECRET
echo "https://your-domain.pages.dev" | wrangler secret put SITE_URL

npx wrangler deploy
