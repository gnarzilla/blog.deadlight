## Troubleshooting

### Federation Issues

**Error 1101 when sending to another instance**
- Wait 1-2 minutes for Cloudflare Workers deployment to propagate globally
- Check Cloudflare Workers logs for the exact error
- Verify target instance has federation enabled: `curl https://target/.well-known/deadlight`

**Posts not appearing in federation inbox**
- Check target instance's `/dashboard/inbox` (admin only)
- Federated posts require admin approval by default
- Check email fallback: look for messages to `federation@target-domain.tld`

**Discovery endpoint returns 404**
- Redeploy Workers: `wrangler deploy`
- Verify route is registered in `src/index.js`
- Check `/.well-known/deadlight` is in public routes group
