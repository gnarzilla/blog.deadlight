# Security Best Practices

## For Instance Admins

### 1. Secure Your JWT Secret
```bash
# Generate a strong secret
openssl rand -base64 32 | npx wrangler secret put JWT_SECRET
```

### 2. Enable Rate Limiting
Unless running behind `proxy.deadlight`, keep rate limiting enabled:
```toml
# wrangler.toml
DISABLE_RATE_LIMITING = "false"
```

### 3. Configure CSRF
CSRF protection is automatic. Ensure all forms include the token:
```html
<form method="POST" action="/admin/delete/123">
  <input type="hidden" name="csrf_token" value="${csrfToken}">
  <button>Delete</button>
</form>
```

### 4. Monitor Analytics
Check `/admin/analytics` for suspicious patterns:
- Unusual vote patterns
- Failed login attempts
- High error rates

## For Developers

### Adding New Protected Routes
```javascript
// Always use middleware for protection
router.group([authMiddleware, csrfValidateMiddleware], (r) => {
  r.register('/my-route', myHandler);
});
```

### CSRF Token in Templates
```javascript
export function renderMyForm(data, user, config, csrfToken) {
  return `
    <form method="POST">
      <input type="hidden" name="csrf_token" value="${csrfToken}">
      <!-- form fields -->
    </form>
  `;
}
```

## Reporting Security Issues

Email: security@deadlight.boo
PGP Key: [link]
```

---
