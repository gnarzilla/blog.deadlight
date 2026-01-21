## Middleware Architecture

Deadlight uses a layered middleware approach for security and functionality:
```
Request
↓
Global Middleware (all routes)
├─ Error handling
├─ Logging
├─ Analytics
└─ Rate limiting (optional)
↓
Route-Specific Middleware
├─ Authentication (sets ctx.user)
├─ Authorization (admin check)
├─ CSRF token generation
└─ CSRF validation (POST/PUT/DELETE only)
↓
Route Handler
↓
Response
```

### Middleware Order

Order matters! Middleware executes in **reverse array order**:

```javascript
// src/index.js
router.group([
  authMiddleware,           // Runs FIRST (sets ctx.user)
  requireAdminMiddleware,   // Runs SECOND (checks role)
  csrfTokenMiddleware      // Runs THIRD (generates token)
], (r) => {
  // Admin routes
});
```

### Custom Middleware
Create your own middleware following this pattern:
```javascript
export async function myMiddleware(request, env, ctx, next) {
  // Pre-processing
  console.log('Before handler');
  
  // Call next middleware/handler
  const response = await next();
  
  // Post-processing
  console.log('After handler');
  
  return response;
}
```
