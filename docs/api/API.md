
## API Documentation

### Public Monitoring Endpoints

These endpoints do not require authentication and are safe to expose for uptime checks and monitoring.

GET /api/health

Returns a minimal heartbeat response.

Response:

{
  "status": "ok",
  "timestamp": "2025-09-15T12:00:00.000Z",
  "version": "5.0.0"
}


---

GET /api/status

Returns detailed service/component status.

Response:

{
  "status": "operational",
  "components": {
    "database": "healthy",
    "proxy": "healthy",
    "worker": "healthy"
  },
  "timestamp": "2025-09-15T12:01:00.000Z"
}

database → DB connection check

proxy → health check against env.PROXY_URL

worker → always reported from current worker context


---

### Blog API Endpoints

These expose blog content as JSON. Useful for headless consumption (mobile apps, static site builders, integrations).

GET /api/blog/status

Returns blog service status and enabled features.

Response:

{
  "status": "running",
  "version": "5.0.0",
  "features": [
    "email_integration",
    "federation",
    "proxy_support"
  ]
}


---

GET /api/blog/posts?limit=10&offset=0

Fetches a paginated list of published posts.

Response:

{
  "posts": [
    {
      "id": 1,
      "title": "Hello Deadlight",
      "slug": "hello-deadlight",
      "content": "...",
      "author_id": 1,
      "published": true,
      "created_at": "2025-09-15T10:00:00.000Z"
    }
  ],
  "total": 1,
  "limit": 10,
  "offset": 0
}


---

### Email Integration Endpoints

These routes enable email → blog workflows and inbox/reply handling.
Authentication is required (middleware sets request.user).

POST /api/email/receive

Receives a single email payload. If sent to blog@ or flagged as is_blog_post, the email becomes a draft blog post.

Request:

{
  "from": "alice@example.com",
  "to": "blog@deadlight.boo",
  "subject": "My First Email Post",
  "body": "Hello world!\nThis is an email-to-blog test.",
  "timestamp": "2025-09-15T09:00:00.000Z",
  "federation": {
    "enabled": true,
    "auto_federate": true
  }
}

Response (blog post created):

{
  "status": "success",
  "message": "Email converted to blog post",
  "blog_post_id": "42",
  "blog_url": "https://deadlight.boo/posts/my-first-email-post",
  "federation_status": "queued"
}

Response (stored as inbox email):

{
  "status": "success",
  "message": "Email received and stored",
  "email_id": 1337
}


---

POST /api/email/fetch

Bulk import multiple emails (e.g. from IMAP/POP3).

Request:

{
  "emails": [
    {
      "from": "bob@example.com",
      "to": "me@deadlight.boo",
      "subject": "Quick update",
      "body": "Just checking in.",
      "date": "2025-09-14T18:30:00.000Z"
    }
  ]
}

Response:

{
  "success": true,
  "inserted": 1,
  "total": 1
}


---

GET /api/email/pending-replies

Lists queued reply drafts that have not been marked as sent.

Response:

{
  "success": true,
  "replies": [
    {
      "id": 5,
      "to": "bob@example.com",
      "from": "deadlight.boo@gmail.com",
      "subject": "Re: Quick update",
      "body": "Thanks for your message!",
      "original_id": 1337,
      "queued_at": "2025-09-15T10:15:00.000Z"
    }
  ],
  "count": 1
}


---

POST /api/email/pending-replies

Marks a queued reply as sent.

Request:

{
  "id": 5
}

Response:

{
  "success": true,
  "id": 5,
  "sent_at": "2025-09-15T11:00:00.000Z"
}


---

### Legacy & Admin Endpoints

These routes remain for backward compatibility and administrative use:

/post/:id → view a single blog post (HTML)

/admin/* → administrative panel (HTML forms)



---

### Federation Workflow

Although federation does not yet expose direct endpoints, it is triggered automatically by:

POST /api/email/receive → if federation.auto_federate=true

Federation service (FederationService) queues distribution to connected domains.


Future documentation should include explicit federation endpoints once they are stabilized.



---


### Public Endpoints
- GET / - Home page with posts
- GET /post/:id - Individual post
- GET /login - Login form
- POST /login - Authenticate
- GET /api/health          → {"status":"ok","timestamp":"...","version":"5.0.0"}
- GET /api/status          → {"status":"operational","components":{...}}
- GET /api/blog/status     → {"status":"running","features":["email_integration","federation","proxy_support"]}
- GET /api/blog/posts      → list of published posts (JSON, supports limit/offset)

### Protected Endpoints (require auth)
- GET /admin - Admin dashboard
- GET /admin/add - New post form
- POST /admin/add - Create post
- GET /admin/edit/:id - Edit post form
- POST /admin/edit/:id - Update post
- POST /admin/delete/:id - Delete post
- GET /admin/users - User management
- POST /admin/users/add - Create user
- POST /admin/users/delete/:id - Delete user

### Email & Federation
- POST /api/email/receive  → ingest email (JSON body), optional auto-federation
- POST /api/email/fetch    → bulk import emails (JSON body {emails: [...]})
- GET  /api/email/pending-replies → list queued reply drafts
- POST /api/email/pending-replies → mark reply as sent
