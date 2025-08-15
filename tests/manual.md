# Manual Test Cases for Federation
- Send federated post to trusted domain: Should succeed, appear in `posts` with `federation_sent_at`.
- Send post to untrusted domain: Should reject with 'untrusted_domain'.
- Receive duplicate post: Should skip with 'duplicate' status.
- Process queue with proxy offline: Should retry up to 3 times, update `retry_count` and `last_error`.
- Inject email via /admin/fetch-emails: Should skip duplicates based on `message_id`.
- Discover new domain: Should send discovery email and update `federation_trust`.
