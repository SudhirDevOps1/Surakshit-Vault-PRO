# Surakshit Vault PRO — Backend

Cloudflare Workers + D1 + R2 + KV backend for optional cloud sync.

**Full documentation:** See [`../BACKEND.md`](../BACKEND.md) in the root.

## Quick Deploy

```bash
cd backend
npm install
wrangler login

# Create resources
wrangler d1 create surakshit-vault-db
wrangler r2 bucket create surakshit-vault-blobs
wrangler kv namespace create RATE_LIMIT

# Copy IDs into wrangler.toml, then:
npm run db:init:remote

# Set secrets
wrangler secret put JWT_SECRET
wrangler secret put TURNSTILE_SECRET
wrangler secret put IP_HASH_SALT

# Deploy
npm run deploy
```

**Copy Worker source code** from [`../BACKEND.md`](../BACKEND.md) → `src/index.ts` section.

© 2026 Surakshit Labs Pvt. Ltd.
