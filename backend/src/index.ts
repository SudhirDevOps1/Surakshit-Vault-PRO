// Surakshit Vault PRO — Cloudflare Worker Backend
// © 2026 Surakshit Labs Pvt. Ltd.
// Zero-Knowledge Multi-User Encrypted Vault Sync API

import { Hono } from "hono"
import { cors } from "hono/cors"
import * as jwt from "@tsndr/cloudflare-worker-jwt"

type Env = {
  DB: D1Database
  BLOBS: R2Bucket
  RATE_LIMIT: KVNamespace
  JWT_SECRET: string
  TURNSTILE_SECRET: string
  TURNSTILE_SITE_KEY: string
  IP_HASH_SALT: string
  CORS_ORIGIN: string
}

const app = new Hono<{ Bindings: Env; Variables: { user_id: string; jti: string } }>()

// ============== MIDDLEWARE ==============

app.use("*", async (c, next) => {
  const origin = c.env.CORS_ORIGIN || "*"
  return cors({
    origin: [origin, "http://localhost:5173", "http://localhost:4173"],
    credentials: true,
    allowMethods: ["GET", "POST", "DELETE", "OPTIONS"],
    allowHeaders: ["Content-Type", "Authorization"],
  })(c, next)
})

app.use("*", async (c, next) => {
  await next()
  c.header("X-Content-Type-Options", "nosniff")
  c.header("X-Frame-Options", "DENY")
  c.header("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
  c.header("Referrer-Policy", "no-referrer")
  c.header("Permissions-Policy", "geolocation=(), microphone=(), camera=()")
})

// ============== UTILITIES ==============

async function sha256(text: string): Promise<string> {
  const buf = new TextEncoder().encode(text)
  const hash = await crypto.subtle.digest("SHA-256", buf)
  return btoa(String.fromCharCode(...new Uint8Array(hash)))
}

async function verifyTurnstile(token: string, secret: string, ip: string): Promise<boolean> {
  if (!token) return false
  try {
    const res = await fetch("https://challenges.cloudflare.com/turnstile/v0/siteverify", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ secret, response: token, remoteip: ip }),
    })
    const data = (await res.json()) as { success: boolean }
    return data.success === true
  } catch {
    return false
  }
}

async function rateLimit(kv: KVNamespace, key: string, max: number, windowSec: number): Promise<boolean> {
  const raw = await kv.get(key)
  const count = raw ? parseInt(raw, 10) : 0
  if (count >= max) return false
  await kv.put(key, String(count + 1), { expirationTtl: windowSec })
  return true
}

async function auditLog(env: Env, userId: string | null, action: string, ip: string, ua: string, success = true) {
  try {
    const ipHash = await sha256(ip + env.IP_HASH_SALT)
    const uaHash = await sha256(ua + env.IP_HASH_SALT)
    await env.DB.prepare(
      "INSERT INTO audit_log (user_id, action, ip_hash, ua_hash, created_at, success) VALUES (?, ?, ?, ?, ?, ?)"
    ).bind(userId, action, ipHash, uaHash, Date.now(), success ? 1 : 0).run()
  } catch {}
}

async function requireAuth(c: any, next: any) {
  const authHeader = c.req.header("Authorization")
  if (!authHeader?.startsWith("Bearer ")) {
    return c.json({ error: "Missing token" }, 401)
  }
  const token = authHeader.slice(7)
  const valid = await jwt.verify(token, c.env.JWT_SECRET)
  if (!valid) return c.json({ error: "Invalid token" }, 401)
  const payload = jwt.decode(token).payload as any

  const revoked = await c.env.DB.prepare(
    "SELECT 1 FROM revoked_tokens WHERE jti = ?"
  ).bind(payload.jti).first()
  if (revoked) return c.json({ error: "Token revoked" }, 401)

  c.set("user_id", payload.sub)
  c.set("jti", payload.jti)
  await next()
}

// ============== ROUTES ==============

app.get("/", (c) => c.json({
  name: "Surakshit Vault PRO Backend",
  version: "1.0.0",
  turnstile_site_key: c.env.TURNSTILE_SITE_KEY,
  status: "operational"
}))

app.get("/health", (c) => c.json({ ok: true, ts: Date.now() }))

// GET /auth/salt?email=... — returns salt for login (always returns something to prevent enumeration)
app.get("/auth/salt", async (c) => {
  const email = c.req.query("email")?.toLowerCase().trim()
  if (!email) return c.json({ error: "Email required" }, 400)
  const ip = c.req.header("CF-Connecting-IP") || "0.0.0.0"
  const okRate = await rateLimit(c.env.RATE_LIMIT, `salt:${ip}`, 20, 60)
  if (!okRate) return c.json({ error: "Rate limit" }, 429)

  const user = await c.env.DB.prepare("SELECT salt FROM users WHERE email = ?")
    .bind(email).first() as any

  const salt = user?.salt || (await sha256(email + c.env.IP_HASH_SALT)).slice(0, 24)
  return c.json({ salt })
})

// POST /auth/signup
app.post("/auth/signup", async (c) => {
  const ip = c.req.header("CF-Connecting-IP") || "0.0.0.0"
  const ua = c.req.header("User-Agent") || "unknown"
  const okRate = await rateLimit(c.env.RATE_LIMIT, `signup:${ip}`, 3, 3600)
  if (!okRate) return c.json({ error: "Too many signups, try later" }, 429)

  const body = await c.req.json() as any
  const { email, salt, authHash, turnstile } = body
  if (!email || !salt || !authHash) return c.json({ error: "Missing fields" }, 400)

  const turnstileOk = await verifyTurnstile(turnstile, c.env.TURNSTILE_SECRET, ip)
  if (!turnstileOk) return c.json({ error: "CAPTCHA failed" }, 403)

  const existing = await c.env.DB.prepare("SELECT id FROM users WHERE email = ?")
    .bind(email.toLowerCase()).first()
  if (existing) {
    await auditLog(c.env, null, "signup", ip, ua, false)
    return c.json({ error: "Email already registered" }, 409)
  }

  const verifier = await sha256(authHash + c.env.JWT_SECRET)
  const userId = crypto.randomUUID()

  await c.env.DB.prepare(
    "INSERT INTO users (id, email, salt, verifier, created_at) VALUES (?, ?, ?, ?, ?)"
  ).bind(userId, email.toLowerCase(), salt, verifier, Date.now()).run()

  const jti = crypto.randomUUID()
  const token = await jwt.sign(
    { sub: userId, jti, iat: Math.floor(Date.now()/1000), exp: Math.floor(Date.now()/1000) + 7*24*3600 },
    c.env.JWT_SECRET
  )

  await auditLog(c.env, userId, "signup", ip, ua, true)
  return c.json({ jwt: token, user_id: userId, email: email.toLowerCase() })
})

// POST /auth/login
app.post("/auth/login", async (c) => {
  const ip = c.req.header("CF-Connecting-IP") || "0.0.0.0"
  const ua = c.req.header("User-Agent") || "unknown"
  const okRate = await rateLimit(c.env.RATE_LIMIT, `login:${ip}`, 10, 300)
  if (!okRate) return c.json({ error: "Too many attempts, try later" }, 429)

  const body = await c.req.json() as any
  const { email, authHash, turnstile } = body
  if (!email || !authHash) return c.json({ error: "Missing fields" }, 400)

  const turnstileOk = await verifyTurnstile(turnstile, c.env.TURNSTILE_SECRET, ip)
  if (!turnstileOk) return c.json({ error: "CAPTCHA failed" }, 403)

  const user = await c.env.DB.prepare(
    "SELECT id, verifier, locked_until, failed_count FROM users WHERE email = ?"
  ).bind(email.toLowerCase()).first() as any

  if (!user) {
    await auditLog(c.env, null, "login", ip, ua, false)
    return c.json({ error: "Invalid credentials" }, 401)
  }

  if (user.locked_until && user.locked_until > Date.now()) {
    const mins = Math.ceil((user.locked_until - Date.now()) / 60000)
    return c.json({ error: `Account locked. Try again in ${mins} min.` }, 423)
  }

  const check = await sha256(authHash + c.env.JWT_SECRET)
  if (check !== user.verifier) {
    const newCount = (user.failed_count || 0) + 1
    const lockUntil = newCount >= 5 ? Date.now() + 15*60*1000 : null
    await c.env.DB.prepare(
      "UPDATE users SET failed_count = ?, locked_until = ? WHERE id = ?"
    ).bind(newCount, lockUntil, user.id).run()
    await auditLog(c.env, user.id, "login", ip, ua, false)
    return c.json({ error: "Invalid credentials" }, 401)
  }

  await c.env.DB.prepare(
    "UPDATE users SET failed_count = 0, locked_until = NULL, last_login = ? WHERE id = ?"
  ).bind(Date.now(), user.id).run()

  const jti = crypto.randomUUID()
  const token = await jwt.sign(
    { sub: user.id, jti, iat: Math.floor(Date.now()/1000), exp: Math.floor(Date.now()/1000) + 7*24*3600 },
    c.env.JWT_SECRET
  )

  await auditLog(c.env, user.id, "login", ip, ua, true)
  return c.json({ jwt: token, user_id: user.id, email: email.toLowerCase() })
})

// POST /auth/logout
app.post("/auth/logout", requireAuth, async (c) => {
  const userId = c.get("user_id")
  const jti = c.get("jti")
  await c.env.DB.prepare(
    "INSERT OR IGNORE INTO revoked_tokens (jti, user_id, revoked_at) VALUES (?, ?, ?)"
  ).bind(jti, userId, Date.now()).run()
  return c.json({ ok: true })
})

// POST /vault/sync
app.post("/vault/sync", requireAuth, async (c) => {
  const userId = c.get("user_id")
  const body = await c.req.json() as any
  const { note_id, ciphertext, title_hash } = body
  if (!note_id || !ciphertext) return c.json({ error: "Missing fields" }, 400)

  const size = ciphertext.length
  const now = Date.now()

  if (size > 100_000) {
    const r2Key = `${userId}/${note_id}`
    await c.env.BLOBS.put(r2Key, ciphertext)
    await c.env.DB.prepare(
      `INSERT OR REPLACE INTO vaults (id, user_id, title_hash, r2_key, ciphertext, size_bytes, created_at, updated_at)
       VALUES (?, ?, ?, ?, NULL, ?, COALESCE((SELECT created_at FROM vaults WHERE id = ?), ?), ?)`
    ).bind(note_id, userId, title_hash || null, r2Key, size, note_id, now, now).run()
  } else {
    await c.env.DB.prepare(
      `INSERT OR REPLACE INTO vaults (id, user_id, title_hash, ciphertext, r2_key, size_bytes, created_at, updated_at)
       VALUES (?, ?, ?, ?, NULL, ?, COALESCE((SELECT created_at FROM vaults WHERE id = ?), ?), ?)`
    ).bind(note_id, userId, title_hash || null, ciphertext, size, note_id, now, now).run()
  }

  return c.json({ ok: true, size })
})

// GET /vault/list
app.get("/vault/list", requireAuth, async (c) => {
  const userId = c.get("user_id")
  const { results } = await c.env.DB.prepare(
    "SELECT id, title_hash, size_bytes, created_at, updated_at FROM vaults WHERE user_id = ? ORDER BY updated_at DESC LIMIT 100"
  ).bind(userId).all()
  return c.json({ items: results })
})

// GET /vault/:id
app.get("/vault/:id", requireAuth, async (c) => {
  const userId = c.get("user_id")
  const id = c.req.param("id")
  const row = await c.env.DB.prepare(
    "SELECT * FROM vaults WHERE id = ? AND user_id = ?"
  ).bind(id, userId).first() as any
  if (!row) return c.json({ error: "Not found" }, 404)

  let ciphertext = row.ciphertext
  if (row.r2_key && !ciphertext) {
    const obj = await c.env.BLOBS.get(row.r2_key)
    if (!obj) return c.json({ error: "Blob missing" }, 500)
    ciphertext = await obj.text()
  }
  return c.json({ id: row.id, ciphertext, updated_at: row.updated_at, size: row.size_bytes })
})

// DELETE /vault/:id
app.delete("/vault/:id", requireAuth, async (c) => {
  const userId = c.get("user_id")
  const id = c.req.param("id")
  const row = await c.env.DB.prepare(
    "SELECT r2_key FROM vaults WHERE id = ? AND user_id = ?"
  ).bind(id, userId).first() as any
  if (row?.r2_key) await c.env.BLOBS.delete(row.r2_key)
  await c.env.DB.prepare("DELETE FROM vaults WHERE id = ? AND user_id = ?")
    .bind(id, userId).run()
  return c.json({ ok: true })
})

// DELETE /account — GDPR permanent deletion
app.delete("/account", requireAuth, async (c) => {
  const userId = c.get("user_id")
  const { results } = await c.env.DB.prepare(
    "SELECT r2_key FROM vaults WHERE user_id = ? AND r2_key IS NOT NULL"
  ).bind(userId).all()
  for (const row of results as any[]) {
    if (row.r2_key) await c.env.BLOBS.delete(row.r2_key)
  }
  await c.env.DB.prepare("DELETE FROM users WHERE id = ?").bind(userId).run()
  return c.json({ ok: true, message: "Account permanently deleted (GDPR)" })
})

// GET /me — current user info
app.get("/me", requireAuth, async (c) => {
  const userId = c.get("user_id")
  const user = await c.env.DB.prepare(
    "SELECT id, email, created_at, last_login FROM users WHERE id = ?"
  ).bind(userId).first()
  if (!user) return c.json({ error: "User not found" }, 404)
  const count = await c.env.DB.prepare(
    "SELECT COUNT(*) as c FROM vaults WHERE user_id = ?"
  ).bind(userId).first() as any
  return c.json({ ...user, vault_count: count?.c || 0 })
})

export default app
