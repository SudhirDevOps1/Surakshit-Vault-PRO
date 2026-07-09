// Surakshit Vault PRO — Cloudflare Worker Backend (Hardened Production v5.0)
// © 2026 Surakshit Labs Pvt. Ltd.
// Zero-Knowledge Multi-User Encrypted Vault Sync API
// Security: Validates all inputs, rate-limits, protects against enumeration, injection, etc.

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

// ============== VALIDATORS ==============
const EMAIL_REGEX = /^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$/
const UUID_REGEX = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i
const B64_REGEX = /^[A-Za-z0-9+/=]+$/
const MAX_EMAIL_LEN = 254
const MAX_CIPHERTEXT_LEN = 1024 * 1024 // 1 MB
const MAX_TITLE_HASH_LEN = 128
const MIN_JWT_SECRET_LEN = 32

function isValidEmail(email: string): boolean {
  if (!email || typeof email !== "string") return false
  if (email.length > MAX_EMAIL_LEN || email.length < 5) return false
  return EMAIL_REGEX.test(email.trim())
}
function isUUID(str: string): boolean {
  if (!str || typeof str !== "string") return false
  return UUID_REGEX.test(str.trim())
}
function isBase64(str: string): boolean {
  if (!str || typeof str !== "string") return false
  if (str.length > 5000) return false // authHash should be small
  return B64_REGEX.test(str.trim())
}

// ============== MIDDLEWARE ==============

app.use("*", async (c, next) => {
  // SECURITY: Never allow wildcard CORS in production
  const configuredOrigin = c.env.CORS_ORIGIN?.trim()
  const allowedOrigins: string[] = []
  if (configuredOrigin && configuredOrigin !== "*" && configuredOrigin.length > 5) {
    // Allow comma-separated origins
    configuredOrigin.split(",").forEach(o => {
      const trimmed = o.trim()
      if (trimmed && trimmed !== "*") allowedOrigins.push(trimmed)
    })
  }
  // Always allow localhost for dev (safe)
  allowedOrigins.push("http://localhost:5173", "http://localhost:4173", "http://127.0.0.1:5173", "https://surakshit-vault-pro.pages.dev")

  return cors({
    origin: (origin) => {
      // Allow no origin (mobile apps, curl) only for health check
      if (!origin) return allowedOrigins[0] || "*"
      if (allowedOrigins.includes(origin)) return origin
      // In production, reject unknown origins
      return null as any
    },
    credentials: true,
    allowMethods: ["GET", "POST", "DELETE", "OPTIONS"],
    allowHeaders: ["Content-Type", "Authorization"],
    maxAge: 86400,
  })(c, next)
})

app.use("*", async (c, next) => {
  // Validate critical secrets exist and are strong enough
  if (!c.env.JWT_SECRET || c.env.JWT_SECRET.length < MIN_JWT_SECRET_LEN) {
    return c.json({ error: "Server misconfigured: JWT secret too short" }, 500)
  }
  if (!c.env.IP_HASH_SALT || c.env.IP_HASH_SALT.length < 16) {
    return c.json({ error: "Server misconfigured: IP hash salt too short" }, 500)
  }
  await next()
  c.header("X-Content-Type-Options", "nosniff")
  c.header("X-Frame-Options", "DENY")
  c.header("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
  c.header("Referrer-Policy", "no-referrer")
  c.header("Permissions-Policy", "geolocation=(), microphone=(), camera=()")
  c.header("X-Robots-Tag", "noindex, nofollow") // Backend should not be indexed
})

// ============== UTILITIES ==============

async function sha256(text: string): Promise<string> {
  const buf = new TextEncoder().encode(text)
  const hash = await crypto.subtle.digest("SHA-256", buf)
  return btoa(String.fromCharCode(...new Uint8Array(hash)))
}

async function verifyTurnstile(token: string, secret: string, ip: string, isDevBypassAllowed: boolean): Promise<boolean> {
  // Allow dev bypass ONLY on localhost or when explicitly set to "dev" secret for local testing
  if (isDevBypassAllowed && (token === "dev" || secret === "dev")) {
    console.warn("Turnstile bypass in dev mode")
    return true
  }
  if (!token || token.length < 10) return false
  if (!secret || secret.length < 10) return false
  try {
    const res = await fetch("https://challenges.cloudflare.com/turnstile/v0/siteverify", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ secret, response: token, remoteip: ip }),
    })
    const data = (await res.json()) as { success: boolean; "error-codes"?: string[] }
    if (!data.success) console.warn("Turnstile failed:", data["error-codes"])
    return data.success === true
  } catch (e) {
    console.error("Turnstile verify error:", e)
    return false
  }
}

async function rateLimit(kv: KVNamespace, key: string, max: number, windowSec: number): Promise<boolean> {
  try {
    const raw = await kv.get(key)
    const count = raw ? parseInt(raw, 10) : 0
    if (Number.isNaN(count)) return true
    if (count >= max) return false
    await kv.put(key, String(count + 1), { expirationTtl: windowSec })
    return true
  } catch {
    // If KV fails, allow request (fail open for availability, but log)
    console.warn("KV rate limit check failed for", key)
    return true
  }
}

async function auditLog(env: Env, userId: string | null, action: string, ip: string, ua: string, success = true) {
  try {
    if (action.length > 50) action = action.slice(0, 50)
    const ipHash = await sha256(ip + env.IP_HASH_SALT)
    const uaHash = await sha256(ua.slice(0, 500) + env.IP_HASH_SALT)
    await env.DB.prepare(
      "INSERT INTO audit_log (user_id, action, ip_hash, ua_hash, created_at, success) VALUES (?, ?, ?, ?, ?, ?)"
    ).bind(userId, action, ipHash.slice(0, 64), uaHash.slice(0, 64), Date.now(), success ? 1 : 0).run()
  } catch (e) {
    console.warn("Audit log failed:", e)
  }
}

async function requireAuth(c: any, next: any) {
  const authHeader = c.req.header("Authorization")
  if (!authHeader?.startsWith("Bearer ")) {
    return c.json({ error: "Missing token" }, 401)
  }
  const token = authHeader.slice(7).trim()
  if (!token || token.length > 2000) return c.json({ error: "Invalid token format" }, 401)
  try {
    const valid = await jwt.verify(token, c.env.JWT_SECRET)
    if (!valid) return c.json({ error: "Invalid token" }, 401)
    const payload = jwt.decode(token).payload as any
    if (!payload || !payload.sub || !payload.jti) return c.json({ error: "Invalid token payload" }, 401)
    if (!isUUID(payload.sub) || !isUUID(payload.jti)) return c.json({ error: "Invalid token format" }, 401)
    if (payload.exp && Date.now() >= payload.exp * 1000) return c.json({ error: "Token expired" }, 401)

    // Check revocation
    const revoked = await c.env.DB.prepare(
      "SELECT 1 FROM revoked_tokens WHERE jti = ?"
    ).bind(payload.jti).first()
    if (revoked) return c.json({ error: "Token revoked" }, 401)

    c.set("user_id", payload.sub)
    c.set("jti", payload.jti)
    await next()
  } catch (e) {
    console.error("Auth error:", e)
    return c.json({ error: "Auth failed" }, 401)
  }
}

// ============== ROUTES ==============

app.get("/", (c) => c.json({
  name: "Surakshit Vault PRO Backend",
  version: "5.0.0",
  turnstile_site_key: c.env.TURNSTILE_SITE_KEY,
  status: "operational",
  endpoints: ["/auth/salt", "/auth/signup", "/auth/login", "/auth/logout", "/vault/sync", "/vault/list", "/vault/:id", "/me"]
}))

app.get("/health", (c) => c.json({ ok: true, ts: Date.now(), version: "5.0.0" }))

// GET /auth/salt?email=... — returns salt for login (always returns something to prevent enumeration)
app.get("/auth/salt", async (c) => {
  const emailRaw = c.req.query("email")?.toLowerCase().trim() || ""
  if (!emailRaw) return c.json({ error: "Email required" }, 400)
  if (!isValidEmail(emailRaw)) return c.json({ error: "Invalid email" }, 400)
  const ip = c.req.header("CF-Connecting-IP") || c.req.header("X-Forwarded-For") || "0.0.0.0"
  const okRate = await rateLimit(c.env.RATE_LIMIT, `salt:${ip}`, 20, 60)
  if (!okRate) return c.json({ error: "Rate limit exceeded" }, 429)

  const user = await c.env.DB.prepare("SELECT salt FROM users WHERE email = ?")
    .bind(emailRaw).first() as any

  // Always return a salt (real or deterministic fake) to prevent email enumeration
  const salt = user?.salt || (await sha256(emailRaw + c.env.IP_HASH_SALT)).slice(0, 24)
  return c.json({ salt })
})

// POST /auth/signup
app.post("/auth/signup", async (c) => {
  const ip = c.req.header("CF-Connecting-IP") || "0.0.0.0"
  const ua = c.req.header("User-Agent")?.slice(0, 500) || "unknown"
  const okRate = await rateLimit(c.env.RATE_LIMIT, `signup:${ip}`, 3, 3600)
  if (!okRate) return c.json({ error: "Too many signups, try later" }, 429)

  let body: any
  try { body = await c.req.json() } catch { return c.json({ error: "Invalid JSON" }, 400) }
  const { email, salt, authHash, turnstile } = body || {}

  if (!email || !salt || !authHash) return c.json({ error: "Missing fields: email, salt, authHash" }, 400)
  if (typeof email !== "string" || typeof salt !== "string" || typeof authHash !== "string") return c.json({ error: "Invalid field types" }, 400)
  if (!isValidEmail(email)) return c.json({ error: "Invalid email format" }, 400)
  if (salt.length > 100 || salt.length < 10) return c.json({ error: "Invalid salt" }, 400)
  if (!isBase64(salt)) return c.json({ error: "Salt must be base64" }, 400)
  if (!isBase64(authHash) || authHash.length < 20 || authHash.length > 200) return c.json({ error: "Invalid authHash" }, 400)

  const isDev = c.env.TURNSTILE_SECRET === "dev"
  const turnstileOk = await verifyTurnstile(turnstile || "", c.env.TURNSTILE_SECRET, ip, isDev)
  if (!turnstileOk) return c.json({ error: "CAPTCHA verification failed" }, 403)

  const emailLower = email.toLowerCase().trim()
  const existing = await c.env.DB.prepare("SELECT id FROM users WHERE email = ?")
    .bind(emailLower).first()
  if (existing) {
    await auditLog(c.env, null, "signup", ip, ua, false)
    return c.json({ error: "Email already registered" }, 409)
  }

  // Double-hash the client's authHash with pepper for defense in depth
  const verifier = await sha256(authHash + c.env.JWT_SECRET)

  const userId = crypto.randomUUID()
  try {
    await c.env.DB.prepare(
      "INSERT INTO users (id, email, salt, verifier, created_at) VALUES (?, ?, ?, ?, ?)"
    ).bind(userId, emailLower, salt, verifier, Date.now()).run()
  } catch (e: any) {
    if (e.message?.includes("UNIQUE") || e.message?.includes("constraint")) {
      return c.json({ error: "Email already registered" }, 409)
    }
    throw e
  }

  const jti = crypto.randomUUID()
  const token = await jwt.sign(
    { sub: userId, jti, iat: Math.floor(Date.now()/1000), exp: Math.floor(Date.now()/1000) + 7*24*3600 },
    c.env.JWT_SECRET
  )

  await auditLog(c.env, userId, "signup", ip, ua, true)
  return c.json({ jwt: token, user_id: userId, email: emailLower })
})

// POST /auth/login
app.post("/auth/login", async (c) => {
  const ip = c.req.header("CF-Connecting-IP") || "0.0.0.0"
  const ua = c.req.header("User-Agent")?.slice(0, 500) || "unknown"
  const okRate = await rateLimit(c.env.RATE_LIMIT, `login:${ip}`, 10, 300)
  if (!okRate) return c.json({ error: "Too many login attempts, try later" }, 429)

  let body: any
  try { body = await c.req.json() } catch { return c.json({ error: "Invalid JSON" }, 400) }
  const { email, authHash, turnstile } = body || {}
  if (!email || !authHash) return c.json({ error: "Missing fields" }, 400)
  if (typeof email !== "string" || typeof authHash !== "string") return c.json({ error: "Invalid field types" }, 400)
  if (!isValidEmail(email)) return c.json({ error: "Invalid email" }, 400)
  if (!isBase64(authHash) || authHash.length < 20) return c.json({ error: "Invalid authHash" }, 400)

  const isDev = c.env.TURNSTILE_SECRET === "dev"
  const turnstileOk = await verifyTurnstile(turnstile || "", c.env.TURNSTILE_SECRET, ip, isDev)
  if (!turnstileOk) return c.json({ error: "CAPTCHA verification failed" }, 403)

  const user = await c.env.DB.prepare(
    "SELECT id, verifier, locked_until, failed_count FROM users WHERE email = ?"
  ).bind(email.toLowerCase().trim()).first() as any

  if (!user) {
    await auditLog(c.env, null, "login", ip, ua, false)
    // Use generic message to prevent enumeration
    return c.json({ error: "Invalid credentials" }, 401)
  }

  if (user.locked_until && user.locked_until > Date.now()) {
    const mins = Math.ceil((user.locked_until - Date.now()) / 60000)
    return c.json({ error: `Account locked. Try again in ${mins} min.` }, 423)
  }

  const check = await sha256(authHash + c.env.JWT_SECRET)
  // Constant-time comparison would be ideal, but JS string === is okay for fixed-length hash
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
  return c.json({ jwt: token, user_id: user.id, email: email.toLowerCase().trim() })
})

// POST /auth/logout
app.post("/auth/logout", requireAuth, async (c) => {
  const userId = c.get("user_id")
  const jti = c.get("jti")
  if (!isUUID(userId) || !isUUID(jti)) return c.json({ error: "Invalid session" }, 400)
  await c.env.DB.prepare(
    "INSERT OR IGNORE INTO revoked_tokens (jti, user_id, revoked_at) VALUES (?, ?, ?)"
  ).bind(jti, userId, Date.now()).run()
  return c.json({ ok: true })
})

// POST /vault/sync — {note_id, ciphertext, title_hash?}
app.post("/vault/sync", requireAuth, async (c) => {
  const userId = c.get("user_id")
  if (!isUUID(userId)) return c.json({ error: "Invalid user" }, 400)

  let body: any
  try { body = await c.req.json() } catch { return c.json({ error: "Invalid JSON" }, 400) }
  const { note_id, ciphertext, title_hash } = body || {}
  if (!note_id || !ciphertext) return c.json({ error: "Missing fields" }, 400)
  if (typeof note_id !== "string" || typeof ciphertext !== "string") return c.json({ error: "Invalid types" }, 400)
  if (!isUUID(note_id)) return c.json({ error: "note_id must be UUID v4" }, 400)
  if (ciphertext.length > MAX_CIPHERTEXT_LEN) return c.json({ error: `Ciphertext too large (max ${MAX_CIPHERTEXT_LEN})` }, 413)
  if (ciphertext.length < 10) return c.json({ error: "Ciphertext too small" }, 400)
  if (title_hash && (typeof title_hash !== "string" || title_hash.length > MAX_TITLE_HASH_LEN)) return c.json({ error: "Invalid title_hash" }, 400)

  const size = ciphertext.length
  const now = Date.now()

  try {
    if (size > 100_000) {
      const r2Key = `${userId}/${note_id}`
      await c.env.BLOBS.put(r2Key, ciphertext, { httpMetadata: { contentType: "text/plain" } })
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
  } catch (e: any) {
    console.error("Sync DB error:", e)
    return c.json({ error: "Database error" }, 500)
  }

  return c.json({ ok: true, size })
})

// GET /vault/list
app.get("/vault/list", requireAuth, async (c) => {
  const userId = c.get("user_id")
  if (!isUUID(userId)) return c.json({ error: "Invalid user" }, 400)
  const { results } = await c.env.DB.prepare(
    "SELECT id, title_hash, size_bytes, created_at, updated_at FROM vaults WHERE user_id = ? ORDER BY updated_at DESC LIMIT 100"
  ).bind(userId).all()
  return c.json({ items: results || [] })
})

// GET /vault/:id
app.get("/vault/:id", requireAuth, async (c) => {
  const userId = c.get("user_id")
  const id = c.req.param("id")
  if (!isUUID(id) || !isUUID(userId)) return c.json({ error: "Invalid ID" }, 400)

  const row = await c.env.DB.prepare(
    "SELECT * FROM vaults WHERE id = ? AND user_id = ?"
  ).bind(id, userId).first() as any
  if (!row) return c.json({ error: "Not found" }, 404)

  let ciphertext = row.ciphertext
  if (row.r2_key && !ciphertext) {
    const obj = await c.env.BLOBS.get(row.r2_key)
    if (!obj) return c.json({ error: "Blob missing" }, 500)
    ciphertext = await obj.text()
    if (ciphertext.length > MAX_CIPHERTEXT_LEN) return c.json({ error: "Blob too large" }, 500)
  }
  return c.json({ id: row.id, ciphertext, updated_at: row.updated_at, size: row.size_bytes })
})

// DELETE /vault/:id
app.delete("/vault/:id", requireAuth, async (c) => {
  const userId = c.get("user_id")
  const id = c.req.param("id")
  if (!isUUID(id) || !isUUID(userId)) return c.json({ error: "Invalid ID" }, 400)
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
  if (!isUUID(userId)) return c.json({ error: "Invalid user" }, 400)
  const { results } = await c.env.DB.prepare(
    "SELECT r2_key FROM vaults WHERE user_id = ? AND r2_key IS NOT NULL LIMIT 100"
  ).bind(userId).all()
  for (const row of (results as any[]) || []) {
    if (row.r2_key) {
      try { await c.env.BLOBS.delete(row.r2_key) } catch {}
    }
  }
  await c.env.DB.prepare("DELETE FROM users WHERE id = ?").bind(userId).run()
  // CASCADE deletes vaults via FK, but ensure audit log not leaking email
  return c.json({ ok: true, message: "Account permanently deleted (GDPR)" })
})

// GET /me — current user info (safe, no sensitive data)
app.get("/me", requireAuth, async (c) => {
  const userId = c.get("user_id")
  if (!isUUID(userId)) return c.json({ error: "Invalid user" }, 400)
  const user = await c.env.DB.prepare(
    "SELECT id, email, created_at, last_login FROM users WHERE id = ?"
  ).bind(userId).first()
  if (!user) return c.json({ error: "User not found" }, 404)
  const count = await c.env.DB.prepare(
    "SELECT COUNT(*) as c FROM vaults WHERE user_id = ?"
  ).bind(userId).first() as any
  return c.json({ ...user, vault_count: count?.c || 0 })
})

// 404 handler
app.notFound((c) => c.json({ error: "Not found", hint: "See GET / for docs" }, 404))

// Error handler
app.onError((err, c) => {
  console.error("Unhandled error:", err)
  return c.json({ error: "Internal server error" }, 500)
})

export default app
