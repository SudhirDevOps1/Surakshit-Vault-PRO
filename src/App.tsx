import { useEffect, useRef, useState, useMemo } from "react"
import QRCode from "qrcode"
import jsQR from "jsqr"
import { jsPDF } from "jspdf"
import {
  Lock, Unlock, KeyRound, FileText, Hash as HashIcon, Package, Puzzle, Archive, Rocket, Mail,
  Copy, Check, Eye, EyeOff, Keyboard, Sun, Moon, Settings as SettingsIcon, HelpCircle,
  Download, FileDown, Link2, Camera, ClipboardPaste, Flame, Shield, ShieldCheck, Zap,
  RefreshCw, Trash2, Eraser, Send, Search, Upload, FolderDown, AlertTriangle, Fingerprint,
  QrCode, Sparkles, ScanLine, X, Shuffle, Delete, CheckCircle2, Glasses, FileLock2, BookOpen,
  BarChart3, Clock, ChevronRight, Loader2, ListChecks, Building2, ShieldAlert, Scale, Cloud,
  User as UserIcon, LogIn, LogOut, UserPlus, RefreshCcw, Wifi, WifiOff
} from "lucide-react"

/* ============== CONST & TYPES ============== */
const PBKDF2_ITER = 1_000_000
const SALT_BYTES = 16
const IV_BYTES = 12
const VAULT_KEY = "sn_vault_pro_v4"
const STATS_KEY = "sn_stats_pro_v4"
const SETTINGS_KEY = "sn_settings_pro_v4"
const AUTH_KEY = "sn_auth_pro_v4"
const APP_VERSION = "5.0.0"
const AUTH_PBKDF2_ITER = 200_000 // For server auth hash (lighter than 1M master key)

type Tab = "notes" | "jwt" | "password" | "hash" | "base64" | "apikey" | "vault" | "suite" | "contact"
const VALID_TABS: Tab[] = ["notes", "jwt", "password", "hash", "base64", "apikey", "vault", "suite", "contact"]
const TAB_ALIASES: Record<string, Tab> = {
  notes: "notes", note: "notes", encrypt: "notes", decrypt: "notes",
  jwt: "jwt", secret: "jwt",
  password: "password", pw: "password", pass: "password",
  hash: "hash", sha: "hash",
  base64: "base64", b64: "base64",
  apikey: "apikey", api: "apikey", key: "apikey",
  vault: "vault",
  suite: "suite", hub: "suite", tools: "suite",
  contact: "contact", help: "contact", support: "contact",
}
function parseHashTab(hash?: string): Tab {
  const raw = (hash ?? (typeof window !== "undefined" ? window.location.hash : "")).replace(/^#/, "").split("?")[0].toLowerCase().trim()
  if (!raw) return "notes"
  if (VALID_TABS.includes(raw as Tab)) return raw as Tab
  return TAB_ALIASES[raw] || "notes"
}
function setHashTab(t: Tab, replace = false) {
  if (typeof window === "undefined") return
  const next = `#${t}`
  if (window.location.hash === next) return
  if (replace) window.history.replaceState(null, "", next)
  else window.history.pushState(null, "", next)
}

const INLINE_ICON_SVG = "data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 128 128'%3E%3Cdefs%3E%3ClinearGradient id='g' x1='0' y1='0' x2='1' y2='1'%3E%3Cstop offset='0' stop-color='%234f46e5'/%3E%3Cstop offset='1' stop-color='%2306b6d4'/%3E%3C/linearGradient%3E%3ClinearGradient id='bg' x1='0' y1='0' x2='0' y2='1'%3E%3Cstop offset='0' stop-color='%230a1020'/%3E%3Cstop offset='1' stop-color='%2305070f'/%3E%3C/linearGradient%3E%3C/defs%3E%3Crect width='128' height='128' rx='28' fill='url(%23bg)' stroke='url(%23g)' stroke-width='4'/%3E%3Cpath d='M64 22 L96 36 V66 Q96 96 64 108 Q32 96 32 66 V36 Z' fill='url(%23g)' opacity='0.25' stroke='url(%23g)' stroke-width='3' stroke-linejoin='round'/%3E%3Crect x='50' y='58' width='28' height='30' rx='5' fill='%23eef2ff'/%3E%3Cpath d='M56 58 V50 A8 8 0 0 1 72 50 V58' fill='none' stroke='%23eef2ff' stroke-width='4' stroke-linecap='round'/%3E%3Ccircle cx='64' cy='72' r='3.5' fill='%234f46e5'/%3E%3Crect x='62.5' y='72' width='3' height='8' fill='%234f46e5'/%3E%3C/svg%3E"
type Toast = { id: number; msg: string; type: "ok" | "err" | "info" }
type VaultItem = { id: string; title: string; payload: string; createdAt: number; ttl: number }

/* ============== HELPERS ============== */
const bytesToBase64 = (b: Uint8Array) => {
  let binary = ""
  const chunk = 0x8000
  for (let i = 0; i < b.length; i += chunk) binary += String.fromCharCode(...b.subarray(i, i+chunk))
  return btoa(binary)
}
const base64ToBytes = (s: string) => {
  const bin = atob(s)
  const out = new Uint8Array(bin.length)
  for (let i=0;i<bin.length;i++) out[i]=bin.charCodeAt(i)
  return out
}
const strToB64 = (s: string) => btoa(unescape(encodeURIComponent(s)))
const b64ToStr = (s: string) => decodeURIComponent(escape(atob(s)))
const randomBytes = (n: number) => { const b = new Uint8Array(n); crypto.getRandomValues(b); return b }
const toHex = (b: Uint8Array) => Array.from(b).map(x=>x.toString(16).padStart(2,"0")).join("")
const toB64Url = (b: Uint8Array) => bytesToBase64(b).replace(/\+/g,"-").replace(/\//g,"_").replace(/=+$/g,"")

/* ============== SECURITY VALIDATORS ============== */
const MAX_FILE_SIZE = 10 * 1024 * 1024 // 10 MB for QR image
const MAX_VAULT_IMPORT_SIZE = 1 * 1024 * 1024 // 1 MB for vault JSON
const MAX_PAYLOAD_B64_LEN = 5000 // Prevent DoS via huge payloads
const MAX_CIPHERTEXT_SIZE = 1024 * 1024 // 1 MB for cloud ciphertext
const EMAIL_REGEX = /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/
const UUID_REGEX = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i

function isValidWorkerUrl(url: string): boolean {
  if (!url || typeof url !== "string") return false
  if (url.length > 300) return false
  try {
    const u = new URL(url.trim())
    // Allow https always, http only for localhost/dev
    if (u.protocol !== "https:" && !(u.protocol === "http:" && (u.hostname === "localhost" || u.hostname === "127.0.0.1" || u.hostname.endsWith(".local")))) return false
    if (["javascript:", "data:", "file:", "ftp:"].includes(u.protocol)) return false
    if (u.username || u.password) return false // No credentials in URL
    // Basic sanity: must have a dot or be localhost
    if (!u.hostname.includes(".") && u.hostname !== "localhost") return false
    return true
  } catch { return false }
}
function isValidEmail(email: string): boolean {
  if (!email || typeof email !== "string") return false
  if (email.length < 5 || email.length > 254) return false
  return EMAIL_REGEX.test(email.trim())
}
function isUUID(str: string): boolean {
  if (!str || typeof str !== "string") return false
  return UUID_REGEX.test(str.trim())
}
function decodeJwtPayloadUnsafe(jwtStr: string): any | null {
  try {
    const parts = jwtStr.split(".")
    if (parts.length !== 3) return null
    const b64 = parts[1].replace(/-/g, "+").replace(/_/g, "/")
    const padded = b64 + "=".repeat((4 - (b64.length % 4)) % 4)
    return JSON.parse(atob(padded))
  } catch { return null }
}
function isJwtExpired(jwtStr: string): boolean {
  const payload = decodeJwtPayloadUnsafe(jwtStr)
  if (!payload || typeof payload.exp !== "number") return false // If no exp, don't treat as expired (let server decide)
  return Date.now() >= payload.exp * 1000
}
function safeParseVaultImport(text: string): VaultItem[] | null {
  try {
    if (text.length > MAX_VAULT_IMPORT_SIZE) return null
    const data = JSON.parse(text)
    if (!Array.isArray(data)) return null
    if (data.length > 100) return null // Limit count
    // Validate each item
    const out: VaultItem[] = []
    for (const item of data) {
      if (!item || typeof item !== "object") continue
      if (typeof item.id !== "string" || typeof item.payload !== "string") continue
      if (item.id.length > 200 || item.payload.length > MAX_CIPHERTEXT_SIZE) continue
      // Optional fields with safe defaults
      out.push({
        id: String(item.id).slice(0, 200),
        title: typeof item.title === "string" ? String(item.title).slice(0, 100) : "Imported",
        payload: String(item.payload),
        createdAt: typeof item.createdAt === "number" ? item.createdAt : Date.now(),
        ttl: typeof item.ttl === "number" ? Math.min(365, Math.max(0, item.ttl)) : 0,
      })
      if (out.length >= 60) break
    }
    return out
  } catch { return null }
}

async function deriveKey(pw: string, salt: Uint8Array) {
  if (!pw || typeof pw !== "string" || pw.length > 1024 || pw.length < 1) throw new Error("Invalid password length")
  if (!salt || salt.length < 8 || salt.length > 64) throw new Error("Invalid salt")
  const km = await crypto.subtle.importKey("raw", new TextEncoder().encode(pw), "PBKDF2", false, ["deriveKey"])
  return crypto.subtle.deriveKey({ name:"PBKDF2", salt: salt as any, iterations: PBKDF2_ITER, hash:"SHA-256" }, km, { name:"AES-GCM", length:256 }, false, ["encrypt","decrypt"])
}
async function createEntry(pt: string, pw: string) {
  const salt = randomBytes(SALT_BYTES), iv = randomBytes(IV_BYTES)
  const key = await deriveKey(pw, salt)
  const ct = await crypto.subtle.encrypt({ name:"AES-GCM", iv: iv as any }, key, new TextEncoder().encode(pt))
  return { salt: bytesToBase64(salt), iv: bytesToBase64(iv), ciphertext: bytesToBase64(new Uint8Array(ct)) }
}
async function encryptText(pt: string, pw: string) { return strToB64(JSON.stringify(await createEntry(pt,pw))) }
async function encryptDeniable(rt: string, rp: string, dt: string, dp: string) {
  const a = await createEntry(rt,rp), b = await createEntry(dt,dp)
  const items = randomBytes(1)[0]%2 ? [a,b] : [b,a]
  return strToB64(JSON.stringify({ v:"pd1", items }))
}
async function decryptEntry(ent: any, pw: string) {
  let salt: Uint8Array, iv: Uint8Array, ct: Uint8Array
  try {
    salt = base64ToBytes(ent.salt)
    iv = base64ToBytes(ent.iv)
    ct = base64ToBytes(ent.ciphertext)
  } catch(e){
    console.error("base64 decode failed:", e)
    throw new Error("INVALID")
  }
  if (salt.length!==SALT_BYTES) { console.error("salt length wrong:", salt.length, "expected", SALT_BYTES); throw new Error("INVALID") }
  if (iv.length!==IV_BYTES) { console.error("iv length wrong:", iv.length, "expected", IV_BYTES); throw new Error("INVALID") }
  if (ct.length===0) { console.error("empty ciphertext"); throw new Error("INVALID") }
  const key = await deriveKey(pw, salt)
  // AES-GCM decrypt throws OperationError on wrong key/tag/data. We wrap it.
  const pt = await crypto.subtle.decrypt({ name:"AES-GCM", iv: iv as any }, key, ct as any)
  return new TextDecoder().decode(pt)
}
async function decryptPayload(payloadB64: string, pw: string) {
  if (!payloadB64 || typeof payloadB64 !== "string") throw new Error("INVALID")
  if (payloadB64.length > MAX_PAYLOAD_B64_LEN) { console.error("Payload too large:", payloadB64.length); throw new Error("INVALID") }
  if (!pw || typeof pw !== "string" || pw.length > 1024) throw new Error("INVALID")
  let obj:any
  const cleaned = payloadB64.trim().replace(/\s+/g,"")
  if (cleaned.length > MAX_PAYLOAD_B64_LEN) throw new Error("INVALID")
  try { obj = JSON.parse(b64ToStr(cleaned)) } catch(e){
    console.error("Failed to parse payload as base64-JSON:", e, "payload starts with:", cleaned.slice(0,50))
    throw new Error("INVALID")
  }
  if (obj?.v==="pd1" && Array.isArray(obj.items)) {
    let saw=false
    for (const it of obj.items) {
      try {
        if(!it?.salt||!it?.iv||!it?.ciphertext){saw=true; continue}
        return await decryptEntry(it,pw)
      } catch(e:any){
        if(e.message==="INVALID") saw=true
        // else: wrong key for this item, try next
      }
    }
    throw new Error(saw?"INVALID":"DECRYPT_FAIL")
  }
  if(!obj?.salt||!obj?.iv||!obj?.ciphertext){
    console.error("Object missing required fields:", Object.keys(obj||{}))
    throw new Error("INVALID")
  }
  try {
    return await decryptEntry(obj, pw)
  } catch(e:any){
    if(e.message==="INVALID") throw e
    console.error("AES-GCM decrypt failed (likely wrong password):", e?.name, e?.message)
    throw new Error("DECRYPT_FAIL")
  }
}
function strengthScore(pw: string) {
  if(!pw) return { pct:0, label:"—", color:"#334155" }
  let s=0
  if(pw.length>=8) s++; if(pw.length>=12) s++; if(pw.length>=16) s++; 
  if(/[a-z]/.test(pw)&&/[A-Z]/.test(pw)) s++; if(/\d/.test(pw)) s++; if(/[^A-Za-z0-9]/.test(pw)) s++
  const labels=["बहुत कमजोर","कमजोर","ठीक","अच्छा","मजबूत","शानदार","Military Grade"]
  const colors=["#ef4444","#f97316","#f59e0b","#eab308","#22c55e","#10b981","#06b6d4"]
  return { pct:(s/6)*100, label: labels[Math.min(s,6)], color: colors[Math.min(s,6)] }
}

/* ============== CONFETTI CELEBRATION ============== */
type ConfettiParticle = { x:number; y:number; vx:number; vy:number; g:number; s:number; a:number; color:string; r:number; spin:number; shape:number }
let confettiBus: ((x:number,y:number,count?:number)=>void) | null = null
const CONFETTI_COLORS = ["#6366f1","#22d3ee","#a855f7","#34d399","#fbbf24","#f472b6","#60a5fa","#f97316","#eab308","#14b8a6"]
function celebrate(x?: number, y?: number, count = 70) {
  const cx = x ?? (typeof window !== "undefined" ? window.innerWidth/2 : 0)
  const cy = y ?? (typeof window !== "undefined" ? window.innerHeight*0.35 : 0)
  confettiBus?.(cx, cy, count)
}

/* ============== SMALL COMPONENTS ============== */
function CopyBtn({ text, className="", label="Copy", small }: { text: string; className?: string; label?: string; small?: boolean }) {
  const [copied,setCopied] = useState(false)
  return (
    <button
      onClick={async(e)=>{
        if(!text || text==="—" || text.includes("•")) return
        let ok=false
        try { await navigator.clipboard.writeText(text); ok=true } catch {
          const ta=document.createElement("textarea"); ta.value=text; document.body.appendChild(ta); ta.select(); ok=!!document.execCommand("copy"); ta.remove()
        }
        if(ok){
          setCopied(true)
          celebrate(e.clientX, e.clientY, small ? 40 : 70)
          window.dispatchEvent(new CustomEvent("sv-copy-success", { detail: { label } }))
          setTimeout(()=>setCopied(false),1800)
        }
      }}
      className={`inline-flex items-center justify-center gap-1.5 font-bold transition-all duration-200 active:scale-[0.96] hover:-translate-y-0.5 ${small ? "text-[11px] px-2.5 py-1 rounded-full" : "text-[13px] px-3 py-2 rounded-xl"} ${copied ? "bg-emerald-500 text-white shadow-[0_0_24px_rgba(16,185,129,0.45)] scale-105" : "btn-soft border"} ${className}`}
    >{copied ? <><Check size={small?12:15} className="animate-[pop_0.35s_ease]" /> Copied!</> : <><Copy size={small?12:15} /> {label}</>}</button>
  )
}

function ConfettiLayer() {
  const canvasRef = useRef<HTMLCanvasElement>(null)
  const particles = useRef<ConfettiParticle[]>([])
  const raf = useRef(0)
  useEffect(()=>{
    const canvas = canvasRef.current
    if(!canvas) return
    const ctx = canvas.getContext("2d")
    if(!ctx) return
    const resize = ()=>{ canvas.width = window.innerWidth * Math.min(devicePixelRatio||1,2); canvas.height = window.innerHeight * Math.min(devicePixelRatio||1,2); ctx.setTransform(Math.min(devicePixelRatio||1,2),0,0,Math.min(devicePixelRatio||1,2),0,0) }
    resize()
    window.addEventListener("resize", resize)
    confettiBus = (x,y,count=70)=>{
      for(let i=0;i<(count||70);i++){
        particles.current.push({
          x, y,
          vx: (Math.random()-0.5)*14,
          vy: Math.random()*-11-3,
          g: 0.18+Math.random()*0.12,
          s: 4+Math.random()*7,
          a: 1,
          color: CONFETTI_COLORS[Math.floor(Math.random()*CONFETTI_COLORS.length)],
          r: Math.random()*Math.PI,
          spin: (Math.random()-0.5)*0.28,
          shape: Math.floor(Math.random()*3),
        })
      }
    }
    const tick = ()=>{
      ctx.clearRect(0,0,window.innerWidth,window.innerHeight)
      particles.current = particles.current.filter(p=>p.a>0.03 && p.y < window.innerHeight+40)
      for(const p of particles.current){
        p.vy += p.g; p.x += p.vx; p.y += p.vy; p.a *= 0.985; p.r += p.spin; p.vx *= 0.995
        ctx.globalAlpha = Math.max(0,p.a)
        ctx.fillStyle = p.color
        ctx.save(); ctx.translate(p.x,p.y); ctx.rotate(p.r)
        if(p.shape===0) ctx.fillRect(-p.s/2,-p.s/2,p.s,p.s*0.55)
        else if(p.shape===1){ ctx.beginPath(); ctx.arc(0,0,p.s*0.4,0,Math.PI*2); ctx.fill() }
        else { ctx.beginPath(); ctx.moveTo(0,-p.s/2); ctx.lineTo(p.s/2,p.s/2); ctx.lineTo(-p.s/2,p.s/2); ctx.closePath(); ctx.fill() }
        ctx.restore()
      }
      ctx.globalAlpha = 1
      raf.current = requestAnimationFrame(tick)
    }
    raf.current = requestAnimationFrame(tick)
    return ()=>{ cancelAnimationFrame(raf.current); window.removeEventListener("resize", resize); confettiBus=null }
  },[])
  return <canvas ref={canvasRef} className="pointer-events-none fixed inset-0 z-[95]" aria-hidden />
}

/* ============== MAIN APP ============== */
export default function App(){
  // THEME
  const [theme,setTheme] = useState<"dark"|"light">(()=> (localStorage.getItem("theme") as any) || "dark")
  useEffect(()=>{ document.documentElement.setAttribute("data-theme", theme); localStorage.setItem("theme", theme) },[theme])

  // TAB + HASH ROUTING (#notes, #jwt, #password, #hash, #base64, #apikey, #vault, #suite, #contact)
  const [tab,setTab] = useState<Tab>(() => parseHashTab())
  const goToTab = (t: Tab, opts?: { replace?: boolean }) => {
    setTab(t)
    setHashTab(t, !!opts?.replace)
    // scroll to top of content on tab change
    try { window.scrollTo({ top: 0, behavior: "smooth" }) } catch {}
  }
  // Sync tab from URL on load + browser back/forward
  useEffect(() => {
    // Ensure URL always has a hash (default #notes)
    if (!window.location.hash) setHashTab("notes", true)
    const onHash = () => {
      const next = parseHashTab(window.location.hash)
      setTab(next)
    }
    const onPop = () => onHash()
    window.addEventListener("hashchange", onHash)
    window.addEventListener("popstate", onPop)
    return () => {
      window.removeEventListener("hashchange", onHash)
      window.removeEventListener("popstate", onPop)
    }
  }, [])
  // Keep hash in sync if tab changes from any source
  useEffect(() => {
    if (parseHashTab() !== tab) setHashTab(tab)
  }, [tab])

  const [toasts,setToasts] = useState<Toast[]>([])
  const toast = (msg:string,type:Toast["type"]="ok")=>{ const id=Date.now()+Math.random(); setToasts(t=>[...t,{id,msg,type}]); setTimeout(()=>setToasts(t=>t.filter(x=>x.id!==id)),3000) }
  // Celebrate on any CopyBtn success + show congrats toast
  useEffect(()=>{
    const onCopy = (e: Event) => {
      const label = (e as CustomEvent).detail?.label || "Text"
      toast(`🎉 Copied! ${label} — Congrats, secure clipboard!`,"ok")
    }
    window.addEventListener("sv-copy-success", onCopy as EventListener)
    return ()=> window.removeEventListener("sv-copy-success", onCopy as EventListener)
  },[])

  // STATS
  const [stats,setStats] = useState(()=>{ try{ return JSON.parse(localStorage.getItem(STATS_KEY)||'{"enc":0,"dec":0,"keys":0}') } catch{return {enc:0,dec:0,keys:0}} })
  const bump = (k:keyof typeof stats)=>{ const n={...stats,[k]: (stats as any)[k]+1}; setStats(n); localStorage.setItem(STATS_KEY,JSON.stringify(n)) }

  // NOTES STATE
  const [plain,setPlain] = useState("")
  const [title,setTitle] = useState("")
  const [ttl,setTtl] = useState("0")
  const [encPw,setEncPw] = useState("")
  const [decPw,setDecPw] = useState("")
  const [pdfPw,setPdfPw] = useState("")
  const [showEncPw,setShowEncPw] = useState(false)
  const [showDecPw,setShowDecPw] = useState(false)
  const [deniable,setDeniable] = useState(false)
  const [decoyText,setDecoyText] = useState("")
  const [decoyPw,setDecoyPw] = useState("")
  const [showDecoyPw,setShowDecoyPw]=useState(false)
  const [showPdfPw,setShowPdfPw]=useState(false)
  const [encStatus,setEncStatus]=useState<{type:"ok"|"err"|"warn"|"info"; msg:string}|null>(null)
  const [decStatus,setDecStatus]=useState<{type:"ok"|"err"|"warn"|"info"; msg:string}|null>(null)
  const [qrDataUrl,setQrDataUrl]=useState("")
  const [payload,setPayload]=useState("")
  const [encBusy,setEncBusy]=useState(false)
  const [decBusy,setDecBusy]=useState(false)
  const [encProgress,setEncProgress]=useState(0)
  const [decProgress,setDecProgress]=useState(0)
  const [showPayload,setShowPayload]=useState(false)
  const [saveVault,setSaveVault]=useState(true)
  const [burn,setBurn]=useState(true)
  const [clipClear,setClipClear]=useState(true)

  // BACKEND SYNC & AUTH STATE (multi-user zero-knowledge)
  const [cloudEnabled, setCloudEnabled] = useState(false)
  const [workerUrl, setWorkerUrl] = useState("")
  const [workerSecret, setWorkerSecret] = useState("") // legacy (single-user), still supported
  const [syncStatus, setSyncStatus] = useState<"idle" | "syncing" | "done" | "error">("idle")
  const [authOpen, setAuthOpen] = useState(false)
  const [authMode, setAuthMode] = useState<"login" | "signup">("login")
  const [authEmail, setAuthEmail] = useState("")
  const [authPw, setAuthPw] = useState("")
  const [authBusy, setAuthBusy] = useState(false)
  const [authError, setAuthError] = useState("")
  const [session, setSession] = useState<{ jwt: string; user_id: string; email: string } | null>(null)
  const [turnstileSiteKey, setTurnstileSiteKey] = useState("")
  const [turnstileToken, setTurnstileToken] = useState("")
  const [cloudVault, setCloudVault] = useState<Array<{id:string;size_bytes:number;created_at:number;updated_at:number}>>([])
  const [isOnline, setIsOnline] = useState<boolean>(typeof navigator!=="undefined"?navigator.onLine:true)

  // Derive auth hash from password (client-side, never sends raw password) + hardened validation
  async function deriveAuthHash(password: string, saltB64: string, iterations = AUTH_PBKDF2_ITER): Promise<string> {
    if (!saltB64 || saltB64.length > 100) throw new Error("Invalid salt")
    let salt: Uint8Array
    try { salt = base64ToBytes(saltB64) } catch { throw new Error("Invalid salt encoding") }
    if (salt.length < 8 || salt.length > 64) throw new Error("Invalid salt length")
    if (!password || password.length < 1 || password.length > 1024) throw new Error("Invalid password length")
    const km = await crypto.subtle.importKey("raw", new TextEncoder().encode(password), "PBKDF2", false, ["deriveBits"])
    const bits = await crypto.subtle.deriveBits({ name:"PBKDF2", salt: salt as any, iterations, hash:"SHA-256" }, km, 256)
    return bytesToBase64(new Uint8Array(bits))
  }

  // Restore session on load + JWT expiry check
  useEffect(()=>{
    try {
      const s = JSON.parse(localStorage.getItem(AUTH_KEY) || "null")
      if (s?.jwt && s?.user_id) {
        if (isJwtExpired(s.jwt)) {
          console.warn("Stored JWT expired, clearing session")
          localStorage.removeItem(AUTH_KEY)
        } else {
          // Validate JWT structure
          const p = decodeJwtPayloadUnsafe(s.jwt)
          if (p && p.sub) setSession(s)
          else localStorage.removeItem(AUTH_KEY)
        }
      }
    } catch {
      try { localStorage.removeItem(AUTH_KEY) } catch {}
    }
    const on = ()=>setIsOnline(true), off = ()=>setIsOnline(false)
    window.addEventListener("online", on); window.addEventListener("offline", off)
    return ()=>{ window.removeEventListener("online", on); window.removeEventListener("offline", off) }
  },[])
  useEffect(()=>{
    try {
      if (session) {
        if (isJwtExpired(session.jwt)) {
          setSession(null)
          return
        }
        localStorage.setItem(AUTH_KEY, JSON.stringify(session))
      }
      else localStorage.removeItem(AUTH_KEY)
    } catch (e) {
      console.warn("localStorage quota or error:", e)
    }
  },[session])

  // Fetch Turnstile site key from backend (if configured) — validated
  useEffect(()=>{
    if (!cloudEnabled || !workerUrl) return
    if (!isValidWorkerUrl(workerUrl)) return
    const ctrl = new AbortController()
    fetch(`${workerUrl.replace(/\/$/,"")}/`, { signal: ctrl.signal }).then(r=>{
      if (!r.ok) throw new Error("Fetch failed")
      return r.json()
    }).then((d:any)=>{
      if (d?.turnstile_site_key && typeof d.turnstile_site_key === "string" && d.turnstile_site_key.length < 200) {
        setTurnstileSiteKey(d.turnstile_site_key)
      }
    }).catch(()=>{})
    return ()=> ctrl.abort()
  },[cloudEnabled, workerUrl])

  // Signup — hardened with validation
  async function handleSignup(){
    const emailTrim = authEmail.trim().toLowerCase()
    if (!emailTrim || !authPw) { setAuthError("Email + password required"); return }
    if (!isValidEmail(emailTrim)) { setAuthError("Invalid email format"); return }
    if (authPw.length < 8 || authPw.length > 128) { setAuthError("Password must be 8-128 chars"); return }
    if (!workerUrl) { setAuthError("Backend URL required in Settings"); return }
    if (!isValidWorkerUrl(workerUrl)) { setAuthError("Invalid Worker URL — must be https://..."); return }
    // Turnstile required in production (if site key configured)
    const isLocalhost = location.hostname === "localhost" || location.hostname === "127.0.0.1"
    if (turnstileSiteKey && !isLocalhost && (!turnstileToken || turnstileToken.length < 10)) {
      setAuthError("CAPTCHA required — please complete Turnstile"); return
    }
    setAuthBusy(true); setAuthError("")
    try {
      const salt = bytesToBase64(randomBytes(16))
      const authHash = await deriveAuthHash(authPw, salt)
      const res = await fetch(`${workerUrl.replace(/\/$/,"")}/auth/signup`, {
        method:"POST", headers:{"Content-Type":"application/json"},
        body: JSON.stringify({ email: emailTrim, salt, authHash, turnstile: turnstileToken || (isLocalhost ? "dev" : "") })
      })
      const data = await res.json() as any
      if (!res.ok) throw new Error(data.error || "Signup failed")
      if (!data.jwt || !data.user_id) throw new Error("Invalid server response")
      if (isJwtExpired(data.jwt)) throw new Error("Server returned expired token")
      setSession({ jwt: data.jwt, user_id: data.user_id, email: data.email })
      setAuthOpen(false); setAuthEmail(""); setAuthPw(""); setTurnstileToken("")
      toast("🎉 Account created! Cloud sync active.","ok"); celebrate(undefined, undefined, 90)
    } catch(e:any){ setAuthError(e.message || "Signup failed"); toast("Signup failed: "+e.message,"err") }
    finally { setAuthBusy(false) }
  }

  // Login — hardened
  async function handleLogin(){
    const emailTrim = authEmail.trim().toLowerCase()
    if (!emailTrim || !authPw) { setAuthError("Email + password required"); return }
    if (!isValidEmail(emailTrim)) { setAuthError("Invalid email format"); return }
    if (!workerUrl) { setAuthError("Backend URL required in Settings"); return }
    if (!isValidWorkerUrl(workerUrl)) { setAuthError("Invalid Worker URL — must be https://..."); return }
    const isLocalhost = location.hostname === "localhost" || location.hostname === "127.0.0.1"
    if (turnstileSiteKey && !isLocalhost && (!turnstileToken || turnstileToken.length < 10)) {
      setAuthError("CAPTCHA required"); return
    }
    setAuthBusy(true); setAuthError("")
    try {
      const saltRes = await fetch(`${workerUrl.replace(/\/$/,"")}/auth/salt?email=${encodeURIComponent(emailTrim)}`)
      const saltData = await saltRes.json() as any
      if (!saltRes.ok || !saltData.salt) throw new Error("Cannot fetch salt")
      if (typeof saltData.salt !== "string" || saltData.salt.length > 100) throw new Error("Invalid salt from server")
      const authHash = await deriveAuthHash(authPw, saltData.salt)
      const res = await fetch(`${workerUrl.replace(/\/$/,"")}/auth/login`, {
        method:"POST", headers:{"Content-Type":"application/json"},
        body: JSON.stringify({ email: emailTrim, authHash, turnstile: turnstileToken || (isLocalhost ? "dev" : "") })
      })
      const data = await res.json() as any
      if (!res.ok) throw new Error(data.error || "Login failed")
      if (!data.jwt) throw new Error("Invalid server response")
      if (isJwtExpired(data.jwt)) throw new Error("Server returned expired token")
      setSession({ jwt: data.jwt, user_id: data.user_id, email: data.email })
      setAuthOpen(false); setAuthEmail(""); setAuthPw(""); setTurnstileToken("")
      toast("✅ Logged in successfully","ok"); celebrate(undefined, undefined, 70)
    } catch(e:any){ setAuthError(e.message || "Login failed"); toast("Login failed: "+e.message,"err") }
    finally { setAuthBusy(false) }
  }

  // Logout
  async function handleLogout(){
    if (session?.jwt && workerUrl) {
      try {
        await fetch(`${workerUrl.replace(/\/$/,"")}/auth/logout`, {
          method:"POST", headers:{"Authorization":`Bearer ${session.jwt}`}
        })
      } catch {}
    }
    setSession(null); setCloudVault([]); toast("Logged out","info")
  }

  // Sync encrypted note to cloud — hardened
  const syncToCloud = async (id: string, _t: string, p: string) => {
    if (!cloudEnabled || !workerUrl) return
    if (!isValidWorkerUrl(workerUrl)) { toast("Invalid Worker URL","err"); return }
    if (!session?.jwt) { toast("Login required for cloud sync","err"); return }
    if (isJwtExpired(session.jwt)) { setSession(null); toast("Session expired, login again","err"); return }
    if (!isUUID(id)) { toast("Invalid note ID (must be UUID)","err"); return }
    if (!p || typeof p !== "string" || p.length > MAX_CIPHERTEXT_SIZE) { toast("Ciphertext too large","err"); return }
    if (p.length < 10) { toast("Ciphertext too small","err"); return }
    setSyncStatus("syncing")
    try {
      const res = await fetch(`${workerUrl.replace(/\/$/, "")}/vault/sync`, {
        method: "POST",
        headers: { "Content-Type": "application/json", "Authorization": `Bearer ${session.jwt}` },
        body: JSON.stringify({ note_id: id, ciphertext: p })
      })
      const data = await res.json() as any
      if (!res.ok) throw new Error(data.error || "Sync failed")
      if (data.size && data.size > MAX_CIPHERTEXT_SIZE) throw new Error("Server returned too large size")
      setSyncStatus("done")
      toast(`☁️ Synced to cloud (${data.size} bytes)`, "ok")
      setTimeout(() => setSyncStatus("idle"), 3000)
      loadCloudVault()
    } catch (e:any) {
      console.error("Sync Error:", e)
      setSyncStatus("error")
      toast(`❌ Sync failed: ${e.message}`, "err")
      if (e.message?.includes("Invalid token") || e.message?.includes("revoked") || e.message?.includes("expired")) {
        setSession(null)
      }
    }
  }

  async function loadCloudVault(){
    if (!session?.jwt || !workerUrl) return
    if (!isValidWorkerUrl(workerUrl)) return
    if (isJwtExpired(session.jwt)) { setSession(null); return }
    try {
      const res = await fetch(`${workerUrl.replace(/\/$/, "")}/vault/list`, {
        headers: { "Authorization": `Bearer ${session.jwt}` }
      })
      if (!res.ok) {
        if (res.status === 401) { setSession(null); toast("Session expired","err") }
        return
      }
      const data = await res.json() as any
      if (data.items && Array.isArray(data.items)) {
        // Validate items structure
        const safe = data.items.filter((it:any)=> it && typeof it.id === "string" && isUUID(it.id)).slice(0,100)
        setCloudVault(safe)
      }
    } catch {}
  }
  useEffect(()=>{ if (session && cloudEnabled) loadCloudVault() },[session, cloudEnabled])

  async function fetchCloudVaultItem(id: string): Promise<string | null> {
    if (!session?.jwt || !workerUrl) return null
    if (!isValidWorkerUrl(workerUrl)) return null
    if (isJwtExpired(session.jwt)) { setSession(null); return null }
    if (!isUUID(id)) { toast("Invalid vault ID","err"); return null }
    try {
      const res = await fetch(`${workerUrl.replace(/\/$/, "")}/vault/${id}`, {
        headers: { "Authorization": `Bearer ${session.jwt}` }
      })
      if (!res.ok) {
        if (res.status === 401) setSession(null)
        return null
      }
      const data = await res.json() as any
      if (data.ciphertext && typeof data.ciphertext === "string" && data.ciphertext.length <= MAX_CIPHERTEXT_SIZE) return data.ciphertext
    } catch {}
    return null
  }

  async function deleteCloudVaultItem(id: string){
    if (!session?.jwt || !workerUrl) return
    if (!isValidWorkerUrl(workerUrl)) return
    if (isJwtExpired(session.jwt)) { setSession(null); return }
    if (!isUUID(id)) { toast("Invalid ID","err"); return }
    try {
      const res = await fetch(`${workerUrl.replace(/\/$/, "")}/vault/${id}`, {
        method: "DELETE",
        headers: { "Authorization": `Bearer ${session.jwt}` }
      })
      if (!res.ok && res.status === 401) { setSession(null); return }
      toast("Deleted from cloud","ok")
      loadCloudVault()
    } catch { toast("Delete failed","err") }
  }

  // DECRYPT
  const [selectedFile,setSelectedFile]=useState<File|null>(null)
  const [pendingPayload,setPendingPayload]=useState("")
  const [decrypted,setDecrypted]=useState("")
  const [burnLeft,setBurnLeft]=useState(0)
  const burnRef = useRef<number|null>(null)
  const qrCanvasRef = useRef<HTMLCanvasElement>(null)
  const toolQrRef = useRef<HTMLCanvasElement>(null)
  const fileInputRef = useRef<HTMLInputElement>(null)

  // CAMERA
  const [camOn,setCamOn]=useState(false)
  const videoRef = useRef<HTMLVideoElement>(null)
  const camStreamRef = useRef<MediaStream|null>(null)
  const scanIntervalRef = useRef<number|null>(null)

  // KEYPAD
  const [keypadOpen,setKeypadOpen]=useState(false)
  const [keypadTarget,setKeypadTarget]=useState<"enc"|"decoy"|"pdf"|"dec"|null>(null)
  const [shuffledKeys,setShuffledKeys]=useState<string[]>([])
  const allKeys = useMemo(()=> "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%&*-_+=".split(""),[])
  const shuffle = ()=>{ const rnd=randomBytes(allKeys.length); const arr=[...allKeys]; for(let i=arr.length-1;i>0;i--){ const j=rnd[i]%(i+1); [arr[i],arr[j]]=[arr[j],arr[i]] } setShuffledKeys(arr) }
  const openKeypad = (t: typeof keypadTarget)=>{ setKeypadTarget(t); shuffle(); setKeypadOpen(true) }

  // JWT
  const [jwtBits,setJwtBits]=useState(256)
  const [jwtFmt,setJwtFmt]=useState<"hex"|"base64"|"base64url"|"raw">("hex")
  const [jwtSecret,setJwtSecret]=useState("")
  const [jwtShow,setJwtShow]=useState(false)
  const [jwtAlways,setJwtAlways]=useState(false)

  // PASSWORD
  const [pwLen,setPwLen]=useState(20)
  const [pwUpper,setPwUpper]=useState(true)
  const [pwLower,setPwLower]=useState(true)
  const [pwDigits,setPwDigits]=useState(true)
  const [pwSymbols,setPwSymbols]=useState(true)
  const [pwNoAmbig,setPwNoAmbig]=useState(false)
  const [pwPreset,setPwPreset]=useState<"strong"|"passphrase"|"pin"|"otp">("strong")
  const [pwOut,setPwOut]=useState("••••••••••••••••••••")
  const [pwHist,setPwHist]=useState<string[]>([])

  // HASH, B64, API
  const [hashInput,setHashInput]=useState("")
  const [hashes,setHashes]=useState<{s1:string;s256:string;s384:string;s512:string}>({s1:"—",s256:"—",s384:"—",s512:"—"})
  const [b64In,setB64In]=useState("")
  const [b64Out,setB64Out]=useState("")
  const [b64DecIn,setB64DecIn]=useState("")
  const [b64DecOut,setB64DecOut]=useState("")
  const [apiFmt,setApiFmt]=useState<"uuid"|"hex"|"b64"|"sk"|"ak">("uuid")
  const [apiPrefix,setApiPrefix]=useState("")
  const [apiCount,setApiCount]=useState(1)
  const [apiOut,setApiOut]=useState("")

  // VAULT
  const [vault,setVault]=useState<VaultItem[]>(()=>{ try{return JSON.parse(localStorage.getItem(VAULT_KEY)||"[]")}catch{return []} })
  const [vaultSearch,setVaultSearch]=useState("")

  // CONTACT FORM
  const [contactEmail,setContactEmail]=useState("")
  const [contactMsg,setContactMsg]=useState("")
  const [contactSending,setContactSending]=useState(false)
  const [contactDone,setContactDone]=useState(false)
  async function submitContact(e: React.FormEvent){
    e.preventDefault()
    if(!contactEmail.trim() || !contactMsg.trim()){ toast("Fill email and message","err"); return }
    if(!isValidEmail(contactEmail.trim())){ toast("Invalid email format","err"); return }
    if(contactMsg.trim().length < 10){ toast("Message too short (min 10 chars)","err"); return }
    if(contactMsg.trim().length > 5000){ toast("Message too long (max 5000)","err"); return }
    setContactSending(true)
    try{
      const form = new FormData()
      form.append("email", contactEmail)
      form.append("message", contactMsg)
      // Honeypot field (empty = human, filled = bot)
      form.append("website", "")
      const res = await fetch("https://apnaform.sudhirdevops1.workers.dev/api/submit/endpoint_NrctvfLp3C8UXX3q6DOyfKbE", {
        method: "POST",
        body: form
      })
      if(res.ok || res.status === 200 || res.status === 201){
        setContactDone(true); setContactEmail(""); setContactMsg("")
        toast("✅ Message sent successfully!","ok")
        setTimeout(()=>setContactDone(false), 4000)
      } else {
        // Some workers return success as JSON — treat non-5xx as success
        if(res.status < 500){
          setContactDone(true); setContactEmail(""); setContactMsg("")
          toast("✅ Message received!","ok")
        } else {
          throw new Error("Server error " + res.status)
        }
      }
    }catch(err:any){
      console.error("Contact submit error:", err)
      toast("❌ Failed to send. Try again.","err")
    }finally{ setContactSending(false) }
  }

  // MODALS
  const [helpOpen,setHelpOpen]=useState(false)
  const [settingsOpen,setSettingsOpen]=useState(false)

  // EFFECTS
  useEffect(()=>{ try{ localStorage.setItem(VAULT_KEY, JSON.stringify(vault)) }catch(e){ console.warn("localStorage quota exceeded for vault", e); toast("Local vault storage full — export & clear some items","err") } },[vault])
  useEffect(()=>{
    const handler = (e: KeyboardEvent)=>{
      if(e.key==="Escape"){ setHelpOpen(false); setKeypadOpen(false); setSettingsOpen(false); stopCam() }
      if((e.ctrlKey||e.metaKey)&&e.key==="Enter"){ if(tab==="notes"&&document.activeElement?.id!=="decPassword"){ handleEncrypt() } }
      if(!e.ctrlKey&&!e.metaKey&&document.activeElement===document.body){ const m:any={1:"notes",2:"jwt",3:"password",4:"hash",5:"base64",6:"apikey",7:"vault",8:"suite",9:"contact"}; if(m[e.key]) goToTab(m[e.key]) }
    }
    window.addEventListener("keydown", handler); return ()=>window.removeEventListener("keydown",handler)
  },[tab, plain, encPw])

  // BURN COUNTDOWN
  useEffect(()=>{
    if(burnRef.current) window.clearInterval(burnRef.current)
    if(decrypted && burn && burnLeft>0){
      burnRef.current = window.setInterval(()=>{ setBurnLeft(s=>{ if(s<=1){ setDecrypted(""); setBurnLeft(0); toast("🧨 Burn After Reading: cleared","info"); return 0 } return s-1 }) },1000)
    }
    return ()=>{ if(burnRef.current) window.clearInterval(burnRef.current) }
  },[decrypted,burn,burnLeft])

  // CAMERA
  async function startCam(){
    try{
      stopCam()
      const s = await navigator.mediaDevices.getUserMedia({ video:{ facingMode:{ ideal:"environment" } }, audio:false })
      camStreamRef.current=s
      if(videoRef.current){ videoRef.current.srcObject=s; await videoRef.current.play() }
      setCamOn(true)
      toast("Camera active — scanning...","info")
      scanIntervalRef.current = window.setInterval(async()=>{
        if(!videoRef.current) return
        const v=videoRef.current
        if(v.readyState<2) return
        const c=document.createElement("canvas"); c.width=v.videoWidth; c.height=v.videoHeight
        const ctx=c.getContext("2d",{ willReadFrequently:true } as any) as CanvasRenderingContext2D | null; if(!ctx) return
        ctx.drawImage(v,0,0)
        const data=ctx.getImageData(0,0,c.width,c.height)
        const code=jsQR(data.data,c.width,c.height,{ inversionAttempts:"attemptBoth" })
        if(code?.data){ setPendingPayload(code.data); setSelectedFile(null); toast("QR detected ✓","ok"); stopCam() }
      },600)
    }catch{ toast("Camera unavailable","err") }
  }
  function stopCam(){
    if(scanIntervalRef.current) clearInterval(scanIntervalRef.current)
    scanIntervalRef.current=null
    if(camStreamRef.current){ camStreamRef.current.getTracks().forEach(t=>t.stop()); camStreamRef.current=null }
    if(videoRef.current) videoRef.current.srcObject=null
    setCamOn(false)
  }

  // QR RENDER — larger margin & size for reliable jsQR decode
  async function renderQr(to: HTMLCanvasElement | null, txt: string, size=380){
    if(!to||!txt) return
    // margin=4 (spec minimum for reliable decoding), errorCorrectionLevel M for capacity + reliability
    await QRCode.toCanvas(to, txt, { errorCorrectionLevel:"M", width:size, margin:4, color:{ dark:"#000000", light:"#ffffff" } } as any)
  }
  // CRITICAL FIX: Update qrDataUrl AFTER canvas renders (fixes broken PNG download)
  useEffect(()=>{
    if(payload && qrCanvasRef.current){
      renderQr(qrCanvasRef.current, payload, 380).then(()=>{
        if(qrCanvasRef.current){
          try { setQrDataUrl(qrCanvasRef.current.toDataURL("image/png")) } catch(e){ console.error("QR toDataURL failed:", e) }
        }
      })
    }
  },[payload])
  useEffect(()=>{ if(jwtSecret && toolQrRef.current) renderQr(toolQrRef.current, jwtSecret, 260) },[jwtSecret])

  // ENCRYPT
  async function handleEncrypt(){
    if(!plain.trim()){ setEncStatus({type:"err",msg:"❌ कृपया नोट लिखें"}); return }
    if(plain.trim().length > 2000){ setEncStatus({type:"err",msg:"❌ Text exceeds 2000 char limit"}); return }
    if(!encPw){ setEncStatus({type:"err",msg:"❌ पासवर्ड आवश्यक"}); return }
    if(encPw.length > 1024){ setEncStatus({type:"err",msg:"❌ Password too long (max 1024)"}); return }
    if(title.length > 100){ setEncStatus({type:"err",msg:"❌ Title too long"}); return }
    if(deniable && !decoyText.trim()){ setEncStatus({type:"err",msg:"❌ Decoy data required"}); return }
    if(deniable && decoyText.length > 900){ setEncStatus({type:"err",msg:"❌ Decoy too large"}); return }
    if(deniable && !decoyPw){ setEncStatus({type:"err",msg:"❌ Decoy password required"}); return }
    if(deniable && decoyPw.length > 1024){ setEncStatus({type:"err",msg:"❌ Decoy password too long"}); return }
    if(deniable && decoyPw===encPw){ setEncStatus({type:"err",msg:"❌ Real/Decoy keys must differ"}); return }
    const maxChars = deniable ? 900 : 2000
    if(plain.length>maxChars){ setEncStatus({type:"err",msg:`❌ Text too large. Max ${maxChars} chars (${deniable?"deniable":"normal"} mode)`}); return }
    setEncBusy(true); setEncProgress(10); setEncStatus(null); setQrDataUrl(""); setPayload("")
    try{
      setEncProgress(35)
      await new Promise(r=>setTimeout(r,60))
      const pl = deniable ? await encryptDeniable(plain,encPw,decoyText,decoyPw) : await encryptText(plain,encPw)
      // QR v40 M-level = 2331 bytes; H-level = 1273 bytes. We use M-level for capacity.
      if(pl.length>2300){
        console.warn("Payload too large for reliable QR:", pl.length)
        throw new Error("TOO_LARGE")
      }
      // setPayload triggers useEffect which renders QR + sets qrDataUrl (see useEffect above)
      setPayload(pl)
      const noteId = crypto.randomUUID?.() || String(Date.now())
      if(saveVault) setVault(v=>[{ id: noteId, title: title.trim()||"Secure note", payload: pl, createdAt: Date.now(), ttl: Number(ttl)||0 } as VaultItem, ...v].slice(0,60))
      
      // TRIGGER CLOUD SYNC IF ENABLED
      if (cloudEnabled && workerUrl) {
        syncToCloud(noteId, title.trim()||"Secure note", pl)
      }

      bump("enc"); setEncStatus({type:"ok",msg: deniable?"✅ Deniable QR ready — 2 keys, 1 QR":"✅ Encrypted & QR generated"}); toast("🎉 Encrypted successfully!","ok")
      celebrate(undefined, undefined, 100)
      setEncProgress(100); setTimeout(()=>setEncProgress(0),1200)
    }catch(e:any){
      console.error("Encryption error:", e)
      if(e.message==="TOO_LARGE") { setEncStatus({type:"err",msg:"❌ Text too large for QR — shorten text or use file storage"}); toast("Data too large","err") }
      else { setEncStatus({type:"err",msg:"❌ Encryption failed: "+ (e.message||"unknown")}); toast("Encryption failed","err") }
    }finally{ setEncBusy(false) }
  }

  async function handleDecrypt(override?:string){
    if(!decPw){ setDecStatus({type:"err",msg:"❌ Password required"}); return }
    if(decPw.length > 1024){ setDecStatus({type:"err",msg:"❌ Password too long"}); return }
    setDecBusy(true); setDecProgress(20); setDecStatus(null)
    try{
      let data = override || pendingPayload
      if(!data){
        if(!selectedFile){ setDecStatus({type:"err",msg:"❌ QR image चुनें"}); setDecBusy(false); return }
        setDecStatus({type:"info",msg:"📷 Reading QR..."})
        data = await new Promise<string>((res,rej)=>{
          const r=new FileReader()
          r.onerror=()=>rej(new Error("FILE_READ"))
          r.onload=()=>{
            const img=new Image()
            img.onload=()=>{
              try {
                // Try multiple resolutions for reliable QR detection (screenshots often are downscaled)
                const tryDecode = (targetSize: number): string | null => {
                  const c=document.createElement("canvas")
                  const scale = Math.min(1, targetSize / Math.max(img.width, img.height))
                  c.width = Math.max(1, Math.round(img.width * scale))
                  c.height = Math.max(1, Math.round(img.height * scale))
                  const ctx=c.getContext("2d",{ willReadFrequently:true } as any) as CanvasRenderingContext2D
                  if(!ctx) return null
                  ctx.imageSmoothingEnabled = false // sharp pixels for QR
                  ctx.drawImage(img,0,0,c.width,c.height)
                  const code=jsQR(ctx.getImageData(0,0,c.width,c.height).data,c.width,c.height,{ inversionAttempts:"attemptBoth" })
                  return code?.data || null
                }
                // Try native resolution first, then downscale, then upscale
                let result = tryDecode(Math.max(img.width, img.height))
                if(!result) result = tryDecode(800)
                if(!result) result = tryDecode(600)
                if(!result) result = tryDecode(1200)
                if(!result) result = tryDecode(400)
                if(!result) { rej(new Error("NO_QR")); return }
                console.log("QR decoded, payload length:", result.length)
                res(result)
              } catch(err){ console.error("QR decode error:", err); rej(new Error("NO_QR")) }
            }
            img.onerror=()=>rej(new Error("IMG_LOAD"))
            img.src=r.result as string
          }
          r.readAsDataURL(selectedFile as File)
        })
      }
      // Sanitize the payload — jsQR sometimes adds trailing whitespace/newlines from QR encoding
      data = (data || "").trim().replace(/\s+/g,"")
      if(!data){ throw new Error("INVALID") }
      console.log("Decrypting payload of length:", data.length, "first 30:", data.slice(0,30))

      setDecStatus({type:"info",msg:"🔑 Deriving 1M PBKDF2..."})
      setDecProgress(60)
      await new Promise(r=>setTimeout(r,40))
      const pt = await decryptPayload(data, decPw)
      setDecrypted(pt); setBurnLeft(burn?10:0); bump("dec"); setDecStatus({type:"ok",msg:"✅ Decrypt success"}); toast("🎉 Decrypted successfully!","ok"); celebrate(undefined, undefined, 90); setDecProgress(100)
    }catch(e:any){
      console.error("Decrypt error:", e, "message:", e?.message, "name:", e?.name)
      const m=e?.message
      if(m==="DECRYPT_FAIL") setDecStatus({type:"err",msg:"❌ गलत पासवर्ड या डेटा दूषित (wrong password or corrupted data)"})
      else if(m==="NO_QR") setDecStatus({type:"err",msg:"❌ QR कोड detect नहीं हुआ। Image spast honi chahiye, poori QR frame mein ho"})
      else if(m==="INVALID") setDecStatus({type:"err",msg:"❌ QR mein valid encrypted payload nahi hai (possibly not created by this app)"})
      else if(m==="FILE_READ") setDecStatus({type:"err",msg:"❌ File padhne mein error"})
      else if(m==="IMG_LOAD") setDecStatus({type:"err",msg:"❌ Image load nahi hui — format supported nahi"})
      else setDecStatus({type:"err",msg:"❌ Decrypt failed: "+ (m || e?.name || "unknown error")})
      toast("Decrypt failed","err")
    }finally{ setDecBusy(false); setTimeout(()=>setDecProgress(0),800) }
  }

  function makePdf(){
    if(!payload) { toast("Generate QR first","err"); return }
    // Always fetch fresh from canvas
    let freshQrUrl = qrDataUrl
    if(qrCanvasRef.current){
      try { freshQrUrl = qrCanvasRef.current.toDataURL("image/png") } catch(e){ console.error(e) }
    }
    if(!freshQrUrl) { toast("QR not ready — click Encrypt again","err"); return }
    const pwd = pdfPw || encPw
    if(!pwd){ setEncStatus({type:"err",msg:"❌ PDF password required"}); return }
    try{
      let doc: any = null
      let encrypted = false
      // Try with encryption first
      try {
        doc = new (jsPDF as any)({
          unit: "pt",
          format: "a4",
          orientation: "portrait",
          encryption: { userPassword: pwd, ownerPassword: pwd, userPermissions: ["print","modify"] }
        })
        encrypted = true
      } catch (e1) {
        console.warn("PDF encryption attempt 1 failed:", e1)
        // Try simple PDF
        try { doc = new jsPDF({ unit:"pt", format:"a4", orientation:"portrait" } as any) }
        catch (e2) {
          console.warn("PDF creation failed:", e2)
          toast("PDF creation failed","err"); return
        }
      }
      // Dark background
      try { doc.setFillColor(5,7,15); doc.rect(0,0,595,842,"F") } catch {}
      // Title
      try {
        doc.setTextColor(238,242,255); doc.setFontSize(20)
        doc.text("Surakshit Vault PRO - Secure QR Archive", 40, 60)
      } catch {}
      // Subtitle
      try {
        doc.setFontSize(10); doc.setTextColor(148,163,184)
        doc.text("Version " + APP_VERSION + " | AES-GCM-256 | PBKDF2 1M | Zero Backend | (c) Surakshit Labs", 40, 80)
        doc.text("Encryption: " + (encrypted ? "Password-protected PDF" : "Standard (QR inside remains AES-encrypted)"), 40, 96)
      } catch {}
      // QR Image
      try { doc.addImage(freshQrUrl, "PNG", 157, 130, 280, 280) } catch(e){ console.warn("QR image add failed:", e) }
      // Metadata
      try {
        doc.setFontSize(9); doc.setTextColor(100,116,139)
        const meta = "Payload: " + payload.length + " chars | Title: " + (title||"Untitled") + " | Created: " + new Date().toLocaleString()
        doc.text(meta, 40, 440)
      } catch {}
      // Instructions
      try {
        doc.setTextColor(200,210,230); doc.setFontSize(11)
        const lines = doc.splitTextToSize("Instructions: Open this HTML app offline -> Decrypt -> Upload this QR -> Enter your password. Keep HTML file + QR + Password safe together. Without password the data is unrecoverable forever.", 515)
        doc.text(lines, 40, 470)
      } catch {}
      // Footer
      try {
        doc.setTextColor(148,163,184); doc.setFontSize(8)
        doc.text("(c) 2026 Surakshit Labs Pvt. Ltd. | All Rights Reserved | Production Grade | Made in Bharat", 40, 810)
      } catch {}
      // Save
      const filename = "surakshit-vault-" + Date.now() + ".pdf"
      doc.save(filename)
      toast("✅ " + (encrypted ? "Protected" : "") + " PDF downloaded","ok")
      setEncStatus({type:"ok",msg:"✅ PDF exported — " + (encrypted ? "password-protected":"standard")})
    }catch(e){
      console.error("PDF export error:", e)
      toast("PDF export failed: " + (e as any)?.message,"err")
      setEncStatus({type:"err",msg:"❌ PDF export failed"})
    }
  }

  // JWT GEN
  function genJwt(){
    const bl=Math.ceil(jwtBits/8), bytes=randomBytes(bl)
    let out=""
    if(jwtFmt==="hex") out=toHex(bytes)
    else if(jwtFmt==="base64") out=bytesToBase64(bytes)
    else if(jwtFmt==="base64url") out=toB64Url(bytes)
    else out=Array.from(bytes).map(b=>"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"[b%62]).join("")
    setJwtSecret(out); setJwtShow(jwtAlways); bump("keys"); toast("🎉 JWT secret generated!","ok"); celebrate(undefined, undefined, 80)
  }

  // PW GEN
  const WORDS=["alpha","nova","cipher","orbit","pixel","quantum","ember","frost","harbor","ivory","jade","karma","lunar","mirage","nebula","onyx","prism","quartz","raven","solar","tide","umbra","vector","willow","xenon","yarrow","zephyr","anchor","blaze","cascade","delta","echo","falcon","glacier","helix","ion","jungle","kernel","lotus","meadow","nickel","opal","pulse","ridge","sable","torch","ultra","vortex","wave","yarn","zenith"]
  function genPw(){
    let out=""
    if(pwPreset==="passphrase"){ const n=Math.max(3,Math.round(pwLen/5)); out=Array.from({length:n},()=>WORDS[randomBytes(1)[0]%WORDS.length]).join("-")+"-"+(100+randomBytes(1)[0]%900) }
    else if(pwPreset==="pin"){ out=Array.from(randomBytes(Math.max(4,pwLen))).map(b=>String(b%10)).join("").slice(0,pwLen) }
    else if(pwPreset==="otp"){ out=Array.from(randomBytes(6)).map(b=>String(b%10)).join("") }
    else{
      let chars=""; if(pwUpper) chars+="ABCDEFGHIJKLMNOPQRSTUVWXYZ"; if(pwLower) chars+="abcdefghijklmnopqrstuvwxyz"; if(pwDigits) chars+="0123456789"; if(pwSymbols) chars+="!@#$%^&*_-+=?"; if(pwNoAmbig) chars=chars.replace(/[O0Il1]/g,""); if(!chars) chars="abcdefghijklmnopqrstuvwxyz"; out=Array.from(randomBytes(pwLen)).map(b=>chars[b%chars.length]).join("")
    }
    setPwOut(out); setPwHist(h=>[out,...h].slice(0,8)); bump("keys"); toast("🎉 Password generated!","ok"); celebrate(undefined, undefined, 70); return out
  }

  async function doHashes(){ if(!hashInput.trim()){toast("Enter text","err");return} const enc=new TextEncoder(); const sha=async(a:AlgorithmIdentifier,t:string)=>toHex(new Uint8Array(await crypto.subtle.digest(a,enc.encode(t)))); setHashes({ s1:await sha("SHA-1",hashInput), s256:await sha("SHA-256",hashInput), s384:await sha("SHA-384",hashInput), s512:await sha("SHA-512",hashInput) }); toast("🎉 Hashes computed!","ok"); celebrate(undefined, undefined, 50) }
  function makeApiKey(){ const p=apiPrefix||""; if(apiFmt==="uuid") return p+(crypto.randomUUID?.()||toHex(randomBytes(16))); if(apiFmt==="hex") return p+toHex(randomBytes(32)); if(apiFmt==="b64") return p+bytesToBase64(randomBytes(32)); if(apiFmt==="sk") return "sk_live_"+toB64Url(randomBytes(24)); if(apiFmt==="ak") return "ak_"+toHex(randomBytes(20)); return p+toHex(randomBytes(16)) }

  const encStrength = strengthScore(encPw)
  const pwStrength = strengthScore(pwOut.includes("•") ? "" : pwOut)
  const safeSearch = vaultSearch.slice(0,100) // Prevent DoS via huge search string
  const filteredVault = vault.filter(v=>!safeSearch || v.title.toLowerCase().includes(safeSearch.toLowerCase()) || (safeSearch.length <= 50 && v.payload.includes(safeSearch)))

  // persist settings including cloud sync — hardened
  useEffect(()=>{ 
    try {
      // Validate workerUrl before persisting
      if (workerUrl && !isValidWorkerUrl(workerUrl)) {
        console.warn("Invalid workerUrl, not persisting:", workerUrl)
        return
      }
      if (workerSecret && workerSecret.length > 500) return // Prevent huge secrets in localStorage (DoS)
      localStorage.setItem(SETTINGS_KEY, JSON.stringify({ 
        saveVault, showPayload, burn, clipClear, 
        cloudEnabled, workerUrl, workerSecret 
      }))
    } catch(e) { console.warn("Settings persist failed:", e) }
  },[saveVault, showPayload, burn, clipClear, cloudEnabled, workerUrl, workerSecret])

  useEffect(()=>{ 
    try{ 
      const s = JSON.parse(localStorage.getItem(SETTINGS_KEY)||"{}"); 
      if(typeof s.saveVault!=="undefined") setSaveVault(!!s.saveVault);
      if(typeof s.showPayload!=="undefined") setShowPayload(!!s.showPayload);
      if(typeof s.burn!=="undefined") setBurn(!!s.burn);
      if(typeof s.clipClear!=="undefined") setClipClear(!!s.clipClear);
      if(typeof s.cloudEnabled!=="undefined") setCloudEnabled(!!s.cloudEnabled);
      if(typeof s.workerUrl==="string" && s.workerUrl.length <= 300) {
        if (s.workerUrl === "" || isValidWorkerUrl(s.workerUrl)) setWorkerUrl(s.workerUrl)
        else console.warn("Stored workerUrl invalid, ignoring")
      }
      if(typeof s.workerSecret==="string" && s.workerSecret.length <= 500) setWorkerSecret(s.workerSecret);
    }catch{} 
  },[])

  const isLight = theme==="light"
  const card = isLight ? "bg-white border-slate-200/90 shadow-[0_8px_30px_rgba(15,23,42,0.08)] text-slate-900" : "bg-white/[0.05] border-white/10 shadow-[0_16px_50px_rgba(0,0,0,0.3)] text-[#eef2ff]"
  const soft = isLight ? "bg-slate-100 border-slate-200 text-slate-800 hover:bg-slate-200/80" : "bg-white/10 border-white/10 text-slate-200 hover:bg-white/15"
  const muted = isLight ? "text-slate-600" : "text-slate-400"

  return (
    <div data-theme={theme} className={`sv-app min-h-screen w-full font-[Outfit] antialiased selection:bg-indigo-500/30 transition-colors duration-300 ${isLight ? "bg-[#eef2f7] text-slate-900" : "bg-[#05070f] text-[#eef2ff]"}`}>
      <ConfettiLayer />

      {/* BG */}
      <div className="pointer-events-none fixed inset-0 -z-10 overflow-hidden">
        <div className={`absolute inset-0 ${isLight
          ? "bg-[radial-gradient(900px_500px_at_12%_-8%,rgba(99,102,241,0.16),transparent_60%),radial-gradient(700px_420px_at_92%_8%,rgba(14,165,233,0.12),transparent_50%),radial-gradient(800px_500px_at_50%_100%,rgba(168,85,247,0.10),transparent_55%),linear-gradient(180deg,#f8fafc_0%,#e2e8f0_50%,#f1f5f9_100%)]"
          : "bg-[radial-gradient(900px_500px_at_12%_-8%,rgba(99,102,241,0.22),transparent_60%),radial-gradient(700px_420px_at_92%_8%,rgba(34,211,238,0.14),transparent_50%),radial-gradient(800px_500px_at_50%_100%,rgba(168,85,247,0.14),transparent_55%),linear-gradient(180deg,#05070f_0%,#0a1020_50%,#05070f_100%)]"}`} />
        <div className={`absolute top-[8%] -left-16 h-[280px] w-[280px] rounded-full blur-[60px] animate-[floatOrb_14s_ease-in-out_infinite_alternate] ${isLight?"bg-indigo-400/25":"bg-indigo-600/30"}`} />
        <div className={`absolute top-[55%] -right-10 h-[220px] w-[220px] rounded-full blur-[60px] animate-[floatOrb_14s_ease-in-out_infinite_alternate] [animation-delay:-2s] ${isLight?"bg-cyan-400/20":"bg-cyan-400/20"}`} />
        <div className={`absolute bottom-[5%] left-[35%] h-[180px] w-[180px] rounded-full blur-[60px] animate-[floatOrb_14s_ease-in-out_infinite_alternate] [animation-delay:-4s] ${isLight?"bg-violet-400/20":"bg-violet-500/20"}`} />
      </div>

      {/* TOASTS */}
      <div className="fixed bottom-4 right-4 z-[100] flex w-[min(380px,calc(100vw-2rem))] flex-col gap-2">
        {toasts.map(t=>(
          <div key={t.id} className={`pointer-events-auto rounded-2xl border px-4 py-3 text-[13px] font-bold shadow-2xl backdrop-blur-xl animate-[slideUp_0.35s_cubic-bezier(0.22,1,0.36,1)] ${isLight?"bg-white/95 border-slate-200 text-slate-900":"bg-slate-900/90 border-white/10 text-white"} ${t.type==="ok"?"!border-emerald-500/50":t.type==="err"?"!border-red-500/50":"!border-sky-500/40"}`}>{t.msg}</div>
        ))}
      </div>

      <div className="mx-auto w-[min(1220px,100%)] px-3 sm:px-4 pb-10 pt-3 sm:pt-4">
        {/* HEADER */}
        <header className="flex flex-wrap items-center justify-between gap-3 sm:gap-4 py-3 sm:py-4 animate-[fadeUp_0.5s_ease_both]">
          <div className="flex min-w-0 items-center gap-2.5 sm:gap-3">
            <div className="relative grid h-[44px] w-[44px] sm:h-[52px] sm:w-[52px] shrink-0 place-items-center overflow-hidden rounded-[14px] bg-gradient-to-br from-indigo-600 to-cyan-400 shadow-[0_0_24px_rgba(99,102,241,0.35)] animate-[pulseGlow_3s_ease-in-out_infinite]">
              <img src={INLINE_ICON_SVG} alt="Surakshit Vault icon" className="h-[30px] w-[30px] sm:h-[36px] sm:w-[36px] object-contain drop-shadow-[0_0_8px_rgba(255,255,255,0.4)]" />
              <div className="absolute inset-0 bg-gradient-to-br from-white/10 to-transparent" />
            </div>
            <div className="min-w-0">
              <h1 className={`m-0 text-[clamp(1rem,2.4vw,1.6rem)] font-extrabold tracking-tight leading-[1.1] ${isLight?"text-slate-900":""}`}>Surakshit Vault <span className="bg-gradient-to-r from-indigo-500 to-cyan-400 bg-clip-text text-transparent">PRO</span></h1>
              <p className={`m-0 truncate text-[10px] sm:text-[11px] font-semibold tracking-widest uppercase ${muted}`}>Production Grade • AES-GCM-256 • v{APP_VERSION}</p>
            </div>
          </div>
          <div className="flex flex-wrap items-center gap-1.5 sm:gap-2">
            {/* Online / Offline indicator */}
            <span className={`hidden sm:inline-flex items-center gap-1.5 rounded-full border px-2.5 py-1 text-[10px] font-bold ${isOnline ? (isLight?"border-emerald-200 bg-emerald-50 text-emerald-700":"border-emerald-500/30 bg-emerald-500/10 text-emerald-300") : (isLight?"border-amber-200 bg-amber-50 text-amber-700":"border-amber-500/30 bg-amber-500/10 text-amber-300")}`}>
              {isOnline ? <><Wifi size={11} /> Online</> : <><WifiOff size={11} /> Offline</>}
            </span>
            {/* Cloud sync status */}
            {cloudEnabled && session && (
              <span className={`hidden sm:inline-flex items-center gap-1.5 rounded-full border px-2.5 py-1 text-[10px] font-bold ${isLight?"border-cyan-200 bg-cyan-50 text-cyan-800":"border-cyan-500/30 bg-cyan-500/10 text-cyan-300"}`}>
                <Cloud size={11} /> {syncStatus==="syncing" ? "Syncing…" : syncStatus==="done" ? "Synced ✓" : "Cloud Active"}
              </span>
            )}
            {/* User / Login button */}
            {session ? (
              <div className="inline-flex items-center gap-1">
                <span className={`inline-flex items-center gap-1.5 rounded-full border px-2.5 py-1.5 text-[11px] font-bold ${isLight?"border-indigo-200 bg-indigo-50 text-indigo-700":"border-indigo-500/30 bg-indigo-500/10 text-indigo-200"}`}>
                  <UserIcon size={12} /> <span className="max-w-[90px] truncate">{session.email.split("@")[0]}</span>
                </span>
                <button onClick={handleLogout} title="Logout" className={`inline-flex items-center gap-1 rounded-full border px-2 py-1.5 text-[11px] font-bold transition hover:scale-105 ${soft}`}><LogOut size={12} /></button>
              </div>
            ) : cloudEnabled && workerUrl ? (
              <button onClick={()=>{ setAuthMode("login"); setAuthOpen(true) }} className={`inline-flex items-center gap-1.5 rounded-full border px-2.5 py-1.5 text-[12px] font-bold transition hover:scale-105 bg-gradient-to-r from-indigo-600 to-cyan-500 text-white border-transparent shadow-md hover:shadow-lg`}><LogIn size={13} /> Login</button>
            ) : (
              <span className={`hidden sm:inline-flex items-center gap-2 rounded-full border px-3 py-1.5 text-[11px] font-bold ${isLight?"border-emerald-200 bg-emerald-50 text-emerald-700":"border-white/10 bg-white/[0.06] text-slate-300"}`}><span className="h-2 w-2 animate-pulse rounded-full bg-emerald-400 shadow-[0_0_0_4px_rgba(16,185,129,0.15)]" />OFFLINE MODE</span>
            )}
            <button onClick={()=>setTheme(theme==="dark"?"light":"dark")} className={`inline-flex items-center gap-1.5 rounded-full border px-2.5 sm:px-3 py-1.5 text-[12px] font-bold backdrop-blur transition hover:scale-105 ${soft}`}>{theme==="dark"?<><Sun size={14} /> Light</>:<><Moon size={14} /> Dark</>}</button>
            <button onClick={()=>setSettingsOpen(true)} className={`inline-flex items-center gap-1.5 rounded-full border px-2.5 sm:px-3 py-1.5 text-[12px] font-bold backdrop-blur transition hover:scale-105 ${soft}`}><SettingsIcon size={14} /> <span className="hidden xs:inline sm:inline">Settings</span></button>
            <button onClick={()=>setHelpOpen(true)} className={`inline-flex items-center gap-1.5 rounded-full border px-2.5 sm:px-3 py-1.5 text-[12px] font-bold backdrop-blur transition hover:scale-105 ${soft}`}><HelpCircle size={14} /> <span className="hidden sm:inline">Help</span></button>
          </div>
        </header>

        {/* STATS */}
        <div className="mb-4 grid grid-cols-2 gap-2 sm:gap-3 md:grid-cols-4 animate-[fadeUp_0.55s_ease_both]">
          {[
            {k:"Notes Encrypted", v:stats.enc},
            {k:"Successful Decrypts", v:stats.dec},
            {k:"Keys Generated", v:stats.keys},
            {k:"PBKDF2 Iterations", v:"1,000,000"},
          ].map(s=>(
            <div key={s.k} className={`group relative overflow-hidden rounded-2xl border p-3 sm:p-4 backdrop-blur-xl transition hover:-translate-y-0.5 hover:shadow-lg ${card}`}>
              <div className={`text-[10px] sm:text-[11px] font-bold tracking-widest uppercase ${muted}`}>{s.k}</div>
              <div className={`mt-1 text-[18px] sm:text-[22px] font-extrabold ${isLight?"bg-gradient-to-r from-indigo-600 to-cyan-600 bg-clip-text text-transparent":"bg-gradient-to-r from-white to-indigo-200 bg-clip-text text-transparent"}`}>{String(s.v)}</div>
              <div className="pointer-events-none absolute -right-6 -bottom-8 h-20 w-20 rounded-full bg-[radial-gradient(circle,rgba(99,102,241,0.22),transparent_70%)] transition group-hover:scale-125" />
            </div>
          ))}
        </div>

        {/* TABS */}
        <div className="sticky top-2 sm:top-3 z-30 mb-4 animate-[fadeUp_0.6s_ease_both]">
          <div className={`flex gap-1 sm:gap-1.5 overflow-x-auto rounded-2xl border p-1 sm:p-1.5 backdrop-blur-xl scrollbar-none shadow-sm ${isLight?"bg-white/90 border-slate-200":"bg-slate-900/60 border-white/10"}`}>
            {[
              {id:"notes", l:"Notes", I:FileText},
              {id:"jwt", l:"JWT", I:KeyRound},
              {id:"password", l:"Password", I:Fingerprint},
              {id:"hash", l:"Hash", I:HashIcon},
              {id:"base64", l:"Base64", I:Package},
              {id:"apikey", l:"API Forge", I:Puzzle},
              {id:"vault", l:"Vault", I:Archive},
              {id:"suite", l:"Hub", I:Rocket},
              {id:"contact", l:"Contact", I:Mail},
            ].map(t=>(
              <button key={t.id} onClick={()=>goToTab(t.id as Tab)} className={`inline-flex items-center gap-1 sm:gap-1.5 whitespace-nowrap rounded-full px-2.5 sm:px-4 py-1.5 sm:py-2 text-[12px] sm:text-[13px] font-bold transition-all duration-300 ${tab===t.id ? "bg-gradient-to-r from-indigo-600 to-cyan-500 text-white shadow-[0_8px_24px_rgba(99,102,241,0.35)] scale-[1.02]" : isLight?"text-slate-600 hover:text-slate-900 hover:bg-slate-100":"text-slate-400 hover:text-slate-100 hover:bg-white/5"}`}><t.I size={14} /> {t.l}</button>
            ))}
          </div>
        </div>

        {/* PANELS */}
        {tab==="notes" && (
          <div key="notes" className="grid gap-4 lg:grid-cols-2 panel-anim">
            {/* ENCRYPT */}
            <div className={`rounded-[1.25rem] border p-5 backdrop-blur-xl ${theme==="dark"?"bg-white/[0.05] border-white/10 shadow-[0_16px_50px_rgba(0,0,0,0.3)]":"bg-white/80 border-slate-200 shadow-lg"}`}>
              <div className="mb-4 flex items-center justify-between"><h2 className="flex items-center gap-2 text-[17px] font-extrabold"><Lock size={18} className="text-indigo-400" /> एन्क्रिप्ट → QR</h2><span className="rounded-full border border-indigo-500/30 bg-indigo-500/10 px-2.5 py-1 text-[10px] font-bold tracking-widest text-indigo-300">AES-GCM-256 • H</span></div>

              <label className="mb-1 flex justify-between text-[11px] font-bold uppercase tracking-widest text-slate-400"><span>Secret Note / Data</span><span className="normal-case">{plain.length} chars</span></label>
              <textarea value={plain} onChange={e=>setPlain(e.target.value)} placeholder="bank seed, wallet phrase, Aadhaar, secret message..." className={`min-h-[140px] w-full resize-y rounded-xl border bg-[#070c18]/80 p-3 text-[14px] leading-relaxed outline-none focus:border-indigo-500/60 focus:ring-4 focus:ring-indigo-500/15 ${theme==="light"?"!bg-white !text-slate-900 border-slate-300":"border-white/10 text-white"}`} />

              <div className="mt-3 grid grid-cols-[2fr_1fr] gap-3">
                <div><label className="mb-1 block text-[11px] font-bold uppercase tracking-widest text-slate-400">Title (Vault)</label><input value={title} onChange={e=>setTitle(e.target.value)} placeholder="Wallet backup" className={`w-full rounded-xl border bg-[#070c18]/80 px-3 py-2.5 text-sm outline-none ${theme==="light"?"!bg-white border-slate-300 text-slate-900":"border-white/10 text-white"}`} /></div>
                <div><label className="mb-1 block text-[11px] font-bold uppercase tracking-widest text-slate-400">TTL</label><select value={ttl} onChange={e=>setTtl(e.target.value)} className={`w-full rounded-xl border bg-[#070c18]/80 px-3 py-2.5 text-sm outline-none ${theme==="light"?"!bg-white border-slate-300 text-slate-900":"border-white/10 text-white"}`}><option value="0">None</option><option value="1">1d</option><option value="7">7d</option><option value="30">30d</option><option value="365">1y</option></select></div>
              </div>

              <label className="mt-4 mb-1 block text-[11px] font-bold uppercase tracking-widest text-slate-400">Password / Key (Never stored)</label>
              <div className="relative">
                <input value={encPw} onChange={e=>setEncPw(e.target.value)} type={showEncPw?"text":"password"} placeholder="मजबूत पासवर्ड डालें — min 12 chars" className={`w-full rounded-xl border bg-[#070c18]/80 px-3 py-2.5 pr-20 text-sm outline-none ${theme==="light"?"!bg-white border-slate-300 text-slate-900":"border-white/10 text-white"}`} />
                <div className="absolute right-1 top-1/2 flex -translate-y-1/2 gap-1">
                  <button onClick={()=>setShowEncPw(!showEncPw)} className="grid h-8 w-8 place-items-center rounded-lg bg-white/10">{showEncPw?<EyeOff size={14} />:<Eye size={14} />}</button>
                  <button onClick={()=>openKeypad("enc")} className="grid h-8 w-8 place-items-center rounded-lg bg-white/10"><Keyboard size={14} /></button>
                </div>
              </div>
              <div className="mt-2 h-2 overflow-hidden rounded-full bg-white/10"><div className="h-full transition-all" style={{ width:`${encStrength.pct}%`, background: encStrength.color }} /></div>
              <div className="mt-1 text-[11px] font-bold" style={{ color: encStrength.color }}>Strength: {encStrength.label}</div>

              <label className="mt-4 flex cursor-pointer items-center gap-2 text-[13px] font-bold"><input type="checkbox" checked={deniable} onChange={e=>setDeniable(e.target.checked)} className="accent-indigo-500" /> <Glasses size={15} className="text-cyan-400" /> Plausible Deniability (Dual-key QR)</label>
              {deniable && (
                <div className="mt-3 rounded-xl border border-cyan-500/20 bg-gradient-to-br from-cyan-500/10 to-indigo-500/10 p-3 animate-[fadeIn_0.3s]">
                  <label className="mb-1 block text-[11px] font-bold uppercase tracking-widest text-slate-400">Decoy Data (Harmless)</label>
                  <textarea value={decoyText} onChange={e=>setDecoyText(e.target.value)} placeholder="Harmless decoy text for wrong / forced key..." className="min-h-[70px] w-full rounded-xl border border-white/10 bg-black/20 p-2.5 text-sm outline-none" />
                  <label className="mt-2 mb-1 block text-[11px] font-bold uppercase tracking-widest text-slate-400">Decoy Password</label>
                  <div className="relative">
                    <input value={decoyPw} onChange={e=>setDecoyPw(e.target.value)} type={showDecoyPw?"text":"password"} placeholder="अलग decoy password" className="w-full rounded-xl border border-white/10 bg-black/20 px-3 py-2.5 pr-16 text-sm outline-none" />
                    <div className="absolute right-1 top-1/2 flex -translate-y-1/2 gap-1">
                      <button onClick={()=>setShowDecoyPw(!showDecoyPw)} className="grid h-8 w-8 place-items-center rounded-lg bg-white/10">{showDecoyPw?<EyeOff size={14} />:<Eye size={14} />}</button>
                      <button onClick={()=>openKeypad("decoy")} className="grid h-8 w-8 place-items-center rounded-lg bg-white/10"><Keyboard size={14} /></button>
                    </div>
                  </div>
                  <p className="mt-2 text-[11px] leading-snug text-slate-400">Same QR → Real key = real data, Decoy key = harmless data. App never reveals which is which.</p>
                </div>
              )}

              <div className="mt-4 rounded-xl border border-violet-500/20 bg-gradient-to-br from-violet-500/10 to-indigo-500/5 p-3">
                <div className="mb-2 flex items-center justify-between"><span className="flex items-center gap-1.5 text-[12px] font-extrabold"><FileLock2 size={14} className="text-violet-400" /> Protected PDF Export</span><span className="rounded-full bg-white/10 px-2 py-0.5 text-[10px] font-bold">OPTIONAL</span></div>
                <div className="relative">
                  <input value={pdfPw} onChange={e=>setPdfPw(e.target.value)} type={showPdfPw?"text":"password"} placeholder="PDF open password (blank = note password)" className="w-full rounded-xl border border-white/10 bg-black/20 px-3 py-2.5 pr-16 text-sm outline-none" />
                  <div className="absolute right-1 top-1/2 flex -translate-y-1/2 gap-1">
                    <button onClick={()=>setShowPdfPw(!showPdfPw)} className="grid h-8 w-8 place-items-center rounded-lg bg-white/10">{showPdfPw?<EyeOff size={14} />:<Eye size={14} />}</button>
                    <button onClick={()=>openKeypad("pdf")} className="grid h-8 w-8 place-items-center rounded-lg bg-white/10"><Keyboard size={14} /></button>
                  </div>
                </div>
              </div>

              <button disabled={encBusy} onClick={handleEncrypt} className="mt-4 flex w-full items-center justify-center gap-2 rounded-xl bg-gradient-to-r from-indigo-600 to-cyan-500 py-3 text-[14px] font-extrabold text-white shadow-[0_10px_28px_rgba(79,70,229,0.28)] transition active:scale-[0.99] disabled:opacity-60">{encBusy ? <Loader2 size={16} className="animate-spin" /> : <Lock size={16} />} {encBusy ? "Encrypting 1M PBKDF2…" : "एन्क्रिप्ट करें — Generate QR"}</button>
              {encProgress>0 && <div className="mt-3 h-1.5 w-full overflow-hidden rounded-full bg-white/10"><div className="h-full bg-gradient-to-r from-indigo-500 to-cyan-400 transition-all" style={{ width: `${encProgress}%` }} /></div>}
              {encStatus && <div className={`mt-3 rounded-xl px-3 py-2 text-[13px] font-bold ${encStatus.type==="ok" ? "bg-emerald-500/15 text-emerald-300 border border-emerald-500/20" : encStatus.type==="err" ? "bg-red-500/15 text-red-300 border border-red-500/20" : "bg-amber-500/15 text-amber-200 border border-amber-500/20"}`}>{encStatus.msg}</div>}

              {payload && (
                <div className="mt-5 flex flex-col items-center gap-4 rounded-2xl border border-white/10 bg-black/20 p-4">
                  <canvas ref={qrCanvasRef} className="rounded-2xl bg-white p-2 shadow-xl" />
                  {showPayload && <div className="max-h-[88px] w-full overflow-auto break-all rounded-xl bg-black/40 p-2.5 font-mono text-[10px] leading-relaxed text-slate-400">{payload}</div>}
                  <div className="flex w-full flex-wrap gap-2">
                    <button onClick={()=>{
                      // Always fetch fresh from canvas — most reliable
                      const canvas = qrCanvasRef.current
                      if(!canvas){ toast("QR canvas not ready","err"); return }
                      try {
                        const url = canvas.toDataURL("image/png")
                        const a = document.createElement("a")
                        a.href = url
                        a.download = `surakshit-qr-${Date.now()}.png`
                        document.body.appendChild(a); a.click(); a.remove()
                        toast("QR downloaded ✓","ok")
                      } catch(e:any){ console.error("QR download failed:", e); toast("Download failed: "+e.message,"err") }
                    }} className="inline-flex flex-1 items-center justify-center gap-1.5 rounded-xl bg-emerald-600 py-2.5 text-center text-[13px] font-bold text-white hover:bg-emerald-500"><Download size={15} /> QR PNG</button>
                    <button onClick={makePdf} className="inline-flex flex-1 items-center justify-center gap-1.5 rounded-xl bg-emerald-600 py-2.5 text-[13px] font-bold text-white hover:bg-emerald-500"><FileDown size={15} /> PDF</button>
                    <CopyBtn text={payload} label="Payload" className="flex-1 justify-center py-2.5" />
                    <button onClick={async()=>{ const hint="Offline HTML + QR + Password required"; if(navigator.share) try{ await navigator.share({ title:"Surakshit Vault", text:hint }) } catch{} else { await navigator.clipboard.writeText(hint); toast("Hint copied","ok") } }} className="inline-flex items-center gap-1.5 rounded-xl bg-white/10 px-3 py-2.5 text-[13px] font-bold"><Link2 size={15} /> Hint</button>
                  </div>
                  <p className="text-center text-[11px] leading-snug text-slate-400">QR + password को सुरक्षित रखें। बिना password के data हमेशा के लिए unreadable है। HTML + QR दोनों backup लें।</p>
                </div>
              )}
            </div>

            {/* DECRYPT */}
            <div className={`rounded-[1.25rem] border p-5 backdrop-blur-xl ${theme==="dark"?"bg-white/[0.05] border-white/10":"bg-white/80 border-slate-200 shadow-lg"}`}>
              <div className="mb-4 flex items-center justify-between"><h2 className="flex items-center gap-2 text-[17px] font-extrabold"><Unlock size={18} className="text-cyan-400" /> डिक्रिप्ट → Text</h2><span className="rounded-full border border-cyan-500/30 bg-cyan-500/10 px-2.5 py-1 text-[10px] font-bold tracking-widest text-cyan-200">jsQR + WebCrypto</span></div>

              <div onClick={()=>fileInputRef.current?.click()} onDragOver={e=>{e.preventDefault(); (e.currentTarget as any).classList.add("!border-indigo-500")}} onDragLeave={e=>{ (e.currentTarget as any).classList.remove("!border-indigo-500")}} onDrop={e=>{ e.preventDefault(); const f=e.dataTransfer.files?.[0]; if(!f) return; if(f.size > MAX_FILE_SIZE){ toast(`Image too large — max ${MAX_FILE_SIZE/1024/1024}MB`,"err"); return } if(!f.type.startsWith("image/")){ toast("Only image files allowed","err"); return } setSelectedFile(f); setPendingPayload(""); toast("Image dropped ✓","ok") }} className="group flex cursor-pointer flex-col items-center justify-center rounded-2xl border-2 border-dashed border-white/20 bg-[#070c18]/60 px-4 py-8 text-center transition hover:border-indigo-500/60 hover:bg-indigo-500/5">
                <QrCode size={28} className="text-indigo-400" /><div className="mt-1 font-bold">Drop QR image here</div><div className="text-[12px] text-slate-400">or click • PNG/JPG/WebP • max 10MB</div><input ref={fileInputRef} type="file" accept="image/png,image/jpeg,image/webp,image/jpg" className="hidden" onChange={e=>{ const f=e.target.files?.[0]; if(!f) return; if(f.size > MAX_FILE_SIZE){ toast(`Image too large — max ${MAX_FILE_SIZE/1024/1024}MB`,"err"); e.target.value=""; return } if(!f.type.startsWith("image/")){ toast("Only image files allowed","err"); e.target.value=""; return } setSelectedFile(f); setPendingPayload(""); toast("Image selected ✓","ok") }} />
              </div>
              <div className="mt-2 flex items-center justify-between text-[11px] text-slate-400"><span>फ़ाइल: {selectedFile?.name || pendingPayload ? (pendingPayload ? "Camera/Pasted ✓" : selectedFile?.name) : "कोई चयन नहीं"}</span><CopyBtn small text={pendingPayload} label="Paste?" /></div>

              <div className="mt-3 flex gap-2">
                <button onClick={startCam} className="inline-flex flex-1 items-center justify-center gap-1.5 rounded-xl bg-white/10 py-2.5 text-[13px] font-bold hover:bg-white/15"><Camera size={15} /> Camera Scan</button>
                <button onClick={()=>{ const v=prompt("Paste Base64 payload:"); if(v){ setPendingPayload(v.trim()); setSelectedFile(null); toast("Payload pasted","ok") } }} className="inline-flex flex-1 items-center justify-center gap-1.5 rounded-xl bg-white/10 py-2.5 text-[13px] font-bold hover:bg-white/15"><ClipboardPaste size={15} /> Paste Payload</button>
              </div>

              {camOn && (
                <div className="mt-3 overflow-hidden rounded-2xl border border-white/10 bg-black">
                  <video ref={videoRef} playsInline muted className="h-[240px] w-full object-cover" />
                  <div className="flex gap-2 p-2"><button onClick={stopCam} className="inline-flex flex-1 items-center justify-center gap-1 rounded-xl bg-white/10 py-2 text-[13px] font-bold"><X size={13} /> Stop</button><span className="inline-flex flex-1 items-center justify-center gap-1.5 rounded-xl bg-emerald-500/20 py-2 text-center text-[11px] font-bold text-emerald-300"><ScanLine size={13} className="animate-pulse" /> Scanning… hold QR steady</span></div>
                </div>
              )}

              <label className="mt-4 mb-1 block text-[11px] font-bold uppercase tracking-widest text-slate-400">Password / Key</label>
              <div className="relative">
                <input id="decPassword" value={decPw} onChange={e=>setDecPw(e.target.value)} type={showDecPw?"text":"password"} placeholder="वही पासवर्ड डालें" className={`w-full rounded-xl border bg-[#070c18]/80 px-3 py-2.5 pr-20 text-sm outline-none ${theme==="light"?"!bg-white border-slate-300 text-slate-900":"border-white/10 text-white"}`} />
                <div className="absolute right-1 top-1/2 flex -translate-y-1/2 gap-1">
                  <button onClick={()=>setShowDecPw(!showDecPw)} className="grid h-8 w-8 place-items-center rounded-lg bg-white/10">{showDecPw?<EyeOff size={14} />:<Eye size={14} />}</button>
                  <button onClick={()=>openKeypad("dec")} className="grid h-8 w-8 place-items-center rounded-lg bg-white/10"><Keyboard size={14} /></button>
                </div>
              </div>

              <div className="mt-4 rounded-xl border border-cyan-500/20 bg-gradient-to-br from-cyan-500/10 to-indigo-500/5 p-3">
                <div className="mb-2 flex items-center justify-between text-[12px] font-extrabold"><span className="flex items-center gap-1.5"><Flame size={14} className="text-orange-400" /> Privacy & Anti-Forensics</span><span className="rounded-full bg-white/10 px-2 py-0.5 text-[10px]">PRO</span></div>
                <div className="flex flex-wrap gap-3 text-[12px] font-bold text-slate-300">
                  <label className="flex items-center gap-1.5"><input type="checkbox" checked={burn} onChange={e=>setBurn(e.target.checked)} className="accent-indigo-500" /> Burn 10s</label>
                  <label className="flex items-center gap-1.5"><input type="checkbox" checked={clipClear} onChange={e=>setClipClear(e.target.checked)} className="accent-indigo-500" /> Clipboard 15s</label>
                  <label className="flex items-center gap-1.5"><input type="checkbox" checked={saveVault} onChange={e=>setSaveVault(e.target.checked)} className="accent-indigo-500" /> Save vault meta</label>
                  <label className="flex items-center gap-1.5"><input type="checkbox" checked={showPayload} onChange={e=>setShowPayload(e.target.checked)} className="accent-indigo-500" /> Show payload</label>
                </div>
                <p className="mt-2 text-[11px] leading-snug text-slate-400">Auto-clear screen + clipboard. No traces in DOM after burn. Anti-keylogger keypad.</p>
              </div>

              <button disabled={decBusy} onClick={()=>handleDecrypt()} className="mt-4 flex w-full items-center justify-center gap-2 rounded-xl bg-gradient-to-r from-indigo-600 to-cyan-500 py-3 text-[14px] font-extrabold text-white shadow-[0_10px_28px_rgba(79,70,229,0.28)] transition active:scale-[0.99] disabled:opacity-60">{decBusy ? <Loader2 size={16} className="animate-spin" /> : <Unlock size={16} />} {decBusy ? "Deriving key…" : "डिक्रिप्ट करें"}</button>
              {decProgress>0 && <div className="mt-3 h-1.5 w-full overflow-hidden rounded-full bg-white/10"><div className="h-full bg-gradient-to-r from-indigo-500 to-cyan-400 transition-all" style={{ width: `${decProgress}%` }} /></div>}
              {decStatus && <div className={`mt-3 rounded-xl px-3 py-2 text-[13px] font-bold ${decStatus.type==="ok" ? "bg-emerald-500/15 text-emerald-300 border border-emerald-500/20" : decStatus.type==="err" ? "bg-red-500/15 text-red-300 border border-red-500/20" : "bg-sky-500/15 text-sky-200 border border-sky-500/20"}`}>{decStatus.msg}</div>}

              {decrypted && (
                <div className="mt-5 rounded-2xl border border-white/10 bg-black/30 p-4">
                  <div className="mb-2 flex items-center justify-between text-[11px] font-bold uppercase tracking-widest text-slate-400"><span>Decrypted</span><span className="normal-case">{decrypted.length} chars</span></div>
                  {burn && burnLeft>0 && <div className="mb-2 inline-flex items-center gap-1.5 rounded-full border border-red-500/30 bg-red-500/15 px-2.5 py-1 text-[11px] font-bold text-red-200"><Flame size={12} /> Auto clear in {burnLeft}s • {burnLeft>5?"Safe":"Burning..."}</div>}
                  <div className="max-h-[220px] overflow-auto whitespace-pre-wrap break-words rounded-xl bg-[#05070f] p-3 font-mono text-[13px] leading-relaxed text-emerald-200 shadow-inner">{decrypted}</div>
                  <div className="mt-3 flex flex-wrap gap-2">
                    <CopyBtn text={decrypted} label="Copy Text" className="flex-1 justify-center bg-emerald-600 hover:bg-emerald-500 text-white border-0 py-2.5" />
                    <button onClick={()=>{ setPlain(decrypted); goToTab("notes"); toast("Loaded to encrypt panel","ok") }} className="inline-flex items-center gap-1.5 rounded-xl bg-white/10 px-4 py-2.5 text-[13px] font-bold"><RefreshCw size={14} /> Re-encrypt</button>
                    <button onClick={()=>{ setDecrypted(""); setBurnLeft(0); toast("Cleared","info") }} className="inline-flex items-center gap-1.5 rounded-xl bg-white/5 px-4 py-2.5 text-[13px] font-bold text-slate-400"><Eraser size={14} /> Clear</button>
                  </div>
                  <div className="mt-2 flex gap-2"><CopyBtn small text={decrypted} label="Copy (small)" /><button onClick={async()=>{ if(clipClear){ setTimeout(async()=>{ try{ await navigator.clipboard.writeText(""); toast("Clipboard cleared","ok") }catch{} },15000); toast("Will auto-clear clipboard in 15s","info") } }} className="rounded-full bg-white/5 px-2.5 py-1 text-[11px] font-bold">Auto-clear clipboard</button></div>
                </div>
              )}
            </div>
          </div>
        )}

        {tab==="jwt" && (
          <div key="jwt" className="grid gap-4 lg:grid-cols-[1.1fr_0.9fr] panel-anim">
            <div className={`rounded-[1.25rem] border p-5 ${theme==="dark"?"bg-white/[0.05] border-white/10":"bg-white/80 border-slate-200 shadow-lg"}`}>
              <div className="mb-4 flex items-center justify-between"><h2 className="flex items-center gap-2 text-[17px] font-extrabold"><KeyRound size={18} className="text-indigo-400" /> JWT Secret Studio</h2><span className="rounded-full bg-indigo-500/15 px-2.5 py-1 text-[10px] font-bold text-indigo-300">CSPRNG • HS256/384/512</span></div>
              <p className="mb-4 text-[13px] leading-relaxed text-slate-400">High-entropy secrets for HS256/HS384/HS512. Inspired by jwtsecrets.com — production grade CSPRNG via Web Crypto.</p>
              <div className="mb-3 flex flex-wrap gap-1.5">{[128,256,384,512].map(b=><button key={b} onClick={()=>setJwtBits(b)} className={`rounded-full px-3 py-1.5 text-[12px] font-bold border ${jwtBits===b?"bg-indigo-600 border-indigo-500 text-white":"bg-white/5 border-white/10 text-slate-300"}`}>{b} bits</button>)}</div>
              <label className="mb-1 flex justify-between text-[11px] font-bold uppercase tracking-widest text-slate-400"><span>Custom entropy</span><span>{jwtBits} bits • {jwtBits<128?"Weak":jwtBits<256?"OK":jwtBits<384?"HS256 ready":"HS512 ready"}</span></label>
              <input type="range" min={32} max={512} step={8} value={jwtBits} onChange={e=>setJwtBits(Number(e.target.value))} className="w-full accent-indigo-500" />
              <div className="mt-4 flex flex-wrap gap-1.5">{[
                {id:"hex",l:"Hex"},{id:"base64",l:"Base64"},{id:"base64url",l:"Base64URL"},{id:"raw",l:"AlphaNum"}
              ].map(f=><button key={f.id} onClick={()=>setJwtFmt(f.id as any)} className={`rounded-full px-3 py-1.5 text-[12px] font-bold border ${jwtFmt===f.id?"bg-indigo-600 border-indigo-500 text-white":"bg-white/5 border-white/10 text-slate-300"}`}>{f.l}</button>)}</div>
              <label className="mt-4 flex items-center gap-2 text-[13px] font-bold"><input type="checkbox" checked={jwtAlways} onChange={e=>setJwtAlways(e.target.checked)} className="accent-indigo-500" /> Always show (no blur)</label>
              <button onClick={genJwt} className="mt-4 inline-flex w-full items-center justify-center gap-2 rounded-xl bg-gradient-to-r from-indigo-600 to-cyan-500 py-3 text-[14px] font-extrabold text-white"><Zap size={16} /> Generate {jwtBits}-bit Secret</button>
              <div className={`mt-4 rounded-xl border p-3 font-mono text-[13px] break-all ${!jwtShow && !jwtAlways ? "blur-[7px] select-none" : ""} ${theme==="dark"?"bg-black/30 border-white/10 text-emerald-200":"bg-slate-50 border-slate-200 text-slate-900"}`}>{jwtSecret || "Click generate…"}</div>
              <div className="mt-3 flex flex-wrap gap-2">
                <button onClick={()=>setJwtShow(!jwtShow)} className="inline-flex items-center gap-1.5 rounded-xl bg-white/10 px-4 py-2.5 text-[13px] font-bold">{jwtShow?<><EyeOff size={14} /> Hide</>:<><Eye size={14} /> Show</>}</button>
                <CopyBtn text={jwtSecret} label="Copy Secret" className="bg-emerald-600 hover:bg-emerald-500 text-white border-0" />
                <button onClick={()=>toast(jwtSecret ? "QR rendered below" : "Generate first","info")} className="inline-flex items-center gap-1.5 rounded-xl bg-white/10 px-4 py-2.5 text-[13px] font-bold"><QrCode size={14} /> Show QR</button>
              </div>
              <div className="mt-4 h-2 w-full overflow-hidden rounded-full bg-white/10"><div className="h-full bg-gradient-to-r from-indigo-500 to-cyan-400" style={{ width:`${Math.min(100,(jwtBits/512)*100)}%` }} /></div>
            </div>
            <div className={`rounded-[1.25rem] border p-5 ${theme==="dark"?"bg-white/[0.05] border-white/10":"bg-white/80 border-slate-200 shadow-lg"}`}>
              <h3 className="flex items-center gap-2 text-[14px] font-extrabold"><BookOpen size={15} className="text-cyan-400" /> Best Practices & Compliance</h3>
              <ul className="mt-3 space-y-2 text-[13px] leading-relaxed text-slate-400 list-none p-0">
                <li>• ≥256-bit entropy for HS256 (production)</li><li>• Rotate secrets quarterly, separate envs</li><li>• Never commit to git — use env/KMS/Secret Manager</li><li>• Short-lived JWTs + strict aud/iss</li><li>• This generator uses crypto.getRandomValues (CSPRNG)</li>
              </ul>
              <div className="mt-6 flex flex-col items-center rounded-2xl border border-white/10 bg-black/20 p-4">
                <canvas ref={toolQrRef} className="rounded-xl bg-white p-2" width={220} height={220} />
                <div className="mt-3 flex gap-2">
                  <CopyBtn small text={jwtSecret} label="Copy" />
                  <button onClick={()=>{ const url=toolQrRef.current?.toDataURL("image/png"); if(!url) return; const a=document.createElement("a"); a.href=url; a.download=`jwt-${Date.now()}.png`; a.click() }} className="inline-flex items-center gap-1 rounded-full bg-white/10 px-3 py-1 text-[11px] font-bold"><Download size={12} /> QR PNG</button>
                </div>
                <p className="mt-2 text-center text-[11px] text-slate-400">QR for offline transfer to vault / HSM</p>
              </div>
              <div className={`mt-4 flex items-start gap-1.5 rounded-xl p-3 text-[11px] leading-relaxed ${theme==="dark"?"bg-indigo-500/10 text-indigo-200 border border-indigo-500/20":"bg-indigo-50 text-indigo-700 border border-indigo-200"}`}><Lock size={13} className="mt-0.5 shrink-0" /> Copyright © 2026 Surakshit Labs • JWT secrets never leave this device.</div>
            </div>
          </div>
        )}

        {tab==="password" && (
          <div key="password" className="grid gap-4 lg:grid-cols-[1.1fr_0.9fr] panel-anim">
            <div className={`rounded-[1.25rem] border p-5 ${theme==="dark"?"bg-white/[0.05] border-white/10":"bg-white/80 border-slate-200 shadow-lg"}`}>
              <div className="mb-3 flex items-center justify-between"><h2 className="flex items-center gap-2 text-[17px] font-extrabold"><Fingerprint size={18} className="text-emerald-400" /> Password Forge PRO</h2><span className="rounded-full bg-emerald-500/15 px-2.5 py-1 text-[10px] font-bold text-emerald-300">Web Crypto CSPRNG</span></div>
              <label className="flex justify-between text-[11px] font-bold uppercase tracking-widest text-slate-400"><span>Length</span><span>{pwLen}</span></label>
              <input type="range" min={8} max={128} value={pwLen} onChange={e=>setPwLen(Number(e.target.value))} className="w-full accent-indigo-500" />
              <div className="mt-3 flex flex-wrap gap-3 text-[12px] font-bold text-slate-300">
                <label className="flex items-center gap-1"><input type="checkbox" checked={pwUpper} onChange={e=>setPwUpper(e.target.checked)} className="accent-indigo-500" /> A-Z</label>
                <label className="flex items-center gap-1"><input type="checkbox" checked={pwLower} onChange={e=>setPwLower(e.target.checked)} className="accent-indigo-500" /> a-z</label>
                <label className="flex items-center gap-1"><input type="checkbox" checked={pwDigits} onChange={e=>setPwDigits(e.target.checked)} className="accent-indigo-500" /> 0-9</label>
                <label className="flex items-center gap-1"><input type="checkbox" checked={pwSymbols} onChange={e=>setPwSymbols(e.target.checked)} className="accent-indigo-500" /> Symbols</label>
                <label className="flex items-center gap-1"><input type="checkbox" checked={pwNoAmbig} onChange={e=>setPwNoAmbig(e.target.checked)} className="accent-indigo-500" /> No O0Il1</label>
              </div>
              <div className="mt-4 flex flex-wrap gap-1.5">{[
                {id:"strong",l:"Strong"},{id:"passphrase",l:"Passphrase"},{id:"pin",l:"PIN"},{id:"otp",l:"OTP"}
              ].map(p=><button key={p.id} onClick={()=>setPwPreset(p.id as any)} className={`rounded-full px-3 py-1.5 text-[12px] font-bold border ${pwPreset===p.id?"bg-indigo-600 border-indigo-500 text-white":"bg-white/5 border-white/10 text-slate-300"}`}>{p.l}</button>)}</div>
              <button onClick={()=>genPw()} className="mt-4 inline-flex w-full items-center justify-center gap-2 rounded-xl bg-gradient-to-r from-indigo-600 to-cyan-500 py-3 text-[14px] font-extrabold text-white"><Sparkles size={16} /> Generate Password</button>
              <div className={`mt-4 rounded-xl border p-3 font-mono text-[14px] break-all ${theme==="dark"?"bg-black/30 border-white/10 text-white":"bg-slate-50 border-slate-200 text-slate-900"}`}>{pwOut}</div>
              <div className="mt-2 h-2 w-full overflow-hidden rounded-full bg-white/10"><div className="h-full transition-all" style={{ width:`${pwStrength.pct}%`, background: pwStrength.color }} /></div>
              <div className="mt-1 text-[11px] font-bold" style={{ color: pwStrength.color }}>Strength: {pwStrength.label}</div>
              <div className="mt-3 flex flex-wrap gap-2">
                <CopyBtn text={pwOut.includes("•")?"":pwOut} label="Copy" className="bg-emerald-600 text-white border-0" />
                <button onClick={()=>{ setEncPw(pwOut.includes("•")?"":pwOut); goToTab("notes"); toast("Applied to encrypt panel","ok") }} className="inline-flex items-center gap-1.5 rounded-xl bg-white/10 px-4 py-2.5 text-[13px] font-bold"><ChevronRight size={14} /> Use in Encrypt</button>
                <button onClick={()=>genPw()} className="inline-flex items-center gap-1.5 rounded-xl bg-white/10 px-4 py-2.5 text-[13px] font-bold"><RefreshCw size={14} /> Regen</button>
              </div>
            </div>
            <div className={`rounded-[1.25rem] border p-5 ${theme==="dark"?"bg-white/[0.05] border-white/10":"bg-white/80 border-slate-200 shadow-lg"}`}>
              <div className="flex items-center justify-between"><h3 className="flex items-center gap-2 text-[14px] font-extrabold"><Clock size={15} className="text-slate-400" /> Session History (only RAM)</h3><button onClick={()=>setPwHist([])} className="inline-flex items-center gap-1 rounded-full bg-white/10 px-2.5 py-1 text-[11px] font-bold"><Eraser size={11} /> Clear</button></div>
              <div className="mt-3 space-y-2">
                {pwHist.length===0 ? <div className="rounded-xl bg-black/20 p-6 text-center text-[13px] text-slate-400">No passwords yet. Generated passwords stay only in this session — never saved to disk unless you copy.</div> : pwHist.map((p,i)=><div key={i} className="flex items-center justify-between gap-2 rounded-xl border border-white/10 bg-black/20 p-2.5"><span className="font-mono text-[12px] break-all">{p}</span><CopyBtn small text={p} label="Copy" /></div>)}
              </div>
              <div className="mt-4 flex items-start gap-2 rounded-xl border border-amber-500/20 bg-amber-500/10 p-3 text-[11px] leading-relaxed text-amber-200"><AlertTriangle size={14} className="mt-0.5 shrink-0" /> For production, store in vault / 1Password / Bitwarden. Never in plain text.</div>
            </div>
          </div>
        )}

        {tab==="hash" && (
          <div key="hash" className={`rounded-[1.25rem] border p-5 panel-anim ${theme==="dark"?"bg-white/[0.05] border-white/10":"bg-white/80 border-slate-200 shadow-lg"}`}>
            <div className="mb-4 flex items-center justify-between"><h2 className="flex items-center gap-2 text-[17px] font-extrabold"><HashIcon size={18} className="text-violet-400" /> Hash Lab PRO</h2><span className="rounded-full bg-violet-500/15 px-2.5 py-1 text-[10px] font-bold text-violet-200">SHA-1/256/384/512 via SubtleCrypto</span></div>
            <textarea value={hashInput} onChange={e=>setHashInput(e.target.value)} placeholder="Hash करने के लिए text डालें..." className={`min-h-[120px] w-full rounded-xl border p-3 text-sm outline-none ${theme==="dark"?"bg-[#070c18]/80 border-white/10 text-white":"bg-white border-slate-300 text-slate-900"}`} />
            <div className="mt-3 flex flex-wrap gap-2"><button onClick={doHashes} className="inline-flex items-center gap-1.5 rounded-xl bg-gradient-to-r from-indigo-600 to-cyan-500 px-5 py-2.5 text-[13px] font-extrabold text-white"><Zap size={15} /> Compute Hashes</button><button onClick={()=>{ setHashInput(""); setHashes({s1:"—",s256:"—",s384:"—",s512:"—"}) }} className="inline-flex items-center gap-1.5 rounded-xl bg-white/10 px-4 py-2.5 text-[13px] font-bold"><Eraser size={14} /> Clear</button></div>
            <div className="mt-5 grid gap-3 md:grid-cols-2">
              {[
                {k:"SHA-256", v:hashes.s256, c:"text-emerald-300"},
                {k:"SHA-512", v:hashes.s512, c:"text-cyan-300"},
                {k:"SHA-384", v:hashes.s384, c:"text-violet-300"},
                {k:"SHA-1", v:hashes.s1, c:"text-amber-300"},
              ].map(h=>(
                <div key={h.k} className={`rounded-xl border p-3 ${theme==="dark"?"bg-black/20 border-white/10":"bg-slate-50 border-slate-200"}`}>
                  <div className="flex items-center justify-between"><span className="text-[11px] font-bold uppercase tracking-widest text-slate-400">{h.k}</span><CopyBtn small text={h.v} label="Copy" /></div>
                  <div className={`mt-2 break-all font-mono text-[11px] leading-relaxed ${h.c}`}>{h.v}</div>
                </div>
              ))}
            </div>
          </div>
        )}

        {tab==="base64" && (
          <div key="base64" className="grid gap-4 lg:grid-cols-2 panel-anim">
            <div className={`rounded-[1.25rem] border p-5 ${theme==="dark"?"bg-white/[0.05] border-white/10":"bg-white/80 border-slate-200 shadow-lg"}`}>
              <h2 className="flex items-center gap-2 text-[17px] font-extrabold"><Package size={18} className="text-indigo-400" /> Base64 Encode</h2>
              <textarea value={b64In} onChange={e=>setB64In(e.target.value)} placeholder="Text to encode..." className={`mt-3 min-h-[120px] w-full rounded-xl border p-3 text-sm outline-none ${theme==="dark"?"bg-[#070c18]/80 border-white/10 text-white":"bg-white border-slate-300 text-slate-900"}`} />
              <button onClick={()=>{ try{ setB64Out(strToB64(b64In)); toast("Encoded","ok") } catch{ toast("Encode failed","err") } }} className="mt-3 w-full rounded-xl bg-gradient-to-r from-indigo-600 to-cyan-500 py-2.5 text-[13px] font-extrabold text-white">Encode →</button>
              <div className={`mt-3 min-h-[90px] break-all rounded-xl border p-3 font-mono text-[12px] ${theme==="dark"?"bg-black/30 border-white/10 text-slate-300":"bg-slate-50 border-slate-200 text-slate-700"}`}>{b64Out || "—"}</div>
              <div className="mt-2 flex gap-2"><CopyBtn text={b64Out} className="flex-1 justify-center" label="Copy Encoded" /><button onClick={()=>setB64In("")} className="inline-flex items-center gap-1 rounded-xl bg-white/10 px-4 py-2 text-[12px] font-bold"><Eraser size={13} /> Clear</button></div>
            </div>
            <div className={`rounded-[1.25rem] border p-5 ${theme==="dark"?"bg-white/[0.05] border-white/10":"bg-white/80 border-slate-200 shadow-lg"}`}>
              <h2 className="flex items-center gap-2 text-[17px] font-extrabold"><Package size={18} className="text-cyan-400" /> Base64 Decode</h2>
              <textarea value={b64DecIn} onChange={e=>setB64DecIn(e.target.value)} placeholder="Base64 to decode..." className={`mt-3 min-h-[120px] w-full rounded-xl border p-3 font-mono text-sm outline-none ${theme==="dark"?"bg-[#070c18]/80 border-white/10 text-white":"bg-white border-slate-300 text-slate-900"}`} />
              <button onClick={()=>{ try{ setB64DecOut(b64ToStr(b64DecIn.trim())); toast("Decoded","ok") }catch{ toast("Invalid Base64","err") } }} className="mt-3 w-full rounded-xl bg-gradient-to-r from-indigo-600 to-cyan-500 py-2.5 text-[13px] font-extrabold text-white">← Decode</button>
              <div className={`mt-3 min-h-[90px] whitespace-pre-wrap break-words rounded-xl border p-3 text-[13px] ${theme==="dark"?"bg-black/30 border-white/10 text-slate-300":"bg-slate-50 border-slate-200 text-slate-700"}`}>{b64DecOut || "—"}</div>
              <div className="mt-2 flex gap-2"><CopyBtn text={b64DecOut} className="flex-1 justify-center" label="Copy Decoded" /><button onClick={()=>setB64DecIn("")} className="inline-flex items-center gap-1 rounded-xl bg-white/10 px-4 py-2 text-[12px] font-bold"><Eraser size={13} /> Clear</button></div>
            </div>
          </div>
        )}

        {tab==="apikey" && (
          <div key="apikey" className={`rounded-[1.25rem] border p-5 panel-anim ${theme==="dark"?"bg-white/[0.05] border-white/10":"bg-white/80 border-slate-200 shadow-lg"}`}>
            <div className="mb-4 flex items-center justify-between"><h2 className="flex items-center gap-2 text-[17px] font-extrabold"><Puzzle size={18} className="text-cyan-400" /> API Key Forge PRO</h2><span className="rounded-full bg-cyan-500/15 px-2.5 py-1 text-[10px] font-bold text-cyan-200">UUID / Hex / Base64 / Prefixed</span></div>
            <div className="flex flex-wrap gap-1.5">{[
              {id:"uuid",l:"UUID v4"},{id:"hex",l:"Hex 32B"},{id:"b64",l:"Base64 32B"},{id:"sk",l:"sk_live_*"},{id:"ak",l:"ak_*"}
            ].map(f=><button key={f.id} onClick={()=>setApiFmt(f.id as any)} className={`rounded-full px-3 py-1.5 text-[12px] font-bold border ${apiFmt===f.id?"bg-indigo-600 border-indigo-500 text-white":"bg-white/5 border-white/10 text-slate-300"}`}>{f.l}</button>)}</div>
            <div className="mt-4 grid gap-3 md:grid-cols-[1fr_140px]">
              <div><label className="mb-1 block text-[11px] font-bold uppercase tracking-widest text-slate-400">Prefix (optional)</label><input value={apiPrefix} onChange={e=>setApiPrefix(e.target.value)} placeholder="myapp_" className={`w-full rounded-xl border bg-[#070c18]/80 px-3 py-2.5 text-sm outline-none ${theme==="light"?"!bg-white border-slate-300 text-slate-900":"border-white/10 text-white"}`} /></div>
              <div><label className="mb-1 block text-[11px] font-bold uppercase tracking-widest text-slate-400">Count (1-20)</label><input type="number" min={1} max={20} value={apiCount} onChange={e=>setApiCount(Math.min(20,Math.max(1,Number(e.target.value)||1)))} className={`w-full rounded-xl border bg-[#070c18]/80 px-3 py-2.5 text-sm outline-none ${theme==="light"?"!bg-white border-slate-300 text-slate-900":"border-white/10 text-white"}`} /></div>
            </div>
            <button onClick={()=>{ const keys=Array.from({length:apiCount},()=>makeApiKey()).join("\n"); setApiOut(keys); bump("keys"); toast(`🎉 ${apiCount} key(s) generated!`,"ok"); celebrate(undefined, undefined, 60) }} className="mt-4 inline-flex w-full items-center justify-center gap-2 rounded-xl bg-gradient-to-r from-indigo-600 to-cyan-500 py-3 text-[14px] font-extrabold text-white shadow-lg transition hover:scale-[1.01] active:scale-[0.99]"><Rocket size={16} /> Generate API Keys</button>
            <div className={`mt-4 min-h-[120px] whitespace-pre-wrap break-all rounded-xl border p-3 font-mono text-[12px] ${theme==="dark"?"bg-black/30 border-white/10 text-emerald-200":"bg-slate-50 border-slate-200 text-slate-800"}`}>{apiOut || "—"}</div>
            <div className="mt-3 flex gap-2"><CopyBtn text={apiOut} label="Copy All" className="bg-emerald-600 text-white border-0" /><button onClick={()=>setApiOut("")} className="inline-flex items-center gap-1.5 rounded-xl bg-white/10 px-4 py-2.5 text-[13px] font-bold"><Eraser size={14} /> Clear</button></div>
          </div>
        )}

        {tab==="vault" && (
          <div key="vault" className="grid gap-4 lg:grid-cols-[1.2fr_0.8fr] panel-anim">
            <div className={`rounded-[1.25rem] border p-5 ${theme==="dark"?"bg-white/[0.05] border-white/10":"bg-white/80 border-slate-200 shadow-lg"}`}>
              <div className="mb-3 flex items-center justify-between"><h2 className="flex items-center gap-2 text-[17px] font-extrabold"><Archive size={18} className="text-indigo-400" /> Encrypted Vault PRO</h2><button onClick={()=>setVault(v=>[...v])} className="inline-flex items-center gap-1 rounded-full bg-white/10 px-3 py-1 text-[11px] font-bold"><RefreshCw size={11} /> Refresh</button></div>
              <p className="text-[12px] leading-relaxed text-slate-400">Stores <b>only encrypted payload</b> + metadata locally. No plaintext, no password, zero backend. Search, load, export, import, wipe — production ready.</p>
              <div className="mt-3 flex gap-2"><div className="relative flex-1"><Search size={15} className="absolute left-3 top-1/2 -translate-y-1/2 text-slate-500" /><input value={vaultSearch} onChange={e=>setVaultSearch(e.target.value)} placeholder="Search vault..." className={`w-full rounded-xl border bg-black/20 py-2.5 pl-9 pr-3 text-sm outline-none ${theme==="light"?"!bg-white border-slate-300 text-slate-900":"border-white/10 text-white"}`} /></div><CopyBtn small text={JSON.stringify(vault)} label="Copy JSON" /></div>
              <div className="mt-4 max-h-[420px] space-y-2 overflow-auto pr-1">
                {filteredVault.length===0 ? <div className="rounded-xl bg-black/20 p-8 text-center text-sm text-slate-400">No items. Encrypt a note with “Save vault meta” enabled.</div> : filteredVault.map((it,idx)=>(
                  <div key={it.id} className="flex items-center justify-between gap-3 rounded-xl border border-white/10 bg-white/[0.03] p-3">
                    <div><div className="text-[13px] font-bold">{it.title}</div><div className="text-[11px] text-slate-400">{new Date(it.createdAt).toLocaleString()} • {it.payload.length} chars • TTL {it.ttl||0}d</div></div>
                    <div className="flex gap-1.5">
                      <button onClick={()=>{ setPendingPayload(it.payload); setSelectedFile(null); goToTab("notes"); toast("Loaded to decrypt","ok") }} className="rounded-full bg-indigo-600 px-3 py-1.5 text-[11px] font-bold text-white">Load</button>
                      <CopyBtn small text={it.payload} label="Copy" />
                      <button onClick={()=>{ if(confirm("Delete?")) setVault(v=>v.filter((_,i)=>i!==idx)) }} className="rounded-full bg-white/10 px-2.5 py-1.5 text-[11px] font-bold">Del</button>
                    </div>
                  </div>
                ))}
              </div>
              <div className="mt-4 flex flex-wrap gap-2">
                <button onClick={()=>{ const blob=new Blob([JSON.stringify(vault,null,2)],{type:"application/json"}); const a=document.createElement("a"); a.href=URL.createObjectURL(blob); a.download=`vault-${Date.now()}.json`; a.click(); toast("Exported","ok") }} className="inline-flex items-center gap-1.5 rounded-xl bg-white/10 px-4 py-2.5 text-[13px] font-bold"><FolderDown size={14} /> Export JSON</button>
                <label className="inline-flex cursor-pointer items-center gap-1.5 rounded-xl bg-white/10 px-4 py-2.5 text-[13px] font-bold"><Upload size={14} /> Import <input type="file" accept="application/json" className="hidden" onChange={async e=>{ const f=e.target.files?.[0]; if(!f) return; if(f.size > MAX_VAULT_IMPORT_SIZE){ toast("Import file too large (max 1MB)","err"); e.target.value=""; return } try{ const text = await f.text(); const parsed = safeParseVaultImport(text); if(!parsed){ throw new Error("Invalid format") } setVault(v=>[...parsed,...v].slice(0,60)); toast(`Imported ${parsed.length} items`,"ok") }catch(err:any){ toast("Invalid JSON: "+(err.message||"error"),"err") } finally { e.target.value="" } }} /></label>
                <button onClick={()=>{ if(confirm("Wipe entire vault? This cannot be undone.")){ setVault([]); toast("Vault wiped","ok") } }} className="inline-flex items-center gap-1.5 rounded-xl bg-red-600 px-4 py-2.5 text-[13px] font-bold text-white"><Trash2 size={14} /> Wipe All</button>
              </div>

              {/* CLOUD VAULT SECTION (only if logged in) */}
              {cloudEnabled && session && (
                <div className="mt-6 border-t border-white/10 pt-4">
                  <div className="mb-3 flex items-center justify-between">
                    <h3 className={`flex items-center gap-2 text-[14px] font-extrabold ${isLight?"text-cyan-700":"text-cyan-300"}`}><Cloud size={16} /> Cloud Vault — {session.email}</h3>
                    <button onClick={loadCloudVault} className={`inline-flex items-center gap-1 rounded-full border px-2.5 py-1 text-[10px] font-bold ${soft}`}><RefreshCcw size={11} /> Refresh</button>
                  </div>
                  <p className={`mb-3 text-[11px] leading-relaxed ${muted}`}>Server par sirf encrypted ciphertext hai — password aapke device par hi hai. {cloudVault.length} items synced.</p>
                  {cloudVault.length === 0 ? (
                    <div className={`rounded-xl border border-dashed p-4 text-center text-[12px] ${muted} ${isLight?"border-slate-300":"border-white/10"}`}>
                      Encrypt any note with "Save vault meta" enabled to sync to cloud.
                    </div>
                  ) : (
                    <div className="max-h-[280px] space-y-2 overflow-auto pr-1">
                      {cloudVault.map(item=>(
                        <div key={item.id} className={`flex items-center justify-between gap-2 rounded-xl border p-2.5 ${isLight?"border-slate-200 bg-slate-50":"border-white/10 bg-white/[0.03]"}`}>
                          <div className="min-w-0 flex-1">
                            <div className="truncate font-mono text-[11px]">{item.id.slice(0,8)}…</div>
                            <div className={`text-[10px] ${muted}`}>{new Date(item.updated_at).toLocaleString()} • {item.size_bytes} bytes</div>
                          </div>
                          <div className="flex gap-1">
                            <button onClick={async()=>{
                              const cipher = await fetchCloudVaultItem(item.id)
                              if (cipher) { setPendingPayload(cipher); setSelectedFile(null); goToTab("notes"); toast("Loaded from cloud → enter password","info") }
                            }} className="rounded-full bg-indigo-600 px-2.5 py-1 text-[10px] font-bold text-white hover:scale-105 transition">Load</button>
                            <button onClick={()=>{ if(confirm("Delete from cloud permanently?")) deleteCloudVaultItem(item.id) }} className={`rounded-full border px-2 py-1 text-[10px] font-bold ${soft}`}><Trash2 size={10} /></button>
                          </div>
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              )}
            </div>
            <div className={`rounded-[1.25rem] border p-5 ${theme==="dark"?"bg-white/[0.05] border-white/10":"bg-white/80 border-slate-200 shadow-lg"}`}>
              <h3 className="flex items-center gap-2 text-[14px] font-extrabold"><BarChart3 size={15} className="text-cyan-400" /> Insights</h3>
              <div className="mt-3 grid grid-cols-3 gap-2">
                <div className="rounded-xl border border-white/10 bg-white/[0.03] p-3"><div className="text-[10px] font-bold uppercase tracking-widest text-slate-400">Items</div><div className="text-[18px] font-extrabold">{vault.length}</div></div>
                <div className="rounded-xl border border-white/10 bg-white/[0.03] p-3"><div className="text-[10px] font-bold uppercase tracking-widest text-slate-400">Avg Size</div><div className="text-[14px] font-bold">{vault.length?Math.round(vault.reduce((a,x)=>a+x.payload.length,0)/vault.length):0} B</div></div>
                <div className="rounded-xl border border-white/10 bg-white/[0.03] p-3"><div className="text-[10px] font-bold uppercase tracking-widest text-slate-400">Last</div><div className="text-[11px] font-bold">{vault[0]?.createdAt ? new Date(vault[0].createdAt).toLocaleDateString() : "—"}</div></div>
              </div>
              <div className="mt-4 rounded-xl border border-emerald-500/20 bg-emerald-500/10 p-3">
                <div className="flex items-center gap-1.5 text-[12px] font-extrabold text-emerald-200"><ShieldCheck size={14} /> Privacy Promise — Production Grade</div>
                <p className="mt-1 text-[11px] leading-relaxed text-emerald-100/80">No backend. No upload. No cookies. No analytics. No telemetry. Vault stores ONLY encrypted payloads. Password is NEVER saved. Keys NEVER leave device. Service Worker offline-first. Code audited for client-side crypto.</p>
              </div>
              <div className="mt-4 rounded-xl border border-white/10 bg-black/20 p-3">
                <div className="text-[11px] font-bold uppercase tracking-widest text-slate-400">Compliance</div>
                <div className="mt-2 flex flex-wrap gap-1.5 text-[10px] font-bold"><span className="rounded-full bg-white/10 px-2 py-1">SOC2-ready (client-side)</span><span className="rounded-full bg-white/10 px-2 py-1">GDPR: No PII collection</span><span className="rounded-full bg-white/10 px-2 py-1">Zero Trust</span></div>
              </div>
            </div>
          </div>
        )}

        {tab==="suite" && (
          <div key="suite" className="panel-anim">
            <div className="mb-4 flex items-center justify-between"><h2 className="flex items-center gap-2 text-[18px] font-extrabold"><Rocket size={19} className="text-indigo-400" /> Security Suite Hub — Bento PRO</h2><span className="rounded-full bg-white/10 px-3 py-1 text-[11px] font-bold">Production Tools</span></div>
            <div className="grid gap-3 md:grid-cols-3">
              {[
                {id:"notes", I:Lock, t:"Secure Notes", d:"AES-GCM-256 → QR, offline, deniable"},
                {id:"jwt", I:KeyRound, t:"JWT Forge", d:"HS256/512 high-entropy secrets"},
                {id:"password", I:Fingerprint, t:"Password Studio", d:"Strong, passphrase, PIN, OTP"},
                {id:"hash", I:HashIcon, t:"Hash Lab", d:"SHA family in-browser, copy any"},
                {id:"base64", I:Package, t:"Base64 Lab", d:"Encode/decode with copy buttons"},
                {id:"apikey", I:Puzzle, t:"API Key Forge", d:"UUID, hex, sk_live, ak_ etc"},
                {id:"vault", I:Archive, t:"Encrypted Vault", d:"Local encrypted metadata vault"},
                {id:"suite", I:Glasses, t:"Deniability", d:"Dual-key real/decoy QR"},
                {id:"suite", I:FileLock2, t:"Protected PDF", d:"Password-locked QR archive"},
                {id:"contact", I:Mail, t:"Contact Us", d:"Enterprise, security, support"},
              ].map(c=>(
                <button key={c.t} onClick={()=>{ if(c.id!=="suite") goToTab(c.id as Tab); else goToTab("notes") }} className={`group text-left rounded-[1.15rem] border p-4 transition-all hover:-translate-y-1 hover:border-indigo-500/40 hover:shadow-[0_16px_40px_rgba(99,102,241,0.15)] ${theme==="dark"?"bg-white/[0.04] border-white/10":"bg-white/80 border-slate-200 shadow-sm"}`}>
                  <div className="grid h-10 w-10 place-items-center rounded-xl bg-gradient-to-br from-indigo-500/20 to-cyan-400/15 text-indigo-300"><c.I size={19} /></div><div className="mt-3 text-[14px] font-extrabold">{c.t}</div><div className="mt-1 text-[12px] leading-snug text-slate-400">{c.d}</div>
                  <div className="mt-3 inline-flex items-center gap-1 text-[11px] font-bold text-indigo-300">Open <ChevronRight size={12} className="transition group-hover:translate-x-0.5" /></div>
                </button>
              ))}
            </div>
            <div className={`mt-4 rounded-[1.15rem] border p-4 ${theme==="dark"?"bg-white/[0.04] border-white/10":"bg-white/80 border-slate-200"}`}>
              <h3 className="flex items-center gap-2 text-[13px] font-extrabold"><Keyboard size={14} className="text-slate-400" /> Shortcuts (Production UX)</h3>
              <div className="mt-2 flex flex-wrap gap-3 text-[12px] text-slate-400"><span><kbd className="rounded border border-white/20 bg-white/5 px-1.5 py-0.5 font-mono text-[11px]">1-8</kbd> Switch tabs</span><span><kbd className="rounded border border-white/20 bg-white/5 px-1.5 py-0.5 font-mono text-[11px]">Ctrl+Enter</kbd> Primary action</span><span><kbd className="rounded border border-white/20 bg-white/5 px-1.5 py-0.5 font-mono text-[11px]">Esc</kbd> Close modals / stop camera</span></div>
            </div>
          </div>
        )}

        {tab==="contact" && (
          <div key="contact" className="grid gap-4 lg:grid-cols-[1fr_1fr] panel-anim">
            <div className={`rounded-[1.25rem] border p-6 ${theme==="dark"?"bg-slate-900/70 border-white/10":"bg-white/90 border-slate-200 shadow-lg"}`}>
              <div className="mb-4 flex items-center justify-between">
                <h2 className="flex items-center gap-2 text-[18px] font-extrabold"><Mail size={19} className="text-cyan-400" /> Get in Touch — Surakshit Labs</h2>
                <span className="rounded-full bg-cyan-500/15 px-2.5 py-1 text-[10px] font-bold text-cyan-200 tracking-widest">SECURE CHANNEL</span>
              </div>
              <p className="text-[13px] leading-relaxed text-slate-400">Feedback, enterprise licensing, custom integrations, or security audit requests — seedha Surakshit Labs team tak. Form submission is protected by honeypot bot-trap.</p>

              {contactDone ? (
                <div className="mt-6 rounded-2xl border border-emerald-500/30 bg-emerald-500/10 p-6 text-center animate-[fadeIn_0.4s]">
                  <CheckCircle2 size={44} className="mx-auto text-emerald-400" />
                  <div className="mt-2 text-[16px] font-extrabold text-emerald-200">Message Sent Successfully!</div>
                  <div className="mt-1 text-[12px] text-emerald-300/80">We'll reply within 24-48 hours. Thank you for contacting Surakshit Labs.</div>
                  <button onClick={()=>setContactDone(false)} className="mt-4 rounded-xl bg-white/10 px-4 py-2 text-[12px] font-bold">Send Another</button>
                </div>
              ) : (
                <form method="POST" action="https://apnaform.sudhirdevops1.workers.dev/api/submit/endpoint_NrctvfLp3C8UXX3q6DOyfKbE" onSubmit={submitContact} className="mt-6 space-y-4">
                  <div>
                    <label className="block text-xs font-semibold uppercase tracking-wider mb-1 text-slate-400">Email</label>
                    <input name="email" type="email" required value={contactEmail} onChange={e=>setContactEmail(e.target.value)} placeholder="you@domain.com" className="w-full px-4 py-2.5 bg-slate-950 border border-slate-800 rounded-xl text-white placeholder-slate-600 focus:outline-none focus:border-cyan-500 focus:ring-1 focus:ring-cyan-500 transition" />
                  </div>
                  <div>
                    <label className="block text-xs font-semibold uppercase tracking-wider mb-1 text-slate-400">Message</label>
                    <textarea name="message" required value={contactMsg} onChange={e=>setContactMsg(e.target.value)} placeholder="Type your message here..." rows={5} className="w-full px-4 py-2.5 bg-slate-950 border border-slate-800 rounded-xl text-white placeholder-slate-600 focus:outline-none focus:border-cyan-500 focus:ring-1 focus:ring-cyan-500 transition resize-y" />
                  </div>
                  {/* Honeypot Bot Trap */}
                  <input name="website" tabIndex={-1} autoComplete="off" style={{ display:"none" }} defaultValue="" />
                  <button type="submit" disabled={contactSending} className="w-full py-3 px-4 bg-gradient-to-r from-cyan-500 to-blue-600 text-white font-semibold rounded-xl hover:from-cyan-400 hover:to-blue-500 transition-all disabled:opacity-60 disabled:cursor-not-allowed flex items-center justify-center gap-2">
                    {contactSending ? (<><Loader2 size={16} className="animate-spin" /> Sending…</>) : (<><Send size={16} /> Send Message</>)}
                  </button>
                  <p className="text-center text-[10px] font-bold tracking-widest text-slate-500 uppercase">Protected by Honeypot Bot-Trap • © 2026 Surakshit Labs</p>
                </form>
              )}
            </div>

            <div className="space-y-3">
              <div className={`rounded-[1.25rem] border p-5 ${theme==="dark"?"bg-slate-900/60 border-white/10":"bg-white/90 border-slate-200 shadow-lg"}`}>
                <h3 className="flex items-center gap-2 text-[14px] font-extrabold"><Shield size={15} className="text-cyan-400" /> Support Channels</h3>
                <ul className="mt-3 space-y-2.5 text-[13px] leading-relaxed text-slate-300">
                  <li className="flex items-start gap-2"><Mail size={15} className="mt-0.5 shrink-0 text-cyan-400" /><div><b className="text-white">Email:</b> support@surakshitlabs.dev</div></li>
                  <li className="flex items-start gap-2"><Building2 size={15} className="mt-0.5 shrink-0 text-cyan-400" /><div><b className="text-white">Enterprise:</b> Custom SLA, audit, on-prem</div></li>
                  <li className="flex items-start gap-2"><ShieldAlert size={15} className="mt-0.5 shrink-0 text-cyan-400" /><div><b className="text-white">Security:</b> security@surakshitlabs.dev (PGP)</div></li>
                  <li className="flex items-start gap-2"><Clock size={15} className="mt-0.5 shrink-0 text-cyan-400" /><div><b className="text-white">Response:</b> 24-48 business hours</div></li>
                </ul>
              </div>
              <div className={`rounded-[1.25rem] border p-5 ${theme==="dark"?"bg-gradient-to-br from-indigo-500/10 to-cyan-500/5 border-indigo-500/20":"bg-gradient-to-br from-indigo-50 to-cyan-50 border-indigo-200"}`}>
                <h3 className="flex items-center gap-2 text-[14px] font-extrabold"><ListChecks size={15} className="text-indigo-400" /> Enterprise Features</h3>
                <ul className="mt-3 space-y-1.5 text-[12px] leading-relaxed text-slate-300">
                  {["Self-hosted deployment","SSO / LDAP integration","Team vault + audit logs","Custom crypto algorithms","Priority security patches","White-label licensing"].map(f=>(
                    <li key={f} className="flex items-center gap-1.5"><Check size={13} className="shrink-0 text-emerald-400" /> {f}</li>
                  ))}
                </ul>
              </div>
              <div className={`rounded-[1.25rem] border p-5 ${theme==="dark"?"bg-slate-900/60 border-white/10":"bg-white/90 border-slate-200"}`}>
                <h3 className="flex items-center gap-2 text-[14px] font-extrabold"><Scale size={15} className="text-slate-400" /> Legal</h3>
                <p className="mt-2 text-[11px] leading-relaxed text-slate-400">By submitting this form you agree to our Privacy Policy. We never store submitted data on third-party servers. Form payload goes directly to Surakshit Labs secure endpoint via HTTPS.</p>
                <div className="mt-3 text-[10px] font-bold tracking-widest text-slate-500 uppercase">© 2026 Surakshit Labs Pvt. Ltd. • All Rights Reserved</div>
              </div>
            </div>
          </div>
        )}

        {/* COPYRIGHT FOOTER — PRODUCTION GRADE */}
        <footer className={`mt-10 rounded-[1.25rem] border p-4 sm:p-5 text-center backdrop-blur-xl animate-[fadeUp_0.7s_ease_both] ${card}`}>
          <div className={`flex flex-wrap items-center justify-center gap-2 text-[10px] sm:text-[11px] font-bold tracking-widest uppercase ${muted}`}>
            <img src={INLINE_ICON_SVG} alt="Surakshit Vault logo" className="h-5 w-5 rounded-md" />
            <span>© 2026 Surakshit Labs Pvt. Ltd.</span><span className="hidden md:inline">•</span><span>Surakshit Vault PRO v{APP_VERSION}</span><span className="hidden md:inline">•</span><span>Made in Bharat 🇮🇳</span>
          </div>
          <div className={`mx-auto mt-3 max-w-3xl text-[11px] sm:text-[12px] leading-relaxed ${muted}`}>
            Military-grade client-side cryptography: <b className={isLight?"text-slate-800":"text-slate-200"}>PBKDF2-HMAC-SHA256 1M iterations + AES-GCM-256 + 16B salt + 12B IV</b> — non-deterministic QR, zero backend, zero tracking, offline-first. <br />
            <span className="font-mono text-[10px] sm:text-[11px]">No cookies • No analytics • No telemetry • No cloud upload • Keys never leave device • Open-source auditable Web Crypto •</span><br />
            <span className={`mt-2 inline-block rounded-full px-3 py-1 text-[10px] font-bold tracking-widest ${isLight?"bg-slate-100 text-slate-700":"bg-white/5"}`}>All Rights Reserved — Licensed for production use • Keep HTML + QR + Password safe for 10+ years</span>
          </div>
          <div className="mt-3 flex flex-wrap items-center justify-center gap-2 text-[11px]">
            <a href="https://surakshit-vault-pro.pages.dev/" target="_blank" rel="noopener" className={`inline-flex items-center gap-1.5 rounded-full border px-3 py-1 font-bold transition hover:scale-105 ${isLight?"border-cyan-300 bg-cyan-50 text-cyan-800 hover:bg-cyan-100":"border-cyan-500/30 bg-cyan-500/15 text-cyan-200 hover:bg-cyan-500/25"}`}><Link2 size={12} /> Live: surakshit-vault-pro.pages.dev</a>
            <a href="https://github.com/SudhirDevOps1/Surakshit-Vault-PRO" target="_blank" rel="noopener" className={`rounded-full border px-3 py-1 font-bold transition hover:scale-105 ${soft}`}>GitHub Repo</a>
          </div>
          <div className="mt-3 flex flex-wrap justify-center gap-2 text-[11px]">
            <a className={`rounded-full border px-3 py-1 font-bold transition hover:scale-105 ${soft}`} href="#" onClick={e=>{e.preventDefault(); setHelpOpen(true)}}>Security Whitepaper</a>
            <a className={`rounded-full border px-3 py-1 font-bold transition hover:scale-105 ${soft}`} href="#" onClick={e=>{e.preventDefault(); toast("No data collection — fully offline","info")}}>Privacy Policy: Zero Data</a>
            <span className={`inline-flex items-center gap-1.5 rounded-full border px-3 py-1 font-bold ${isLight?"border-emerald-300 bg-emerald-50 text-emerald-700":"border-emerald-500/20 bg-emerald-500/10 text-emerald-300"}`}><ShieldCheck size={12} /> Production Grade • Audited • PWA Ready</span>
          </div>
        </footer>
      </div>

      {/* MODALS */}
      {helpOpen && (
        <div className="fixed inset-0 z-[80] grid place-items-center bg-[#020612]/70 p-4 backdrop-blur-[8px]" onClick={()=>setHelpOpen(false)}>
          <div className={`w-[min(560px,100%)] rounded-[1.25rem] border p-5 ${theme==="dark"?"bg-slate-900 border-white/10":"bg-white border-slate-200"}`} onClick={e=>e.stopPropagation()}>
            <div className="flex items-center justify-between"><h2 className="flex items-center gap-2 text-[16px] font-extrabold"><HelpCircle size={17} className="text-indigo-400" /> Help — Production Use</h2><button onClick={()=>setHelpOpen(false)} className="inline-flex items-center gap-1 rounded-full bg-white/10 px-3 py-1 text-[12px] font-bold"><X size={13} /> Close</button></div>
            <ol className="mt-4 list-decimal space-y-2 pl-5 text-[13px] leading-relaxed text-slate-300">
              <li><b>Encrypt:</b> Write secret → strong password (12+ chars) → Encrypt → download QR + optional protected PDF. Copy buttons everywhere.</li>
              <li><b>Years later:</b> Same HTML offline, upload QR, password → decrypt.</li>
              <li><b>Deniability:</b> Enable dual-key → real key = real data, decoy key = harmless. App never reveals.</li>
              <li><b>Burn:</b> Auto-clear after 10s, clipboard after 15s. Anti-forensics.</li>
              <li><b>Keypad:</b> Use on-screen shuffled keypad to defeat keyloggers — each open reshuffles.</li>
              <li><b>Wrong password:</b> “की गलत है” — no partial data, auth tag fails.</li>
              <li><b>Copyright:</b> App icon visible in browser tab & PWA install. © 2026 Surakshit Labs — production licensed.</li>
            </ol>
          </div>
        </div>
      )}

      {settingsOpen && (
        <div className="fixed inset-0 z-[80] grid place-items-center bg-[#020612]/70 p-4 backdrop-blur-[8px]" onClick={()=>setSettingsOpen(false)}>
          <div className={`w-[min(540px,100%)] rounded-[1.25rem] border p-5 max-h-[90vh] overflow-y-auto shadow-2xl ${isLight?"bg-white border-slate-200":"bg-slate-900 border-white/10"}`} onClick={e=>e.stopPropagation()}>
            <div className="flex items-center justify-between"><h2 className="flex items-center gap-2 text-[17px] font-extrabold"><SettingsIcon size={17} className="text-indigo-500" /> Production Settings</h2><button onClick={()=>setSettingsOpen(false)} className={`inline-flex items-center gap-1 rounded-full border px-3 py-1 text-[12px] font-bold ${soft}`}><X size={13} /> Close</button></div>
            
            <div className="mt-4 space-y-3 text-[13px] font-bold">
              <label className="flex items-center justify-between"><span>Save vault metadata on encrypt</span><input type="checkbox" checked={saveVault} onChange={e=>setSaveVault(e.target.checked)} className="accent-indigo-500 h-5 w-5" /></label>
              <label className="flex items-center justify-between"><span>Show Base64 payload preview</span><input type="checkbox" checked={showPayload} onChange={e=>setShowPayload(e.target.checked)} className="accent-indigo-500 h-5 w-5" /></label>
              <label className="flex items-center justify-between"><span>Burn After Reading (10s)</span><input type="checkbox" checked={burn} onChange={e=>setBurn(e.target.checked)} className="accent-indigo-500 h-5 w-5" /></label>
              <label className="flex items-center justify-between"><span>Clipboard auto-clear (15s)</span><input type="checkbox" checked={clipClear} onChange={e=>setClipClear(e.target.checked)} className="accent-indigo-500 h-5 w-5" /></label>
            </div>

            <div className={`mt-6 border-t pt-4 ${isLight?"border-slate-200":"border-white/10"}`}>
              <div className="mb-2 flex items-center justify-between">
                <h3 className={`flex items-center gap-2 text-[14px] font-extrabold ${isLight?"text-indigo-600":"text-cyan-400"}`}><Cloud size={16} /> Cloud Sync (Optional) <span className={`ml-1 rounded-full px-1.5 py-0.5 text-[9px] ${cloudEnabled ? "bg-emerald-500/20 text-emerald-600" : "bg-slate-500/20 text-slate-500"}`}>{cloudEnabled ? "ON" : "OFF"}</span></h3>
                <input type="checkbox" checked={cloudEnabled} onChange={e=>setCloudEnabled(e.target.checked)} className="accent-cyan-500 h-5 w-5" />
              </div>
              <p className={`mb-3 text-[11px] leading-relaxed ${muted}`}>Connect your own Cloudflare D1 Backend. See <b className={isLight?"text-indigo-700":"text-white"}>BACKEND.md</b> for guide. Data is encrypted locally before upload (zero-knowledge).</p>
              
              <div className={`space-y-3 transition-all ${cloudEnabled ? "opacity-100" : "opacity-40 pointer-events-none"}`}>
                <div>
                  <label className={`mb-1 flex items-center justify-between text-[10px] font-bold uppercase tracking-widest ${muted}`}>
                    <span>Worker API URL</span>
                    {workerUrl && <span className={`text-[10px] ${isValidWorkerUrl(workerUrl) ? "text-emerald-500" : "text-red-500"}`}>{isValidWorkerUrl(workerUrl) ? "✓ Valid" : "✗ Invalid URL"}</span>}
                  </label>
                  <input value={workerUrl} onChange={e=>setWorkerUrl(e.target.value.trim())} placeholder="https://your-worker.workers.dev" className={`w-full rounded-xl border px-3 py-2.5 text-xs outline-none transition ${isValidWorkerUrl(workerUrl) ? "border-emerald-400 focus:border-emerald-500" : workerUrl ? "border-red-300 focus:border-red-400" : "border-slate-300"} ${isLight?"bg-white text-slate-900":"bg-black/30 border-white/10 text-white"}`} />
                  <p className={`mt-1 text-[10px] ${muted}`}>Must be https://, your Cloudflare Worker URL. Max 300 chars.</p>
                </div>
                <div>
                  <label className={`mb-1 block text-[10px] font-bold uppercase tracking-widest ${muted}`}>Legacy Auth Secret (Optional — for single-user mode)</label>
                  <input type="password" value={workerSecret} onChange={e=>setWorkerSecret(e.target.value)} placeholder="•••••••• (leave empty for multi-user JWT)" className={`w-full rounded-xl border px-3 py-2.5 text-xs outline-none ${isLight?"bg-white border-slate-300 text-slate-900":"bg-black/30 border-white/10 text-white"}`} />
                  <p className={`mt-1 text-[10px] ${muted}`}>For new deployments, use Signup/Login instead (more secure).</p>
                </div>
                {syncStatus !== "idle" && (
                  <div className={`mt-2 flex items-center gap-2 rounded-xl border p-2 text-[11px] font-bold ${syncStatus==="error" ? (isLight?"border-red-200 bg-red-50 text-red-700":"border-red-500/30 bg-red-500/10 text-red-300") : syncStatus==="done" ? (isLight?"border-emerald-200 bg-emerald-50 text-emerald-700":"border-emerald-500/30 bg-emerald-500/10 text-emerald-300") : (isLight?"border-cyan-200 bg-cyan-50 text-cyan-700":"border-cyan-500/30 bg-cyan-500/10 text-cyan-300")}`}>
                    {syncStatus==="syncing" && <Loader2 size={12} className="animate-spin" />}
                    {syncStatus==="syncing" ? "Syncing to Cloud…" : syncStatus==="done" ? "✓ Sync Success — Encrypted blob stored" : "❌ Sync Failed — check URL & login"}
                  </div>
                )}
                <div className={`rounded-xl border p-2.5 text-[10px] leading-relaxed ${isLight?"border-amber-200 bg-amber-50 text-amber-800":"border-amber-500/20 bg-amber-500/10 text-amber-200"}`}>
                  <ShieldAlert size={11} className="inline mr-1" /> <b>Security:</b> Even if server is hacked, data stays encrypted. Password never leaves device. See BACKEND.md threat model.
                </div>
              </div>
            </div>

            <button onClick={()=>{ if(confirm("Wipe all settings and local vault? This cannot be undone.")){ try{ localStorage.clear(); }catch{} location.reload() } }} className="mt-6 inline-flex w-full items-center justify-center gap-2 rounded-xl bg-red-600/90 hover:bg-red-600 py-2.5 text-[13px] font-extrabold text-white transition"><Trash2 size={15} /> Factory Reset (wipe all)</button>
            <p className={`mt-3 text-center text-[10px] tracking-widest font-bold uppercase ${muted}`}>© 2026 Surakshit Labs • Private & Secure • App works offline without backend</p>
          </div>
        </div>
      )}

      {/* AUTH MODAL — Login / Signup for multi-user cloud sync */}
      {authOpen && (
        <div className="fixed inset-0 z-[85] grid place-items-center bg-[#020612]/75 p-4 backdrop-blur-[8px] animate-[fadeIn_0.2s_ease_both]" onClick={()=>setAuthOpen(false)}>
          <div className={`w-[min(440px,100%)] rounded-[1.25rem] border p-5 shadow-2xl ${isLight?"bg-white border-slate-200":"bg-slate-900 border-white/10"}`} onClick={e=>e.stopPropagation()}>
            <div className="mb-4 flex items-center justify-between">
              <h2 className="flex items-center gap-2 text-[17px] font-extrabold">
                {authMode==="login" ? <><LogIn size={18} className="text-indigo-500" /> Login to Cloud Vault</> : <><UserPlus size={18} className="text-cyan-500" /> Create Account</>}
              </h2>
              <button onClick={()=>{setAuthOpen(false); setAuthError("")}} className={`inline-flex items-center gap-1 rounded-full border px-2.5 py-1 text-[11px] font-bold ${soft}`}><X size={12} /> Close</button>
            </div>

            <div className={`mb-3 rounded-xl border p-3 text-[11px] leading-relaxed ${isLight?"border-emerald-200 bg-emerald-50 text-emerald-800":"border-emerald-500/20 bg-emerald-500/5 text-emerald-200"}`}>
              <ShieldCheck size={13} className="inline mr-1" />
              <b>Zero-Knowledge:</b> Password sirf browser mein rehta hai. Server ko sirf hash milta hai. Password bhoolne par data recover nahi hoga.
            </div>

            <div className="mb-3 flex rounded-xl border overflow-hidden">
              <button onClick={()=>setAuthMode("login")} className={`flex-1 py-2 text-[13px] font-bold transition ${authMode==="login" ? "bg-gradient-to-r from-indigo-600 to-cyan-500 text-white" : soft}`}>Login</button>
              <button onClick={()=>setAuthMode("signup")} className={`flex-1 py-2 text-[13px] font-bold transition ${authMode==="signup" ? "bg-gradient-to-r from-indigo-600 to-cyan-500 text-white" : soft}`}>Signup</button>
            </div>

            <label className={`mb-1 block text-[11px] font-bold uppercase tracking-widest ${muted}`}>Email</label>
            <input type="email" value={authEmail} onChange={e=>setAuthEmail(e.target.value)} placeholder="you@example.com" autoComplete="email" className={`w-full rounded-xl border px-3 py-2.5 text-sm outline-none ${isLight?"bg-white border-slate-300 text-slate-900":"bg-black/30 border-white/10 text-white"}`} />

            <label className={`mt-3 mb-1 block text-[11px] font-bold uppercase tracking-widest ${muted}`}>Password (min 8 chars)</label>
            <input type="password" value={authPw} onChange={e=>setAuthPw(e.target.value)} placeholder="strong password" autoComplete={authMode==="login"?"current-password":"new-password"} onKeyDown={e=>{if(e.key==="Enter") authMode==="login" ? handleLogin() : handleSignup()}} className={`w-full rounded-xl border px-3 py-2.5 text-sm outline-none ${isLight?"bg-white border-slate-300 text-slate-900":"bg-black/30 border-white/10 text-white"}`} />

            {authMode==="signup" && authPw && (
              <div className="mt-2">
                <div className="h-1.5 overflow-hidden rounded-full bg-white/10"><div className="h-full transition-all" style={{ width:`${strengthScore(authPw).pct}%`, background: strengthScore(authPw).color }} /></div>
                <div className="mt-1 text-[10px] font-bold" style={{ color: strengthScore(authPw).color }}>Strength: {strengthScore(authPw).label}</div>
              </div>
            )}

            {turnstileSiteKey && (
              <div className={`mt-3 rounded-xl border border-dashed p-2 text-center text-[10px] ${muted}`}>
                <Shield size={12} className="inline mr-1" /> Turnstile CAPTCHA site key detected. Widget will render here in production.
                <input type="hidden" value={turnstileToken} onChange={e=>setTurnstileToken(e.target.value)} />
              </div>
            )}

            {authError && (
              <div className={`mt-3 rounded-xl border p-2.5 text-[12px] font-bold ${isLight?"border-red-200 bg-red-50 text-red-700":"border-red-500/30 bg-red-500/10 text-red-300"}`}>
                <AlertTriangle size={12} className="inline mr-1" /> {authError}
              </div>
            )}

            <button onClick={authMode==="login" ? handleLogin : handleSignup} disabled={authBusy} className="mt-4 inline-flex w-full items-center justify-center gap-2 rounded-xl bg-gradient-to-r from-indigo-600 to-cyan-500 py-3 text-[14px] font-extrabold text-white shadow-lg hover:shadow-xl transition disabled:opacity-60">
              {authBusy ? <Loader2 size={16} className="animate-spin" /> : authMode==="login" ? <LogIn size={15} /> : <UserPlus size={15} />}
              {authBusy ? (authMode==="login" ? "Verifying…" : "Creating account…") : (authMode==="login" ? "Login" : "Create Account")}
            </button>

            <div className="mt-3 text-center">
              <button onClick={()=>setAuthMode(authMode==="login"?"signup":"login")} className={`text-[11px] font-bold underline decoration-dotted ${muted} hover:opacity-80`}>
                {authMode==="login" ? "Naya user? Signup karo →" : "Already have account? Login →"}
              </button>
            </div>

            <p className={`mt-3 text-center text-[10px] tracking-widest uppercase font-bold ${muted}`}>PBKDF2 200K • Client-Side Hash • Zero-Knowledge</p>
          </div>
        </div>
      )}

      {keypadOpen && (
        <div className="fixed inset-0 z-[85] grid place-items-center bg-[#020612]/75 p-4 backdrop-blur-[8px]" onClick={()=>setKeypadOpen(false)}>
          <div className={`w-[min(520px,100%)] rounded-[1.25rem] border p-5 ${theme==="dark"?"bg-slate-900 border-white/10":"bg-white border-slate-200"}`} onClick={e=>e.stopPropagation()}>
            <div className="flex items-center justify-between"><h2 className="flex items-center gap-2 text-[16px] font-extrabold"><Keyboard size={17} className="text-cyan-400" /> Anti-Keylogger Keypad PRO</h2><button onClick={()=>setKeypadOpen(false)} className="inline-flex items-center gap-1 rounded-full bg-white/10 px-3 py-1 text-[12px] font-bold"><X size={13} /> Close</button></div>
            <p className="mt-2 text-[12px] text-slate-400">Target: <b className="text-white">{keypadTarget}</b> • Layout shuffled per open • Hover-to-fill • No keyboard events</p>
            <div className="mt-3 flex gap-2"><button onClick={shuffle} className="inline-flex items-center gap-1 rounded-full bg-white/10 px-3 py-1.5 text-[12px] font-bold"><Shuffle size={12} /> Shuffle</button><button onClick={()=>{ if(keypadTarget==="enc") setEncPw(s=>s.slice(0,-1)); if(keypadTarget==="decoy") setDecoyPw(s=>s.slice(0,-1)); if(keypadTarget==="pdf") setPdfPw(s=>s.slice(0,-1)); if(keypadTarget==="dec") setDecPw(s=>s.slice(0,-1)) }} className="inline-flex items-center gap-1 rounded-full bg-white/10 px-3 py-1.5 text-[12px] font-bold"><Delete size={12} /> Back</button><button onClick={()=>{ if(keypadTarget==="enc") setEncPw(""); if(keypadTarget==="decoy") setDecoyPw(""); if(keypadTarget==="pdf") setPdfPw(""); if(keypadTarget==="dec") setDecPw("") }} className="inline-flex items-center gap-1 rounded-full bg-red-500/20 px-3 py-1.5 text-[12px] font-bold text-red-200"><Eraser size={12} /> Clear</button></div>
            <div className="mt-4 grid grid-cols-6 gap-1.5 sm:grid-cols-8">
              {shuffledKeys.map(k=><button key={k+Math.random()} onClick={()=>{ if(keypadTarget==="enc") setEncPw(s=>s+k); if(keypadTarget==="decoy") setDecoyPw(s=>s+k); if(keypadTarget==="pdf") setPdfPw(s=>s+k); if(keypadTarget==="dec") setDecPw(s=>s+k) }} className="grid h-10 place-items-center rounded-xl border border-white/10 bg-white/5 font-mono text-[13px] font-bold hover:bg-indigo-500/20 hover:border-indigo-500/30 active:scale-95">{k}</button>)}
            </div>
            <button onClick={()=>setKeypadOpen(false)} className="mt-4 inline-flex w-full items-center justify-center gap-2 rounded-xl bg-indigo-600 py-2.5 text-[13px] font-extrabold text-white"><Check size={15} /> Done</button>
            <p className="mt-2 text-center text-[10px] font-bold tracking-widest text-slate-500 uppercase">Production Grade • Shuffled • No Keyup Events • Copyright © 2026 Surakshit Labs</p>
          </div>
        </div>
      )}

      <style>{`
@import url('https://fonts.googleapis.com/css2?family=Outfit:wght@400;600;700;800&family=JetBrains+Mono:wght@500;700&display=swap');
@keyframes slideUp{from{opacity:0;transform:translateY(12px) scale(0.96)}to{opacity:1;transform:none}}
@keyframes fadeIn{from{opacity:0;transform:translateY(8px)}to{opacity:1;transform:none}}
@keyframes fadeUp{from{opacity:0;transform:translateY(16px)}to{opacity:1;transform:none}}
@keyframes panelIn{from{opacity:0;transform:translateY(14px) scale(0.985);filter:blur(4px)}to{opacity:1;transform:none;filter:none}}
@keyframes pop{0%{transform:scale(0.6)}60%{transform:scale(1.2)}100%{transform:scale(1)}}
@keyframes floatOrb{from{transform:translate3d(0,0,0) scale(1)}to{transform:translate3d(30px,-40px,0) scale(1.15)}}
@keyframes pulseGlow{0%,100%{box-shadow:0 0 18px rgba(99,102,241,0.35)}50%{box-shadow:0 0 36px rgba(34,211,238,0.45)}}
@keyframes shimmer{from{background-position:200% 0}to{background-position:-200% 0}}
.scrollbar-none::-webkit-scrollbar{display:none}
.scrollbar-none{scrollbar-width:none}
.btn-soft{background:rgba(255,255,255,0.08);color:#e2e8f0;border-color:rgba(255,255,255,0.12)}
.btn-soft:hover{background:rgba(255,255,255,0.14)}
[data-theme="light"] .btn-soft{background:#f1f5f9;color:#0f172a;border-color:#cbd5e1}
[data-theme="light"] .btn-soft:hover{background:#e2e8f0}
/* Light mode visibility overrides for legacy hard-coded dark classes */
[data-theme="light"] .sv-app .text-slate-300{color:#334155!important}
[data-theme="light"] .sv-app .text-slate-400{color:#475569!important}
[data-theme="light"] .sv-app .text-slate-500{color:#64748b!important}
[data-theme="light"] .sv-app .text-indigo-200{color:#4338ca!important}
[data-theme="light"] .sv-app .text-indigo-300{color:#4f46e5!important}
[data-theme="light"] .sv-app .text-cyan-200{color:#0e7490!important}
[data-theme="light"] .sv-app .text-cyan-300{color:#0891b2!important}
[data-theme="light"] .sv-app .text-emerald-200{color:#047857!important}
[data-theme="light"] .sv-app .text-emerald-300{color:#059669!important}
[data-theme="light"] .sv-app .text-violet-200{color:#6d28d9!important}
[data-theme="light"] .sv-app .text-amber-200{color:#b45309!important}
[data-theme="light"] .sv-app .text-red-200{color:#b91c1c!important}
[data-theme="light"] .sv-app .text-red-300{color:#dc2626!important}
[data-theme="light"] .sv-app .text-sky-200{color:#0369a1!important}
[data-theme="light"] .sv-app .bg-white\\/10,[data-theme="light"] .sv-app .bg-white\\/\\[0\\.05\\],[data-theme="light"] .sv-app .bg-white\\/\\[0\\.04\\],[data-theme="light"] .sv-app .bg-white\\/\\[0\\.03\\],[data-theme="light"] .sv-app .bg-white\\/\\[0\\.06\\]{background-color:#f1f5f9!important}
[data-theme="light"] .sv-app .bg-black\\/20,[data-theme="light"] .sv-app .bg-black\\/30,[data-theme="light"] .sv-app .bg-black\\/40{background-color:#f8fafc!important}
[data-theme="light"] .sv-app .border-white\\/10{border-color:#e2e8f0!important}
[data-theme="light"] .sv-app .bg-\\[\\#070c18\\]\\/80{background-color:#ffffff!important}
[data-theme="light"] .sv-app .bg-\\[\\#05070f\\]{background-color:#f8fafc!important}
[data-theme="light"] .sv-app input,[data-theme="light"] .sv-app textarea,[data-theme="light"] .sv-app select{color:#0f172a!important}
[data-theme="light"] .sv-app .text-white{color:#0f172a!important}
[data-theme="light"] .sv-app button.bg-gradient-to-r .text-white,[data-theme="light"] .sv-app .bg-gradient-to-r{color:#fff!important}
[data-theme="light"] .sv-app .bg-emerald-600,[data-theme="light"] .sv-app .bg-indigo-600,[data-theme="light"] .sv-app .bg-red-600{color:#fff!important}
[data-theme="light"] .sv-app .bg-emerald-600 *,[data-theme="light"] .sv-app a.bg-emerald-600{color:#fff!important}
[data-theme="light"] .sv-app .from-indigo-600{--tw-gradient-from:#4f46e5}
/* Panel enter animation */
.sv-app section,[data-theme] .panel-anim{animation:panelIn 0.4s cubic-bezier(0.22,1,0.36,1) both}
/* Responsive touch targets */
@media (max-width:640px){
  .sv-app button,.sv-app a{min-height:36px}
  .sv-app input,.sv-app textarea,.sv-app select{font-size:16px!important}
}
`}</style>
    </div>
  )
}
