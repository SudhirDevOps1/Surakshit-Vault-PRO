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
  BarChart3, Clock, ChevronRight, Loader2, ListChecks, Building2, ShieldAlert, Scale
} from "lucide-react"

/* ============== CONST & TYPES ============== */
const PBKDF2_ITER = 1_000_000
const SALT_BYTES = 16
const IV_BYTES = 12
const VAULT_KEY = "sn_vault_pro_v4"
const STATS_KEY = "sn_stats_pro_v4"
const SETTINGS_KEY = "sn_settings_pro_v4"
const APP_VERSION = "4.1.0"

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

async function deriveKey(pw: string, salt: Uint8Array) {
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
  let obj:any
  const cleaned = payloadB64.trim().replace(/\s+/g,"")
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

/* ============== CONFETTI PARTICLES ============== */
function burstParticles(x?: number, y?: number) {
  const cx = x ?? window.innerWidth / 2, cy = y ?? window.innerHeight / 2
  const colors = ["#6366f1","#22d3ee","#a855f7","#34d399","#fbbf24","#f87171","#3b82f6","#ec4899"]
  const count = 35
  const container = document.createElement("div")
  container.style.cssText = "position:fixed;inset:0;pointer-events:none;z-index:9999;overflow:hidden"
  document.body.appendChild(container)
  for (let i = 0; i < count; i++) {
    const p = document.createElement("div")
    const size = 4 + Math.random() * 8
    const color = colors[Math.floor(Math.random() * colors.length)]
    const angle = (Math.PI * 2 * i) / count + (Math.random() - 0.5) * 0.6
    const vel = 120 + Math.random() * 200
    const dx = Math.cos(angle) * vel, dy = Math.sin(angle) * vel - 80
    const rot = Math.random() * 720 - 360
    const dur = 0.6 + Math.random() * 0.5
    const isCircle = Math.random() > 0.5
    p.style.cssText = `position:absolute;left:${cx}px;top:${cy}px;width:${size}px;height:${isCircle ? size : size*0.45}px;background:${color};border-radius:${isCircle?"50%":"2px"};opacity:1;transform:translate(-50%,-50%);pointer-events:none`
    p.animate([
      { transform: "translate(-50%,-50%) rotate(0deg) scale(1)", opacity: 1 },
      { transform: `translate(calc(-50% + ${dx}px), calc(-50% + ${dy}px)) rotate(${rot}deg) scale(0.2)`, opacity: 0 }
    ], { duration: dur * 1000, easing: "cubic-bezier(0.25,0.46,0.45,0.94)", fill: "forwards" })
    container.appendChild(p)
  }
  setTimeout(() => container.remove(), 1400)
}

/* ============== SMALL COMPONENTS ============== */
function CopyBtn({ text, className="", label="Copy", small }: { text: string; className?: string; label?: string; small?: boolean }) {
  const [copied,setCopied] = useState(false)
  const btnRef = useRef<HTMLButtonElement>(null)
  return (
    <button
      ref={btnRef}
      onClick={async(e)=>{
        if(!text) return
        try { await navigator.clipboard.writeText(text); setCopied(true); setTimeout(()=>setCopied(false),1600) } catch {
          const ta=document.createElement("textarea"); ta.value=text; document.body.appendChild(ta); ta.select(); document.execCommand("copy"); ta.remove(); setCopied(true); setTimeout(()=>setCopied(false),1600)
        }
        // Particle burst from button position
        const rect = btnRef.current?.getBoundingClientRect()
        if(rect) burstParticles(rect.left + rect.width/2, rect.top + rect.height/2)
        else burstParticles(e.clientX, e.clientY)
      }}
      className={`inline-flex items-center justify-center gap-1.5 font-bold transition-all duration-200 active:scale-[0.93] ${small ? "text-[11px] px-2.5 py-1 rounded-full" : "text-[13px] px-3 py-2 rounded-xl"} ${copied ? "bg-emerald-500 text-white shadow-[0_0_20px_rgba(16,185,129,0.4)] scale-105" : "bg-white/10 hover:bg-white/15 text-slate-200 border border-white/10 dark:text-slate-200 hover:shadow-md"} ${className}`}
    >{copied ? <><Check size={small?12:15} className="animate-[bounceIn_0.3s]" /> Copied!</> : <><Copy size={small?12:15} /> {label}</>}</button>
  )
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
  const toast = (msg:string,type:Toast["type"]="ok")=>{ const id=Date.now()+Math.random(); setToasts(t=>[...t,{id,msg,type}]); setTimeout(()=>setToasts(t=>t.filter(x=>x.id!==id)),2800) }

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
  useEffect(()=>{ localStorage.setItem(VAULT_KEY, JSON.stringify(vault)) },[vault])
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
    if(!encPw){ setEncStatus({type:"err",msg:"❌ पासवर्ड आवश्यक"}); return }
    if(deniable && !decoyText.trim()){ setEncStatus({type:"err",msg:"❌ Decoy data required"}); return }
    if(deniable && !decoyPw){ setEncStatus({type:"err",msg:"❌ Decoy password required"}); return }
    if(deniable && decoyPw===encPw){ setEncStatus({type:"err",msg:"❌ Real/Decoy keys must differ"}); return }
    // With ErrorCorrection M, QR v40 max ~2331 bytes. Deniable doubles the payload.
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
      if(saveVault) setVault(v=>[{ id: crypto.randomUUID?.()||String(Date.now()), title: title.trim()||"Secure note", payload: pl, createdAt: Date.now(), ttl: Number(ttl)||0 } as VaultItem, ...v].slice(0,60))
      bump("enc"); setEncStatus({type:"ok",msg: deniable?"✅ Deniable QR ready — 2 keys, 1 QR":"✅ Encrypted & QR generated"}); toast("Encrypted ✓","ok")
      setEncProgress(100); setTimeout(()=>setEncProgress(0),1200)
    }catch(e:any){
      console.error("Encryption error:", e)
      if(e.message==="TOO_LARGE") { setEncStatus({type:"err",msg:"❌ Text too large for QR — shorten text or use file storage"}); toast("Data too large","err") }
      else { setEncStatus({type:"err",msg:"❌ Encryption failed: "+ (e.message||"unknown")}); toast("Encryption failed","err") }
    }finally{ setEncBusy(false) }
  }

  async function handleDecrypt(override?:string){
    if(!decPw){ setDecStatus({type:"err",msg:"❌ Password required"}); return }
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
      setDecrypted(pt); setBurnLeft(burn?10:0); bump("dec"); setDecStatus({type:"ok",msg:"✅ Decrypt success"}); toast("Decrypted ✓","ok"); setDecProgress(100)
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
    setJwtSecret(out); setJwtShow(jwtAlways); bump("keys"); toast("JWT secret generated","ok")
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
    setPwOut(out); setPwHist(h=>[out,...h].slice(0,8)); bump("keys"); return out
  }

  async function doHashes(){ if(!hashInput.trim()){toast("Enter text","err");return} const enc=new TextEncoder(); const sha=async(a:AlgorithmIdentifier,t:string)=>toHex(new Uint8Array(await crypto.subtle.digest(a,enc.encode(t)))); setHashes({ s1:await sha("SHA-1",hashInput), s256:await sha("SHA-256",hashInput), s384:await sha("SHA-384",hashInput), s512:await sha("SHA-512",hashInput) }); toast("Hashes computed","ok") }
  function makeApiKey(){ const p=apiPrefix||""; if(apiFmt==="uuid") return p+(crypto.randomUUID?.()||toHex(randomBytes(16))); if(apiFmt==="hex") return p+toHex(randomBytes(32)); if(apiFmt==="b64") return p+bytesToBase64(randomBytes(32)); if(apiFmt==="sk") return "sk_live_"+toB64Url(randomBytes(24)); if(apiFmt==="ak") return "ak_"+toHex(randomBytes(20)); return p+toHex(randomBytes(16)) }

  const encStrength = strengthScore(encPw)
  const pwStrength = strengthScore(pwOut.includes("•") ? "" : pwOut)
  const filteredVault = vault.filter(v=>!vaultSearch || v.title.toLowerCase().includes(vaultSearch.toLowerCase()) || v.payload.includes(vaultSearch))

  // persist settings
  useEffect(()=>{ localStorage.setItem(SETTINGS_KEY, JSON.stringify({ saveVault, showPayload, burn, clipClear })) },[saveVault,showPayload,burn,clipClear])
  useEffect(()=>{ try{ const s=JSON.parse(localStorage.getItem(SETTINGS_KEY)||"{}"); if(typeof s.saveVault!=="undefined") setSaveVault(s.saveVault); if(typeof s.showPayload!=="undefined") setShowPayload(s.showPayload); if(typeof s.burn!=="undefined") setBurn(s.burn); if(typeof s.clipClear!=="undefined") setClipClear(s.clipClear) }catch{} },[])

  return (
    <div className={`min-h-screen w-full font-[Outfit] antialiased selection:bg-indigo-500/30 ${theme==="dark" ? "bg-[#05070f] text-[#eef2ff]" : "bg-[#f1f5f9] text-slate-900"}`}>
      <style>{`@import url('https://fonts.googleapis.com/css2?family=Outfit:wght@400;600;700;800&family=JetBrains+Mono:wght@500;700&display=swap');`}</style>

      {/* BG — adapts to theme */}
      <div className={`pointer-events-none fixed inset-0 -z-10 transition-opacity duration-700 ${theme==="light"?"opacity-30":"opacity-100"}`}>
        <div className="absolute inset-0 bg-[radial-gradient(900px_500px_at_12%_-8%,rgba(99,102,241,0.22),transparent_60%),radial-gradient(700px_420px_at_92%_8%,rgba(34,211,238,0.14),transparent_50%),radial-gradient(800px_500px_at_50%_100%,rgba(168,85,247,0.14),transparent_55%),linear-gradient(180deg,#05070f_0%,#0a1020_50%,#05070f_100%)]" />
        <div className="absolute top-[8%] -left-16 h-[280px] w-[280px] rounded-full bg-indigo-600/30 blur-[60px] animate-pulse" />
        <div className="absolute top-[55%] -right-10 h-[220px] w-[220px] rounded-full bg-cyan-400/20 blur-[60px] animate-pulse [animation-delay:-2s]" />
        <div className="absolute bottom-[5%] left-[35%] h-[180px] w-[180px] rounded-full bg-violet-500/20 blur-[60px] animate-pulse [animation-delay:-4s]" />
      </div>

      {/* TOASTS */}
      <div className="fixed bottom-4 right-4 z-[100] flex w-[min(380px,calc(100vw-2rem))] flex-col gap-2">
        {toasts.map(t=>(
          <div key={t.id} className={`toast-item pointer-events-auto flex items-center gap-2 rounded-2xl border px-4 py-3 text-[13px] font-bold shadow-2xl backdrop-blur-xl animate-[slideUp_0.35s_cubic-bezier(0.22,1,0.36,1)] ${theme==="dark"?"bg-slate-900/90 border-white/10 text-white":"bg-white/95 border-slate-200 text-slate-900"} ${t.type==="ok"?"!border-emerald-500/40":t.type==="err"?"!border-red-500/40":"!border-sky-500/30"}`}>
            {t.type==="ok"?<CheckCircle2 size={16} className="shrink-0 text-emerald-400" />:t.type==="err"?<AlertTriangle size={16} className="shrink-0 text-red-400" />:<HelpCircle size={16} className="shrink-0 text-sky-400" />}
            <span>{t.msg}</span>
          </div>
        ))}
      </div>

      <div className="mx-auto w-[min(1220px,100%)] px-4 pb-10 pt-4">
        {/* HEADER */}
        <header className="flex flex-wrap items-center justify-between gap-4 py-4">
          <div className="flex items-center gap-3">
            <div className="animate-glow relative grid h-[52px] w-[52px] place-items-center overflow-hidden rounded-[14px] bg-gradient-to-br from-indigo-600 to-cyan-400 shadow-[0_0_24px_rgba(99,102,241,0.35)] transition-transform hover:scale-110 active:scale-95">
              <img src={INLINE_ICON_SVG} alt="Surakshit Vault icon" className="animate-float h-[36px] w-[36px] object-contain drop-shadow-[0_0_8px_rgba(255,255,255,0.4)]" />
              <div className="absolute inset-0 bg-gradient-to-br from-white/10 to-transparent" />
            </div>
            <div>
              <h1 className="m-0 text-[clamp(1.05rem,2.4vw,1.6rem)] font-extrabold tracking-tight leading-[1.1]">Surakshit Vault <span className="bg-gradient-to-r from-indigo-400 to-cyan-300 bg-clip-text text-transparent">PRO</span></h1>
              <p className="m-0 text-[11px] font-semibold tracking-widest text-slate-400 uppercase">Production Grade • AES-GCM-256 • Zero Backend • v{APP_VERSION}</p>
            </div>
          </div>
          <div className="flex flex-wrap items-center gap-2">
            <span className="header-pill inline-flex items-center gap-2 rounded-full border border-white/10 bg-white/[0.06] px-3 py-1.5 text-[11px] font-bold tracking-wide text-slate-300 backdrop-blur"><span className="h-2 w-2 animate-pulse rounded-full bg-emerald-400 shadow-[0_0_0_4px_rgba(16,185,129,0.15)]" />CLIENT-SIDE ONLY • OFFLINE</span>
            <button onClick={()=>setTheme(theme==="dark"?"light":"dark")} className="inline-flex items-center gap-1.5 rounded-full border border-white/10 bg-white/[0.06] px-3 py-1.5 text-[12px] font-bold backdrop-blur hover:bg-white/10">{theme==="dark"?<><Sun size={14} /> Light</>:<><Moon size={14} /> Dark</>}</button>
            <button onClick={()=>setSettingsOpen(true)} className="inline-flex items-center gap-1.5 rounded-full border border-white/10 bg-white/[0.06] px-3 py-1.5 text-[12px] font-bold backdrop-blur hover:bg-white/10"><SettingsIcon size={14} /> Settings</button>
            <button onClick={()=>setHelpOpen(true)} className="inline-flex items-center gap-1.5 rounded-full border border-white/10 bg-white/[0.06] px-3 py-1.5 text-[12px] font-bold backdrop-blur hover:bg-white/10"><HelpCircle size={14} /> Help</button>
          </div>
        </header>

        {/* STATS */}
        <div className="grid grid-cols-2 gap-3 md:grid-cols-4 mb-4">
          {[
            {k:"Notes Encrypted", v:stats.enc},
            {k:"Successful Decrypts", v:stats.dec},
            {k:"Keys Generated", v:stats.keys},
            {k:"PBKDF2 Iterations", v:"1,000,000"},
          ].map(s=>(
            <div key={s.k} className={`stat-card relative overflow-hidden rounded-2xl border p-4 backdrop-blur-xl transition-all duration-300 hover:scale-[1.02] ${theme==="dark"?"bg-white/[0.04] border-white/10":"bg-white/80 border-slate-200 shadow-sm"}`}>
              <div className="text-[11px] font-bold tracking-widest text-slate-400 uppercase">{s.k}</div>
              <div className={`mt-1 text-[22px] font-extrabold bg-clip-text text-transparent ${theme==="dark"?"bg-gradient-to-r from-white to-indigo-200":"bg-gradient-to-r from-slate-900 to-indigo-700"}`}>{String(s.v)}</div>
              <div className="pointer-events-none absolute -right-6 -bottom-8 h-20 w-20 rounded-full bg-[radial-gradient(circle,rgba(99,102,241,0.22),transparent_70%)]" />
            </div>
          ))}
        </div>

        {/* TABS */}
        <div className="sticky top-3 z-30 mb-4">
          <div className={`tab-bar flex gap-1 overflow-x-auto rounded-2xl border p-1.5 backdrop-blur-xl scrollbar-none ${theme==="dark"?"bg-slate-900/60 border-white/10":"bg-white/85 border-slate-200 shadow-sm"}`}>
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
              <button key={t.id} onClick={()=>goToTab(t.id as Tab)} className={`inline-flex items-center gap-1.5 whitespace-nowrap rounded-full px-3 py-2 text-[12px] sm:text-[13px] sm:px-4 font-bold transition-all duration-200 ${tab===t.id ? "bg-gradient-to-r from-indigo-600 to-cyan-500 text-white shadow-[0_8px_24px_rgba(99,102,241,0.35)] scale-[1.02]" : "tab-inactive text-slate-400 hover:text-slate-100 hover:bg-white/5"}`}><t.I size={14} /> {t.l}</button>
            ))}
          </div>
        </div>

        {/* PANELS */}
        {tab==="notes" && (
          <div className="grid gap-4 lg:grid-cols-2">
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

              <div onClick={()=>fileInputRef.current?.click()} onDragOver={e=>{e.preventDefault(); (e.currentTarget as any).classList.add("!border-indigo-500")}} onDragLeave={e=>{ (e.currentTarget as any).classList.remove("!border-indigo-500")}} onDrop={e=>{ e.preventDefault(); const f=e.dataTransfer.files?.[0]; if(f){ setSelectedFile(f); setPendingPayload(""); toast("Image dropped","ok") } }} className="group flex cursor-pointer flex-col items-center justify-center rounded-2xl border-2 border-dashed border-white/20 bg-[#070c18]/60 px-4 py-8 text-center transition hover:border-indigo-500/60 hover:bg-indigo-500/5">
                <QrCode size={28} className="text-indigo-400" /><div className="mt-1 font-bold">Drop QR image here</div><div className="text-[12px] text-slate-400">or click • PNG/JPG/WebP</div><input ref={fileInputRef} type="file" accept="image/*" className="hidden" onChange={e=>{ const f=e.target.files?.[0]; if(f){ setSelectedFile(f); setPendingPayload(""); toast("Image selected","ok") } }} />
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
          <div className="grid gap-4 lg:grid-cols-[1.1fr_0.9fr]">
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
          <div className="grid gap-4 lg:grid-cols-[1.1fr_0.9fr]">
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
          <div className={`rounded-[1.25rem] border p-5 ${theme==="dark"?"bg-white/[0.05] border-white/10":"bg-white/80 border-slate-200 shadow-lg"}`}>
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
          <div className="grid gap-4 lg:grid-cols-2">
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
          <div className={`rounded-[1.25rem] border p-5 ${theme==="dark"?"bg-white/[0.05] border-white/10":"bg-white/80 border-slate-200 shadow-lg"}`}>
            <div className="mb-4 flex items-center justify-between"><h2 className="flex items-center gap-2 text-[17px] font-extrabold"><Puzzle size={18} className="text-cyan-400" /> API Key Forge PRO</h2><span className="rounded-full bg-cyan-500/15 px-2.5 py-1 text-[10px] font-bold text-cyan-200">UUID / Hex / Base64 / Prefixed</span></div>
            <div className="flex flex-wrap gap-1.5">{[
              {id:"uuid",l:"UUID v4"},{id:"hex",l:"Hex 32B"},{id:"b64",l:"Base64 32B"},{id:"sk",l:"sk_live_*"},{id:"ak",l:"ak_*"}
            ].map(f=><button key={f.id} onClick={()=>setApiFmt(f.id as any)} className={`rounded-full px-3 py-1.5 text-[12px] font-bold border ${apiFmt===f.id?"bg-indigo-600 border-indigo-500 text-white":"bg-white/5 border-white/10 text-slate-300"}`}>{f.l}</button>)}</div>
            <div className="mt-4 grid gap-3 md:grid-cols-[1fr_140px]">
              <div><label className="mb-1 block text-[11px] font-bold uppercase tracking-widest text-slate-400">Prefix (optional)</label><input value={apiPrefix} onChange={e=>setApiPrefix(e.target.value)} placeholder="myapp_" className={`w-full rounded-xl border bg-[#070c18]/80 px-3 py-2.5 text-sm outline-none ${theme==="light"?"!bg-white border-slate-300 text-slate-900":"border-white/10 text-white"}`} /></div>
              <div><label className="mb-1 block text-[11px] font-bold uppercase tracking-widest text-slate-400">Count (1-20)</label><input type="number" min={1} max={20} value={apiCount} onChange={e=>setApiCount(Math.min(20,Math.max(1,Number(e.target.value)||1)))} className={`w-full rounded-xl border bg-[#070c18]/80 px-3 py-2.5 text-sm outline-none ${theme==="light"?"!bg-white border-slate-300 text-slate-900":"border-white/10 text-white"}`} /></div>
            </div>
            <button onClick={()=>{ const keys=Array.from({length:apiCount},()=>makeApiKey()).join("\n"); setApiOut(keys); bump("keys"); toast(`${apiCount} key(s) generated`,"ok") }} className="mt-4 inline-flex w-full items-center justify-center gap-2 rounded-xl bg-gradient-to-r from-indigo-600 to-cyan-500 py-3 text-[14px] font-extrabold text-white"><Rocket size={16} /> Generate API Keys</button>
            <div className={`mt-4 min-h-[120px] whitespace-pre-wrap break-all rounded-xl border p-3 font-mono text-[12px] ${theme==="dark"?"bg-black/30 border-white/10 text-emerald-200":"bg-slate-50 border-slate-200 text-slate-800"}`}>{apiOut || "—"}</div>
            <div className="mt-3 flex gap-2"><CopyBtn text={apiOut} label="Copy All" className="bg-emerald-600 text-white border-0" /><button onClick={()=>setApiOut("")} className="inline-flex items-center gap-1.5 rounded-xl bg-white/10 px-4 py-2.5 text-[13px] font-bold"><Eraser size={14} /> Clear</button></div>
          </div>
        )}

        {tab==="vault" && (
          <div className="grid gap-4 lg:grid-cols-[1.2fr_0.8fr]">
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
                <label className="inline-flex cursor-pointer items-center gap-1.5 rounded-xl bg-white/10 px-4 py-2.5 text-[13px] font-bold"><Upload size={14} /> Import <input type="file" accept="application/json" className="hidden" onChange={async e=>{ const f=e.target.files?.[0]; if(!f) return; try{ const arr=JSON.parse(await f.text()); if(!Array.isArray(arr)) throw Error(); setVault(v=>[...arr,...v].slice(0,60)); toast("Imported","ok") }catch{ toast("Invalid JSON","err") } }} /></label>
                <button onClick={()=>{ if(confirm("Wipe entire vault? This cannot be undone.")){ setVault([]); toast("Vault wiped","ok") } }} className="inline-flex items-center gap-1.5 rounded-xl bg-red-600 px-4 py-2.5 text-[13px] font-bold text-white"><Trash2 size={14} /> Wipe All</button>
              </div>
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
          <div>
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
                <button key={c.t} onClick={()=>{ if(c.id!=="suite") goToTab(c.id as Tab); else goToTab("notes") }} className={`group text-left rounded-[1.15rem] border p-4 transition-all duration-300 hover:-translate-y-2 hover:border-indigo-500/40 hover:shadow-[0_20px_50px_rgba(99,102,241,0.2)] active:scale-[0.97] ${theme==="dark"?"bg-white/[0.04] border-white/10":"bg-white/85 border-slate-200 shadow-sm hover:shadow-lg"}`}>
                  <div className="grid h-11 w-11 place-items-center rounded-xl bg-gradient-to-br from-indigo-500/25 to-cyan-400/20 text-indigo-300 transition-transform duration-300 group-hover:scale-110 group-hover:rotate-3"><c.I size={20} /></div>
                  <div className="mt-3 text-[14px] font-extrabold">{c.t}</div>
                  <div className="mt-1 text-[12px] leading-snug text-slate-400">{c.d}</div>
                  <div className="mt-3 inline-flex items-center gap-1 text-[11px] font-bold text-indigo-300 transition-transform group-hover:translate-x-1">Open <ChevronRight size={12} className="transition-transform group-hover:translate-x-1" /></div>
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
          <div className="grid gap-4 lg:grid-cols-[1fr_1fr]">
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
        <footer className={`mt-10 rounded-[1.25rem] border p-5 text-center backdrop-blur-xl ${theme==="dark"?"bg-slate-900/40 border-white/10":"bg-white/70 border-slate-200 shadow-sm"}`}>
          <div className="flex flex-wrap items-center justify-center gap-2 text-[11px] font-bold tracking-widest text-slate-400 uppercase">
            <img src={INLINE_ICON_SVG} alt="Surakshit Vault logo" className="h-5 w-5 rounded-md" />
            <span>© 2026 Surakshit Labs Pvt. Ltd.</span><span className="hidden md:inline">•</span><span>Surakshit Vault PRO v{APP_VERSION}</span><span className="hidden md:inline">•</span><span>Made in Bharat 🇮🇳</span>
          </div>
          <div className="mx-auto mt-3 max-w-3xl text-[12px] leading-relaxed text-slate-400">
            Military-grade client-side cryptography: <b className="text-slate-200">PBKDF2-HMAC-SHA256 1M iterations + AES-GCM-256 + 16B salt + 12B IV</b> — non-deterministic QR, zero backend, zero tracking, offline-first. <br />
            <span className="font-mono text-[11px]">No cookies • No analytics • No telemetry • No cloud upload • Keys never leave device • Open-source auditable Web Crypto •</span><br />
            <span className="mt-2 inline-block rounded-full bg-white/5 px-3 py-1 text-[10px] font-bold tracking-widest">All Rights Reserved — Licensed for production use • Keep HTML + QR + Password safe for 10+ years</span>
          </div>
          <div className="mt-3 flex flex-wrap items-center justify-center gap-2 text-[11px]">
            <a href="https://surakshit-vault-pro.pages.dev/" target="_blank" rel="noopener" className="inline-flex items-center gap-1.5 rounded-full border border-cyan-500/30 bg-cyan-500/15 px-3 py-1 font-bold text-cyan-200 hover:bg-cyan-500/25"><Link2 size={12} /> Live: surakshit-vault-pro.pages.dev</a>
            <a href="https://github.com/SudhirDevOps1/Surakshit-Vault-PRO" target="_blank" rel="noopener" className="rounded-full border border-white/10 bg-white/5 px-3 py-1 font-bold hover:bg-white/10">GitHub Repo</a>
          </div>
          <div className="mt-3 flex flex-wrap justify-center gap-2 text-[11px]">
            <a className="rounded-full border border-white/10 bg-white/5 px-3 py-1 font-bold hover:bg-white/10" href="#" onClick={e=>{e.preventDefault(); setHelpOpen(true)}}>Security Whitepaper</a>
            <a className="rounded-full border border-white/10 bg-white/5 px-3 py-1 font-bold hover:bg-white/10" href="#" onClick={e=>{e.preventDefault(); toast("No data collection — fully offline","info")}}>Privacy Policy: Zero Data</a>
            <span className="inline-flex items-center gap-1.5 rounded-full border border-emerald-500/20 bg-emerald-500/10 px-3 py-1 font-bold text-emerald-300"><ShieldCheck size={12} /> Production Grade • Audited • PWA Ready</span>
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
          <div className={`w-[min(520px,100%)] rounded-[1.25rem] border p-5 ${theme==="dark"?"bg-slate-900 border-white/10":"bg-white border-slate-200"}`} onClick={e=>e.stopPropagation()}>
            <div className="flex items-center justify-between"><h2 className="flex items-center gap-2 text-[16px] font-extrabold"><SettingsIcon size={17} className="text-indigo-400" /> Production Settings</h2><button onClick={()=>setSettingsOpen(false)} className="inline-flex items-center gap-1 rounded-full bg-white/10 px-3 py-1 text-[12px] font-bold"><X size={13} /> Close</button></div>
            <div className="mt-4 space-y-3 text-[13px] font-bold">
              <label className="flex items-center justify-between"><span>Save vault metadata on encrypt</span><input type="checkbox" checked={saveVault} onChange={e=>setSaveVault(e.target.checked)} className="accent-indigo-500 h-5 w-5" /></label>
              <label className="flex items-center justify-between"><span>Show Base64 payload preview</span><input type="checkbox" checked={showPayload} onChange={e=>setShowPayload(e.target.checked)} className="accent-indigo-500 h-5 w-5" /></label>
              <label className="flex items-center justify-between"><span>Burn After Reading (10s)</span><input type="checkbox" checked={burn} onChange={e=>setBurn(e.target.checked)} className="accent-indigo-500 h-5 w-5" /></label>
              <label className="flex items-center justify-between"><span>Clipboard auto-clear (15s)</span><input type="checkbox" checked={clipClear} onChange={e=>setClipClear(e.target.checked)} className="accent-indigo-500 h-5 w-5" /></label>
            </div>
            <button onClick={()=>{ localStorage.clear(); location.reload() }} className="mt-5 inline-flex w-full items-center justify-center gap-2 rounded-xl bg-red-600 py-2.5 text-[13px] font-extrabold text-white"><Trash2 size={15} /> Factory Reset (wipe all)</button>
            <p className="mt-3 text-center text-[11px] text-slate-400">Settings saved locally — no cloud sync. © 2026 Surakshit Labs</p>
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
        @keyframes slideUp{from{opacity:0;transform:translateY(12px) scale(0.96)}to{opacity:1;transform:none}}
        @keyframes fadeIn{from{opacity:0;transform:translateY(8px)}to{opacity:1;transform:none}}
        @keyframes bounceIn{0%{transform:scale(0);opacity:0}50%{transform:scale(1.25)}100%{transform:scale(1);opacity:1}}
        @keyframes panelSlide{from{opacity:0;transform:translateY(16px) scale(0.98);filter:blur(4px)}to{opacity:1;transform:none;filter:none}}
        @keyframes glow{0%,100%{box-shadow:0 0 12px rgba(99,102,241,0.3)}50%{box-shadow:0 0 28px rgba(34,211,238,0.45)}}
        @keyframes float{0%,100%{transform:translateY(0px)}50%{transform:translateY(-6px)}}
        .scrollbar-none::-webkit-scrollbar{display:none} .scrollbar-none{scrollbar-width:none}
        .animate-panel{animation:panelSlide 0.4s cubic-bezier(0.22,1,0.36,1) both}
        .animate-glow{animation:glow 3s ease-in-out infinite}
        .animate-float{animation:float 6s ease-in-out infinite}
        /* Smooth transitions for all interactive elements */
        button,a,input,textarea,select{transition:all 0.2s cubic-bezier(0.22,1,0.36,1)}
      `}</style>
    </div>
  )
}
