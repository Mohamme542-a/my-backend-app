// Qarfash API v2.1 — Backend (admin open, user signed)
const express = require('express');
const cors = require('cors');
const compression = require('compression');
const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const fetch = require('node-fetch');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;

// ===== ENV =====
const JWT_SECRET            = process.env.JWT_SECRET  || crypto.randomBytes(32).toString('hex');
const APP_INTEGRITY_HASH    = (process.env.APP_INTEGRITY_HASH || '2ad9fc388b30f1314d07654cae91106981bcff7aa61448264e924666e47487bb').toLowerCase();
const FIREBASE_DB_URL       = (process.env.FIREBASE_DB_URL || '').replace(/\/$/, '');
const FIREBASE_DB_SECRET    = process.env.FIREBASE_DB_SECRET || '';
const CLOUDINARY_CLOUD_NAME = process.env.CLOUDINARY_CLOUD_NAME || 'dbcqz0yae';
const CLOUDINARY_PRESET     = process.env.CLOUDINARY_UPLOAD_PRESET || 'anasheed_unsigned';
const RATE_LIMIT_IP         = parseInt(process.env.RATE_LIMIT_IP || '120', 10);
const RATE_LIMIT_DEVICE     = parseInt(process.env.RATE_LIMIT_DEVICE || '240', 10);
const SELF_URL              = process.env.SELF_URL || '';

// ===== State =====
const usedNonces = new Map();
const ipHits     = new Map();
const deviceHits = new Map();
const tempBlock  = new Map();
const refreshTokens = new Map();

setInterval(() => {
  const now = Date.now();
  for (const [k, exp] of usedNonces) if (exp < now) usedNonces.delete(k);
  for (const [k, until] of tempBlock) if (until < now) tempBlock.delete(k);
  for (const [k, v] of refreshTokens) if (v.expiresAt < now) refreshTokens.delete(k);
  for (const m of [ipHits, deviceHits]) {
    for (const [k, arr] of m) {
      const f = arr.filter(t => now - t < 60_000);
      if (f.length) m.set(k, f); else m.delete(k);
    }
  }
}, 30_000);

if (SELF_URL) setInterval(() => { fetch(`${SELF_URL}/health`).catch(()=>{}); }, 10*60*1000);

// ===== Middleware =====
app.use(compression());
app.use(express.json({ limit: '512kb' }));
app.use(cors({ origin: true, credentials: false }));
app.options('*', cors());
app.use((_req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('Referrer-Policy', 'no-referrer');
  next();
});

// ===== Helpers =====
function getIp(req){return (req.headers['x-forwarded-for']||req.socket.remoteAddress||'').split(',')[0].trim();}
function sha256(s){return crypto.createHash('sha256').update(s).digest('hex');}
function safeEq(a,b){try{const A=Buffer.from(String(a)),B=Buffer.from(String(b));return A.length===B.length&&crypto.timingSafeEqual(A,B);}catch{return false;}}
function deny(res,c=403){return res.status(c).json({error:'FORBIDDEN'});}

function rateLimit(req,res,next){
  const ip=getIp(req); const dev=req.headers['x-device-id']||ip; const now=Date.now();
  if ((tempBlock.get(`ip:${ip}`)||0)>now) return deny(res,429);
  const ipArr=(ipHits.get(ip)||[]).filter(t=>now-t<60_000); ipArr.push(now); ipHits.set(ip,ipArr);
  if (ipArr.length>RATE_LIMIT_IP){tempBlock.set(`ip:${ip}`,now+5*60*1000);return deny(res,429);}
  const dArr=(deviceHits.get(dev)||[]).filter(t=>now-t<60_000); dArr.push(now); deviceHits.set(dev,dArr);
  if (dArr.length>RATE_LIMIT_DEVICE){tempBlock.set(`dev:${dev}`,now+5*60*1000);return deny(res,429);}
  next();
}

function verifyAccess(req,res,next){
  try{
    const m=(req.headers.authorization||'').match(/^Bearer\s+(.+)$/i);
    if(!m) return deny(res,401);
    const p=jwt.verify(m[1],JWT_SECRET);
    if(p.typ!=='access') return deny(res,401);
    req.session=p; req.accessToken=m[1]; next();
  }catch{return deny(res,401);}
}

async function verifySignature(req,res,next){
  try{
    const ts=req.headers['x-timestamp'], nonce=req.headers['x-nonce'],
          dev=req.headers['x-device-id'], sig=req.headers['x-signature'];
    if(!ts||!nonce||!dev||!sig) return deny(res,401);
    if (Math.abs(Date.now()-parseInt(ts,10))>30_000) return deny(res,401);
    if (usedNonces.has(nonce)) return deny(res,401);
    usedNonces.set(nonce,Date.now()+60_000);
    if (req.session && req.session.dev!==dev) return deny(res,401);
    const bodyStr=req.method==='GET'?'':JSON.stringify(req.body||{});
    const baseStr=`${req.method}|${req.path}|${ts}|${nonce}|${dev}|${sha256(bodyStr)}`;
    const expected=crypto.createHmac('sha256',req.accessToken).update(baseStr).digest('hex');
    if(!safeEq(expected,sig)) return deny(res,401);
    next();
  }catch{return deny(res,401);}
}

// ===== Firebase =====
function fbUrl(p){const a=FIREBASE_DB_SECRET?`?auth=${encodeURIComponent(FIREBASE_DB_SECRET)}`:'';return `${FIREBASE_DB_URL}/${p}.json${a}`;}
async function fbGet(p){const r=await fetch(fbUrl(p));if(!r.ok)throw new Error('fb get');return r.json();}
async function fbPost(p,b){const r=await fetch(fbUrl(p),{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify(b)});if(!r.ok)throw new Error('fb post');return r.json();}
async function fbPut(p,b){const r=await fetch(fbUrl(p),{method:'PUT',headers:{'content-type':'application/json'},body:JSON.stringify(b)});if(!r.ok)throw new Error('fb put');return r.json();}
async function fbPatch(p,b){const r=await fetch(fbUrl(p),{method:'PATCH',headers:{'content-type':'application/json'},body:JSON.stringify(b)});if(!r.ok)throw new Error('fb patch');return r.json();}
async function fbDelete(p){const r=await fetch(fbUrl(p),{method:'DELETE'});if(!r.ok)throw new Error('fb del');return true;}

// ===== Public =====
app.get('/health',(_q,r)=>r.json({ok:true,t:Date.now()}));
app.get('/',(_q,r)=>r.json({ok:true,name:'qarfash-api',v:'2.1'}));

// Cloudinary public config (for browser unsigned upload)
app.get('/api/cloudinary/config', (_q,r) => r.json({
  cloudName: CLOUDINARY_CLOUD_NAME, uploadPreset: CLOUDINARY_PRESET
}));

// Handshake for user app
app.post('/auth/handshake', rateLimit, (req,res) => {
  try{
    const { deviceId, appIntegrity } = req.body||{};
    if (!deviceId || typeof deviceId!=='string' || deviceId.length<8) return deny(res,400);
    if (APP_INTEGRITY_HASH){
      const expected = sha256(APP_INTEGRITY_HASH + deviceId);
      if (!safeEq(expected, String(appIntegrity||''))) return deny(res,401);
    }
    const access = jwt.sign({typ:'access',dev:deviceId,role:'user'}, JWT_SECRET, {expiresIn:'15m'});
    const jti = crypto.randomUUID();
    const refresh = jwt.sign({typ:'refresh',dev:deviceId,jti}, JWT_SECRET, {expiresIn:'30d'});
    refreshTokens.set(jti,{deviceId,expiresAt:Date.now()+30*24*3600*1000});
    res.json({accessToken:access,refreshToken:refresh,expiresIn:900});
  }catch(e){console.error('[hs]',e.message);deny(res,500);}
});

app.post('/auth/refresh', rateLimit, (req,res) => {
  try{
    const { refreshToken } = req.body||{};
    if (!refreshToken) return deny(res,400);
    const p = jwt.verify(refreshToken, JWT_SECRET);
    if (p.typ!=='refresh') return deny(res,401);
    const meta = refreshTokens.get(p.jti);
    if (!meta || meta.deviceId!==p.dev) return deny(res,401);
    const access = jwt.sign({typ:'access',dev:p.dev,role:'user'}, JWT_SECRET, {expiresIn:'15m'});
    res.json({accessToken:access,expiresIn:900});
  }catch{return deny(res,401);}
});

// ===== Signed user endpoints =====
const userChain = [rateLimit, verifyAccess, verifySignature];

app.get('/api/data', ...userChain, async (_q,r) => {
  try{ const d=await fbGet('anasheed')||{}; r.json({items:Object.entries(d).map(([id,v])=>({id,...v})).sort((a,b)=>(b.createdAt||0)-(a.createdAt||0))}); }
  catch(e){console.error('[data]',e.message);deny(r,502);}
});
app.get('/api/sections', ...userChain, async (_q,r) => {
  try{ const d=await fbGet('sections')||{}; r.json({items:Object.entries(d).map(([id,v])=>({id,...v})).sort((a,b)=>(a.order||0)-(b.order||0))}); }
  catch(e){console.error('[sec]',e.message);deny(r,502);}
});
app.get('/api/side-menu', ...userChain, async (_q,r) => {
  try{ const d=await fbGet('sideMenu')||{}; r.json({items:Object.entries(d).map(([id,v])=>({id,...v})).sort((a,b)=>(a.order||0)-(b.order||0))}); }
  catch(e){console.error('[sm]',e.message);deny(r,502);}
});
app.get('/api/app-status', ...userChain, async (_q,r) => {
  try{ r.json((await fbGet('appStatus'))||{disabled:false,message:'',version:'1.0.0',updateUrl:''}); }
  catch(e){console.error('[st]',e.message);deny(r,502);}
});

// ===== ADMIN (open, no auth — protected only by rate limiting) =====
const adminChain = [rateLimit];

// Public list endpoints for admin (mirror user data, but unsigned)
app.get('/api/admin/data', ...adminChain, async (_q,r) => {
  try{ const d=await fbGet('anasheed')||{}; r.json({items:Object.entries(d).map(([id,v])=>({id,...v})).sort((a,b)=>(b.createdAt||0)-(a.createdAt||0))}); }
  catch(e){deny(r,502);}
});
app.get('/api/admin/sections', ...adminChain, async (_q,r) => {
  try{ const d=await fbGet('sections')||{}; r.json({items:Object.entries(d).map(([id,v])=>({id,...v})).sort((a,b)=>(a.order||0)-(b.order||0))}); }
  catch(e){deny(r,502);}
});
app.get('/api/admin/side-menu', ...adminChain, async (_q,r) => {
  try{ const d=await fbGet('sideMenu')||{}; r.json({items:Object.entries(d).map(([id,v])=>({id,...v})).sort((a,b)=>(a.order||0)-(b.order||0))}); }
  catch(e){deny(r,502);}
});
app.get('/api/admin/app-status', ...adminChain, async (_q,r) => {
  try{ r.json((await fbGet('appStatus'))||{disabled:false,message:'',version:'1.0.0',updateUrl:''}); }
  catch(e){deny(r,502);}
});

// CRUD: Sections
app.post('/api/admin/sections', ...adminChain, async (req,res) => {
  try{
    const { name, imageUrl, order } = req.body||{};
    if (!name || typeof name!=='string' || name.length>80) return deny(res,400);
    const r = await fbPost('sections', {
      name: name.slice(0,80),
      imageUrl: String(imageUrl||'').slice(0,700),
      order: Number(order)||Date.now(),
      createdAt: Date.now(),
    });
    res.json({id:r.name});
  }catch(e){console.error('[sec+]',e.message);deny(res,500);}
});
app.put('/api/admin/sections/:id', ...adminChain, async (req,res) => {
  try{
    const { name, imageUrl, order } = req.body||{};
    const patch = {};
    if (name!==undefined)     patch.name = String(name).slice(0,80);
    if (imageUrl!==undefined) patch.imageUrl = String(imageUrl).slice(0,700);
    if (order!==undefined)    patch.order = Number(order)||0;
    await fbPatch(`sections/${encodeURIComponent(req.params.id)}`, patch);
    res.json({ok:true});
  }catch(e){console.error('[sec~]',e.message);deny(res,500);}
});
app.delete('/api/admin/sections/:id', ...adminChain, async (req,res) => {
  try{ await fbDelete(`sections/${encodeURIComponent(req.params.id)}`); res.json({ok:true}); }
  catch{ deny(res,500); }
});

// CRUD: Anasheed
app.post('/api/admin/anasheed', ...adminChain, async (req,res) => {
  try{
    const { title, artist, audioUrl, coverUrl, sectionId, tags } = req.body||{};
    if (!title || !audioUrl) return deny(res,400);
    const r = await fbPost('anasheed', {
      title: String(title).slice(0,120),
      artist: String(artist||'').slice(0,80),
      audioUrl: String(audioUrl).slice(0,800),
      coverUrl: String(coverUrl||'').slice(0,800),
      sectionId: sectionId ? String(sectionId).slice(0,40) : null,
      tags: Array.isArray(tags) ? tags.slice(0,8).map(t=>String(t).slice(0,30)) : [],
      createdAt: Date.now(),
    });
    res.json({id:r.name});
  }catch(e){console.error('[na+]',e.message);deny(res,500);}
});
app.put('/api/admin/anasheed/:id', ...adminChain, async (req,res) => {
  try{
    const { title, artist, audioUrl, coverUrl, sectionId, tags } = req.body||{};
    const patch = {};
    if (title!==undefined)     patch.title = String(title).slice(0,120);
    if (artist!==undefined)    patch.artist = String(artist).slice(0,80);
    if (audioUrl!==undefined)  patch.audioUrl = String(audioUrl).slice(0,800);
    if (coverUrl!==undefined)  patch.coverUrl = String(coverUrl).slice(0,800);
    if (sectionId!==undefined) patch.sectionId = sectionId ? String(sectionId).slice(0,40) : null;
    if (tags!==undefined)      patch.tags = Array.isArray(tags) ? tags.slice(0,8).map(t=>String(t).slice(0,30)) : [];
    await fbPatch(`anasheed/${encodeURIComponent(req.params.id)}`, patch);
    res.json({ok:true});
  }catch(e){console.error('[na~]',e.message);deny(res,500);}
});
app.delete('/api/admin/anasheed/:id', ...adminChain, async (req,res) => {
  try{ await fbDelete(`anasheed/${encodeURIComponent(req.params.id)}`); res.json({ok:true}); }
  catch{ deny(res,500); }
});

// CRUD: Side menu
app.post('/api/admin/side-menu', ...adminChain, async (req,res) => {
  try{
    const { label, icon, action, order } = req.body||{};
    if (!label) return deny(res,400);
    const r = await fbPost('sideMenu', {
      label: String(label).slice(0,50),
      icon: String(icon||'').slice(0,30),
      action: String(action||'').slice(0,300),
      order: Number(order)||Date.now(),
    });
    res.json({id:r.name});
  }catch(e){console.error('[sm+]',e.message);deny(res,500);}
});
app.put('/api/admin/side-menu/:id', ...adminChain, async (req,res) => {
  try{
    const { label, icon, action, order } = req.body||{};
    const patch = {};
    if (label!==undefined)  patch.label = String(label).slice(0,50);
    if (icon!==undefined)   patch.icon  = String(icon).slice(0,30);
    if (action!==undefined) patch.action= String(action).slice(0,300);
    if (order!==undefined)  patch.order = Number(order)||0;
    await fbPatch(`sideMenu/${encodeURIComponent(req.params.id)}`, patch);
    res.json({ok:true});
  }catch(e){deny(res,500);}
});
app.delete('/api/admin/side-menu/:id', ...adminChain, async (req,res) => {
  try{ await fbDelete(`sideMenu/${encodeURIComponent(req.params.id)}`); res.json({ok:true}); }
  catch{ deny(res,500); }
});

// App status
app.post('/api/admin/app-status', ...adminChain, async (req,res) => {
  try{
    const { disabled, message, version, updateUrl } = req.body||{};
    await fbPut('appStatus', {
      disabled: !!disabled,
      message: String(message||'').slice(0,300),
      version: String(version||'1.0.0').slice(0,20),
      updateUrl: String(updateUrl||'').slice(0,500),
      updatedAt: Date.now(),
    });
    res.json({ok:true});
  }catch(e){console.error('[st+]',e.message);deny(res,500);}
});

// Static
app.use(express.static(path.join(__dirname,'public'),{maxAge:'1h'}));
app.use((_q,r)=>r.status(404).json({error:'NOT_FOUND'}));
app.use((err,_q,r,_n)=>{console.error('[err]',err.message);r.status(500).json({error:'INTERNAL'});});

app.listen(PORT, ()=>console.log(`[qarfash-api] listening on :${PORT}`));
