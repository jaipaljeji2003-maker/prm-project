/**
 * PRM Worker API (Google Sheets = single source of truth)
 * - Auth against USERS sheet (username|role|pin)
 * - Dispatch + Lead endpoints
 * - Short-lived write-through patches prevent "alert bounce-back"
 *
 * Required env vars:
 *   SPREADSHEET_ID
 *   USERS_SHEET_NAME (default: USERS
 *   DISPATCH_DB_SHEET_NAME (default: Dispatch_DB)
 *   SCAN_COUNTS_SHEET_NAME (default: PRM_ScanCounts)
 *   GOOGLE_SERVICE_ACCOUNT_EMAIL
 * Secrets (recommended):
 *   GOOGLE_PRIVATE_KEY
 *   AUTH_SECRET
 */

const ROLE_ACCESS = {
  Dispatch: { dispatch: true, lead: false, mgmt: false },
  Lead:     { dispatch: false, lead: true, mgmt: false },
  Mgmt:     { dispatch: true, lead: true, mgmt: true },
};

const DB_RANGE_HEADER = "A1:AO1";   // 41 columns (matches your DB_HEADER)
const DB_RANGE_BODY   = "A2:AO";     // values until last row
const KEY_COL_RANGE   = "A2:A";      // Key column

const PATCH_TTL_MS = 10_000;         // bridge read-after-write gap
const DB_CACHE_MS  = 2_000;          // reduce read load (still feels realtime)
const HDR_CACHE_MS = 5 * 60_000;
const IDX_CACHE_MS = 30_000;
const USERS_CACHE_MS = 120_000;
const ROW_CACHE_MS = 1_000;
const SCAN_CACHE_MS = 10_000;

const DEFAULT_TZ = "America/Toronto";

const ZONE_ACK_COL = {
  "DISPATCH": "Dispatch_Ack",
  "PIER A":   "PierA_Ack",
  "PIERA":    "PierA_Ack",
  "TB":       "TB_Ack",
  "GATES":    "Gates_Ack",
  "T1":       "T1_Ack",
  "UNASSIGNED":"Unassigned_Ack",
};

const _rowCache = new Map();
const _rowInflight = new Map();

// Sheets remain the single source of truth; this short cache only smooths bursty reads.
async function cachedRows(key, fn) {
  const now = Date.now();
  const hit = _rowCache.get(key);
  if (hit && (now - hit.ts) <= ROW_CACHE_MS) {
    if (Array.isArray(hit.val)) {
      return hit.val.map(applyPatchesToRowObj);
    }
    return hit.val;
  }

  if (_rowInflight.has(key)) return _rowInflight.get(key);

  const p = (async () => {
    try {
      const val = await fn();
      _rowCache.set(key, { ts: Date.now(), val });
      return val;
    } finally {
      _rowInflight.delete(key);
    }
  })();

  _rowInflight.set(key, p);
  return p;
}

const json = (obj, init = {}) => {
  const headers = new Headers(init.headers || {});
  headers.set("content-type", "application/json; charset=utf-8");
  return new Response(JSON.stringify(obj), { ...init, headers });
};

const withCors = (res, origin = "*") => {
  const h = new Headers(res.headers);
  h.set("access-control-allow-origin", origin);
  h.set("access-control-allow-methods", "GET,POST,PATCH,OPTIONS");
  h.set("access-control-allow-headers", "content-type,authorization");
  h.set("access-control-max-age", "86400");
  return new Response(res.body, { status: res.status, statusText: res.statusText, headers: h });
};

const base64url = {
  enc: (buf) => {
    const b64 = btoa(String.fromCharCode(...new Uint8Array(buf)));
    return b64.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
  },
  encStr: (s) => base64url.enc(new TextEncoder().encode(s)),
  decToBuf: (s) => {
    s = s.replace(/-/g, "+").replace(/_/g, "/");
    while (s.length % 4) s += "=";
    const bin = atob(s);
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out.buffer;
  },
  decToStr: (s) => new TextDecoder().decode(new Uint8Array(base64url.decToBuf(s))),
};

function normalizeZone(z) {
  const s = (z == null) ? "" : String(z).trim();
  if (!s) return "";
  const up = s.toUpperCase().replace(/\s+/g, " ");
  if (up === "PIER A" || up === "PIERA") return "Pier A";
  if (up === "TB") return "TB";
  if (up === "GATE" || up === "GATES") return "Gates";
  if (up === "T1" || up === "TERMINAL 1") return "T1";
  if (up === "UNASSIGNED") return "Unassigned";
  if (up === "ALL") return "ALL";
  return s;
}

/** Convert Google Sheets serial date-time to JS Date (UTC instant). */
/** Convert Google Sheets serial date-time (sheet local wall time) to a real UTC Date instant. */
function serialToDate(serial, tz) {
  if (serial == null || serial === "") return null;
  const n = Number(serial);
  if (!Number.isFinite(n)) return null;

  // Serial -> "wall clock" components (timezone-less). Use UTC getters to keep the wall clock intact.
  const ms = (n - 25569) * 86400_000; // days since 1899-12-30
  const d = new Date(ms);

  const parts = {
    year: d.getUTCFullYear(),
    month: d.getUTCMonth() + 1,
    day: d.getUTCDate(),
    hour: d.getUTCHours(),
    minute: d.getUTCMinutes(),
    second: d.getUTCSeconds(),
  };

  // Treat those parts as local time in tz, convert to UTC instant
  return zonedTimeToUtc(parts, tz);
}

function parseDbTime(v, tz) {
  if (v == null || v === "") return null;

  if (typeof v === "number") return serialToDate(v, tz);
  if (v instanceof Date) return v;

  const s = String(v).trim();

  // If ISO already has timezone (Z or ±hh:mm), Date() is safe.
  if (/[zZ]$/.test(s) || /[+-]\d\d:\d\d$/.test(s)) {
    const d = new Date(s);
    return isNaN(d.getTime()) ? null : d;
  }

  // If it's a local-looking string like "YYYY-MM-DD HH:MM[:SS]" treat as tz local.
  const m = s.match(/^(\d{4})-(\d{2})-(\d{2})[ T](\d{2}):(\d{2})(?::(\d{2}))?/);
  if (m) {
    return zonedTimeToUtc({
      year: +m[1], month: +m[2], day: +m[3],
      hour: +m[4], minute: +m[5], second: m[6] ? +m[6] : 0,
    }, tz);
  }

  // Fallback
  const d = new Date(s);
  return isNaN(d.getTime()) ? null : d;
}

function toIso(v, tz) {
  if (v == null || v === "") return "";
  const d = parseDbTime(v, tz || DEFAULT_TZ);
  return d ? d.toISOString() : String(v);
}


// ---------- Toronto operational window ----------
// Cache Intl formatter per timezone (creating it repeatedly is expensive)
const _dtfCache = new Map();
function _getTzFormatter(tz) {
  let fmt = _dtfCache.get(tz);
  if (!fmt) {
    fmt = new Intl.DateTimeFormat("en-CA", {
      timeZone: tz,
      year: "numeric", month: "2-digit", day: "2-digit",
      hour: "2-digit", minute: "2-digit", second: "2-digit",
      hour12: false,
    });
    _dtfCache.set(tz, fmt);
  }
  return fmt;
}

function getTzParts(date, tz) {
  const fmt = _getTzFormatter(tz);
  const parts = Object.fromEntries(fmt.formatToParts(date).map(p => [p.type, p.value]));
  return {
    year: Number(parts.year),
    month: Number(parts.month),
    day: Number(parts.day),
    hour: Number(parts.hour),
    minute: Number(parts.minute),
    second: Number(parts.second),
  };
}


// Convert a local date-time in `tz` to a UTC Date using iterative correction (DST-safe).
function zonedTimeToUtc({ year, month, day, hour, minute, second }, tz) {
  let utc = Date.UTC(year, month - 1, day, hour, minute, second || 0);
  for (let i = 0; i < 3; i++) {
    const got = getTzParts(new Date(utc), tz);
    const wantLike = Date.UTC(year, month - 1, day, hour, minute, second || 0);
    const gotLike  = Date.UTC(got.year, got.month - 1, got.day, got.hour, got.minute, got.second || 0);
    const diff = wantLike - gotLike;
    if (diff === 0) break;
    utc += diff;
  }
  return new Date(utc);
}

function addDaysLocal(ymd, deltaDays, tz) {
  // Use UTC noon so Toronto local date won't accidentally shift at midnight boundaries.
  const baseUtcNoon = Date.UTC(ymd.year, ymd.month - 1, ymd.day, 12, 0, 0);
  const moved = new Date(baseUtcNoon + deltaDays * 86400_000);
  const p = getTzParts(moved, tz);
  return { year: p.year, month: p.month, day: p.day };
}

function normalizeOpsDay(mode) {
  const v = String(mode || "").trim().toLowerCase();
  return v === "next" ? "next" : "current";
}

function computeOpsWindowToronto(mode = "current", now = new Date()) {
  const tz = DEFAULT_TZ;
  const p = getTzParts(now, tz);

  let opDate = { year: p.year, month: p.month, day: p.day };
  if (p.hour < 4) opDate = addDaysLocal(opDate, -1, tz);

  const opsMode = normalizeOpsDay(mode);
  if (opsMode === "next") opDate = addDaysLocal(opDate, 1, tz);

  const opStartUtc = zonedTimeToUtc({ ...opDate, hour: 4, minute: 0, second: 0 }, tz);
  const opEndDate = addDaysLocal(opDate, 1, tz);
  const opEndUtc = zonedTimeToUtc({ ...opEndDate, hour: 3, minute: 59, second: 59 }, tz);
  opEndUtc.setUTCMilliseconds(999);

  let start = opStartUtc;
  const lookbackStart = new Date(now.getTime() - 60 * 60 * 1000);
  if (lookbackStart > start) start = lookbackStart;

  return {
    start,
    end: opEndUtc,
    startISO: start.toISOString(),
    endISO: opEndUtc.toISOString(),
    startMs: start.getTime(),
    endMs: opEndUtc.getTime(),
  };
}


// ---------- Auth (HMAC tokens, no server storage) ----------
let _hmacKeyPromise = null;

async function getHmacKey(env) {
  if (_hmacKeyPromise) return _hmacKeyPromise;
  const secret = env.AUTH_SECRET || "";
  if (!secret) throw new Error("Missing AUTH_SECRET (set as Worker secret).");
  _hmacKeyPromise = crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign", "verify"]
  );
  return _hmacKeyPromise;
}

async function signToken(env, payloadObj) {
  const payload = base64url.encStr(JSON.stringify(payloadObj));
  const key = await getHmacKey(env);
  const sigBuf = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(payload));
  const sig = base64url.enc(sigBuf);
  return `${payload}.${sig}`;
}

async function verifyToken(env, token) {
  token = String(token || "").trim();
  const parts = token.split(".");
  if (parts.length !== 2) return { ok: false, error: "Invalid token." };

  const [payloadB64, sigB64] = parts;
  const key = await getHmacKey(env);
  const sigBuf = base64url.decToBuf(sigB64);
  const ok = await crypto.subtle.verify("HMAC", key, sigBuf, new TextEncoder().encode(payloadB64));
  if (!ok) return { ok: false, error: "Invalid token." };

  let payload;
  try { payload = JSON.parse(base64url.decToStr(payloadB64)); } catch { return { ok:false, error:"Invalid token." }; }
  if (!payload || !payload.expAt || Date.now() > payload.expAt) return { ok:false, error:"Session expired. Please login again." };

  const access = ROLE_ACCESS[payload.role] || null;
  if (!access) return { ok:false, error:`Invalid role: ${payload.role}` };

  return { ok:true, user: payload, access };
}

function getBearer(req) {
  const h = req.headers.get("authorization") || "";
  const m = h.match(/^\s*Bearer\s+(.+)\s*$/i);
  return m ? m[1] : "";
}

async function requireAuth(req, env, app /* 'dispatch'|'lead'|'' */) {
  const token = getBearer(req);
  if (!token) throw new Error("Missing Authorization token");
  const v = await verifyToken(env, token);
  if (!v.ok) throw new Error(v.error || "Unauthorized");
  if (app) {
    const a = String(app).toLowerCase();
    if (!v.access[a]) throw new Error(`No access to ${a}`);
  }
  return v;
}

// ---------- Google OAuth (Service Account JWT) ----------
const googleState = {
  token: null,
  expAt: 0,
  pkcs8Key: null,
};

function pemToArrayBuffer(pem) {
  const b64 = pem.replace(/-----BEGIN [^-]+-----/g, "")
                .replace(/-----END [^-]+-----/g, "")
                .replace(/\s+/g, "");
  const bin = atob(b64);
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return bytes.buffer;
}

async function importPrivateKey(env) {
  if (googleState.pkcs8Key) return googleState.pkcs8Key;
  const pem = (env.GOOGLE_PRIVATE_KEY || "").replace(/\\n/g, "\n");
  if (!pem.includes("BEGIN PRIVATE KEY")) throw new Error("Missing GOOGLE_PRIVATE_KEY (set as Worker secret).");
  const keyData = pemToArrayBuffer(pem);
  const key = await crypto.subtle.importKey(
    "pkcs8",
    keyData,
    { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
    false,
    ["sign"]
  );
  googleState.pkcs8Key = key;
  return key;
}

async function getGoogleAccessToken(env) {
  const now = Math.floor(Date.now() / 1000);
  if (googleState.token && googleState.expAt > (now + 60)) return googleState.token;

  const saEmail = env.GOOGLE_SERVICE_ACCOUNT_EMAIL;
  if (!saEmail) throw new Error("Missing GOOGLE_SERVICE_ACCOUNT_EMAIL.");
  const scope = "https://www.googleapis.com/auth/spreadsheets";
  const aud = "https://oauth2.googleapis.com/token";

  const header = base64url.encStr(JSON.stringify({ alg: "RS256", typ: "JWT" }));
  const payload = base64url.encStr(JSON.stringify({
    iss: saEmail,
    scope,
    aud,
    iat: now,
    exp: now + 3600,
  }));
  const signingInput = `${header}.${payload}`;

  const key = await importPrivateKey(env);
  const sigBuf = await crypto.subtle.sign(
    "RSASSA-PKCS1-v1_5",
    key,
    new TextEncoder().encode(signingInput)
  );
  const assertion = `${signingInput}.${base64url.enc(sigBuf)}`;

  const body = new URLSearchParams({
    grant_type: "urn:ietf:params:oauth:grant-type:jwt-bearer",
    assertion,
  });

  const resp = await fetch(aud, {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body,
  });

  const data = await resp.json();
  if (!resp.ok) throw new Error(`Google token error: ${data.error || resp.status}`);

  googleState.token = data.access_token;
  googleState.expAt = now + (data.expires_in || 3600);
  return googleState.token;
}

// ---------- Sheets API helpers ----------
async function sheetsGetValues(env, rangeA1) {
  const token = await getGoogleAccessToken(env);
  const sid = env.SPREADSHEET_ID;
  if (!sid) throw new Error("Missing SPREADSHEET_ID.");
  const url = new URL(`https://sheets.googleapis.com/v4/spreadsheets/${sid}/values/${encodeURIComponent(rangeA1)}`);
  url.searchParams.set("valueRenderOption", "UNFORMATTED_VALUE");
  url.searchParams.set("dateTimeRenderOption", "SERIAL_NUMBER");

  const resp = await fetch(url.toString(), {
    headers: { authorization: `Bearer ${token}` }
  });
  const data = await resp.json();
  if (!resp.ok) throw new Error(`Sheets GET error: ${data.error?.message || resp.status}`);
  return data.values || [];
}

async function sheetsBatchUpdate(env, dataRanges /* [{range, values:[[...]]}] */) {
  const token = await getGoogleAccessToken(env);
  const sid = env.SPREADSHEET_ID;

  const url = `https://sheets.googleapis.com/v4/spreadsheets/${sid}/values:batchUpdate?valueInputOption=USER_ENTERED`;
  const resp = await fetch(url, {
    method: "POST",
    headers: {
      authorization: `Bearer ${token}`,
      "content-type": "application/json",
    },
    body: JSON.stringify({ data: dataRanges }),
  });
  const out = await resp.json();
  if (!resp.ok) throw new Error(`Sheets UPDATE error: ${out.error?.message || resp.status}`);
  return out;
}

function colToA1(colNum) {
  let n = colNum;
  let s = "";
  while (n > 0) {
    const r = (n - 1) % 26;
    s = String.fromCharCode(65 + r) + s;
    n = Math.floor((n - 1) / 26);
  }
  return s;
}

// ---------- Caches ----------
const cachesState = {
  hdr: { map: null, ts: 0 },
  idx: { map: null, ts: 0 },
  db:  { rows: null, ts: 0 }, // raw rows (arrays)
  users:{ rows: null, ts: 0 },
  scans:{ map: null, ts: 0 },
  patches: new Map(), // key -> { patch, expAt }
};

async function getHeaderMap(env) {
  const now = Date.now();
  if (cachesState.hdr.map && (now - cachesState.hdr.ts) < HDR_CACHE_MS) return cachesState.hdr.map;

  const sheet = env.DISPATCH_DB_SHEET_NAME || "Dispatch_DB";
  const values = await sheetsGetValues(env, `${sheet}!${DB_RANGE_HEADER}`);
  const header = (values[0] || []).map(x => String(x || "").trim());
  const map = {};
  for (let i = 0; i < header.length; i++) map[header[i]] = i + 1; // 1-based col
  cachesState.hdr = { map, ts: now };
  return map;
}

async function getKeyIndex(env) {
  const now = Date.now();
  if (cachesState.idx.map && (now - cachesState.idx.ts) < IDX_CACHE_MS) return cachesState.idx.map;

  const sheet = env.DISPATCH_DB_SHEET_NAME || "Dispatch_DB";
  const values = await sheetsGetValues(env, `${sheet}!${KEY_COL_RANGE}`);
  const map = new Map();
  for (let i = 0; i < values.length; i++) {
    const key = String(values[i]?.[0] ?? "").trim();
    if (!key) continue;
    map.set(key, 2 + i); // row number in sheet
  }
  cachesState.idx = { map, ts: now };
  return map;
}

function setPatch(key, patch) {
  cachesState.patches.set(String(key), { patch, expAt: Date.now() + PATCH_TTL_MS });
}

function applyPatchesToRowObj(rowObj) {
  const key = String(rowObj.key || "");
  const p = cachesState.patches.get(key);
  if (!p) return rowObj;
  if (Date.now() > p.expAt) { cachesState.patches.delete(key); return rowObj; }
  return { ...rowObj, ...p.patch };
}

async function getDbRows(env) {
  const now = Date.now();
  if (cachesState.db.rows && (now - cachesState.db.ts) < DB_CACHE_MS) return cachesState.db.rows;

  const sheet = env.DISPATCH_DB_SHEET_NAME || "Dispatch_DB";
  const values = await sheetsGetValues(env, `${sheet}!${DB_RANGE_BODY}`);
  cachesState.db = { rows: values, ts: now };
  return values;
}

async function getScanCounts(env) {
  const now = Date.now();
  if (cachesState.scans.map && (now - cachesState.scans.ts) < SCAN_CACHE_MS) return cachesState.scans.map;

  const sheet = env.SCAN_COUNTS_SHEET_NAME || "PRM_ScanCounts";
  const values = await sheetsGetValues(env, `${sheet}!A2:B`);
  const map = new Map();
  for (const row of values) {
    const key = String(row?.[0] ?? "").trim();
    if (!key) continue;
    map.set(key, row?.[1] ?? "");
  }
  cachesState.scans = { map, ts: now };
  return map;
}

// ---------- USERS lookup ----------
async function getUsers(env) {
  const now = Date.now();
  if (cachesState.users.rows && (now - cachesState.users.ts) < USERS_CACHE_MS) return cachesState.users.rows;

  const sheet = env.USERS_SHEET_NAME || "USERS";
  // read first 1000 rows, 3 cols
  const values = await sheetsGetValues(env, `${sheet}!A1:C1000`);
  cachesState.users = { rows: values, ts: now };
  return values;
}

async function handleLogin(req, env) {
  const body = await req.json().catch(() => ({}));
  const username = String(body.username || "").trim();
  const pin = String(body.pin || "").trim();
  if (!username || !pin) return json({ ok:false, error:"Missing username or pin." }, { status: 400 });

  const values = await getUsers(env);
  if (!values || values.length < 2) return json({ ok:false, error:"USERS has no users." }, { status: 400 });

  const hdr = (values[0] || []).map(x => String(x || "").trim().toLowerCase());
  const ixU = hdr.indexOf("username");
  const ixR = hdr.indexOf("role");
  const ixP = hdr.indexOf("pin");
  if (ixU === -1 || ixR === -1 || ixP === -1) {
    return json({ ok:false, error:"USERS headers must be: username | role | pin" }, { status: 400 });
  }

  let user = null;
  for (let i = 1; i < values.length; i++) {
    const u = String(values[i]?.[ixU] ?? "").trim();
    const r = String(values[i]?.[ixR] ?? "").trim();
    const p = String(values[i]?.[ixP] ?? "").trim();
    if (!u) continue;
    if (u.toLowerCase() === username.toLowerCase() && p === pin) {
      user = { username: u, role: r };
      break;
    }
  }
  if (!user) return json({ ok:false, error:"Invalid username or pin." }, { status: 401 });

  const access = ROLE_ACCESS[user.role];
  if (!access) return json({ ok:false, error:`Invalid role in USERS: ${user.role}` }, { status: 401 });

  const expAt = Date.now() + (6 * 60 * 60 * 1000); // 6 hours
  const token = await signToken(env, { username: user.username, role: user.role, expAt });
  return json({ ok:true, token, user:{ username:user.username, role:user.role, expAt }, access });
}

async function handleValidate(req, env) {
  const u = await requireAuth(req, env, "");
  const url = new URL(req.url);
  const app = (url.searchParams.get("app") || "").trim().toLowerCase();
  if (app && !u.access[app]) return json({ ok:false, error:`No access to ${app}` }, { status: 403 });
  return json({ ok:true, user:u.user, access:u.access });
}

// ---------- Dispatch / Lead row shaping ----------
function operationalWindow(env, opsDay) {
  return computeOpsWindowToronto(opsDay);
}

// Indices based on your DB_HEADER order (0-based)
const IX = {
  key: 0, type: 1, flight: 2,
  time: 3, sched: 4, origin: 5, gate: 6,
  wchr: 7, wchc: 8, comment: 9,
  gateChanged: 11,
  assignment: 13, pax: 14,
  zoneCur: 15,
  timePrev: 19,
  timeChanged: 20, timeDelta: 21, timeChgAt: 22,
  zoneChanged: 25,
  zoneFrom: 27, zoneTo: 28,
  alertText: 29,
};

async function dispatchRowsImpl(env, opsDay) {
  const rows = await getDbRows(env);
  const hdr = await getHeaderMap(env);
  const watchCol = hdr["Watchlist"] || hdr["Watch List"] || hdr["Watch"] || null;
  const ackCol = hdr["Dispatch_Ack"] || null; // 1-based
  const scanCounts = await getScanCounts(env);

  const tz = env.TIMEZONE || DEFAULT_TZ;
  const win = operationalWindow(env, opsDay);

  const out = []; // store [timeMs, rowObj] so sort is cheap
  for (const r of rows) {
    if (!r || !r.length) continue;
    const t = r[IX.time];
    if (t == null || t === "") continue;

    const dt = parseDbTime(t, tz);
    if (!dt || isNaN(dt.getTime())) continue;
    if (dt < win.start || dt > win.end) continue;

    const dispatchAcked = ackCol ? isTrue(r[ackCol - 1]) : false;

    const key = String(r[IX.key] || "");
    const obj = {
      key:        String(r[IX.key] || ""),
      type:       String(r[IX.type] || ""),
      flight:     String(r[IX.flight] || ""),

      // IMPORTANT: use dt we already parsed (don’t re-parse via toIso)
      timeEst:    dt.toISOString(),

      sched:      toIso(r[IX.sched], tz),
      origin:     String(r[IX.origin] || ""),
      gate:       String(r[IX.gate] || ""),
      zone:       String(r[IX.zoneCur] || ""),

      alert:      dispatchAcked ? "" : String(r[IX.alertText] || ""),

      wchr:       (r[IX.wchr] ?? "").toString(),
      wchc:       (r[IX.wchc] ?? "").toString(),
      comment:    (r[IX.comment] ?? "").toString(),

      assignment: (r[IX.assignment] ?? "").toString(),
      pax:        (r[IX.pax] ?? "").toString(),
      scanCount:  String(scanCounts.get(key) ?? ""),

      gateChanged: dispatchAcked ? false : (r[IX.gateChanged] === true),
      timeChanged: dispatchAcked ? false : (r[IX.timeChanged] === true),
      zoneChanged: dispatchAcked ? false : (r[IX.zoneChanged] === true),

      timePrev:  toIso(r[IX.timePrev], tz),
      timeDelta: (r[IX.timeDelta] ?? "").toString(),
      timeChgAt: toIso(r[IX.timeChgAt], tz),
    };

    out.push([dt.getTime(), applyPatchesToRowObj(obj)]);
  }

  out.sort((a, b) => a[0] - b[0]);
  return out.map(x => x[1]);
}

async function dispatchRows(env, params) {
  const opsDay = normalizeOpsDay(params?.opsDay);
  return cachedRows(`dispatch:${opsDay}`, () => dispatchRowsImpl(env, opsDay));
}


function isTrue(v) {
  if (v === true) return true;
  const s = String(v ?? "").trim().toLowerCase();
  return s === "true" || s === "1" || s === "yes" || s === "y";
}

async function leadRowsImpl(env, params) {
  const zoneWanted = normalizeZone(params.zone || "ALL");
  const typeFilter = String(params.type || "ALL").toUpperCase();
  const q = String(params.q || "").trim().toUpperCase().replace(/\s+/g, "");
  const opsDay = normalizeOpsDay(params.opsDay);

  const rows = await getDbRows(env);
  const hdr = await getHeaderMap(env);
  const watchCol = hdr["Watchlist"] || hdr["Watch List"] || hdr["Watch"] || null;
  const scanCounts = await getScanCounts(env);

  const tz = env.TIMEZONE || DEFAULT_TZ;   // moved OUT of the loop
  const win = operationalWindow(env, opsDay);

  const ackColName = (zoneWanted !== "ALL")
    ? (ZONE_ACK_COL[String(zoneWanted).toUpperCase()] || null)
    : null;
  const ackCol = ackColName ? hdr[ackColName] : null;

  // Store [timeMs, obj] so sort is cheap (no Date parsing in sort)
  const out = [];

  for (const r of rows) {
    if (!r || !r.length) continue;

    const t = r[IX.time];
    if (t == null || t === "") continue;

    const dt = parseDbTime(t, tz);
    if (!dt || isNaN(dt.getTime())) continue;
    if (dt < win.start || dt > win.end) continue;

    const rowType = String(r[IX.type] || "").toUpperCase();
    if (typeFilter !== "ALL" && rowType !== typeFilter) continue;

    const flight = String(r[IX.flight] || "");
    const flightQ = flight.toUpperCase().replace(/\s+/g, "");
    if (q && !flightQ.includes(q)) continue;

    const zoneCur = normalizeZone(r[IX.zoneCur] || "");
    const zoneChanged = (r[IX.zoneChanged] === true);
    const zoneFrom = normalizeZone(r[IX.zoneFrom] || "");
    const zoneTo   = normalizeZone(r[IX.zoneTo] || "");

    const ackedHere = (ackCol ? isTrue(r[ackCol - 1]) : false);

    if (zoneWanted !== "ALL") {
      const inMyZone = (zoneCur === zoneWanted);
      const movedOutNeedsAck = zoneChanged && (zoneFrom === zoneWanted) && (zoneCur !== zoneWanted) && !ackedHere;
      if (!inMyZone && !movedOutNeedsAck) continue;
    }

    const key = String(r[IX.key] || "");
    const obj = {
      key,
      type:       String(r[IX.type] || ""),
      flight,
      // Use the already-parsed dt instead of re-parsing with toIso(...)
      timeEst:    dt.toISOString(),

      gate:       String(r[IX.gate] || ""),
      zone:       String(r[IX.zoneCur] || ""),

      wchr: (r[IX.wchr] ?? "").toString(),
      wchc: (r[IX.wchc] ?? "").toString(),

      assignment: String(r[IX.assignment] ?? ""),
      pax:        String(r[IX.pax] ?? ""),
      scanCount:  String(scanCounts.get(key) ?? ""),

      alert: ackedHere ? "" : String(r[IX.alertText] || ""),

      gateChanged: ackedHere ? false : (r[IX.gateChanged] === true),
      timeChanged: ackedHere ? false : (r[IX.timeChanged] === true),
      zoneChanged: ackedHere ? false : (r[IX.zoneChanged] === true),

      zoneFrom,
      zoneTo,
    };

    if (watchCol) obj.watchlist = String(r[watchCol - 1] ?? "");

    out.push([dt.getTime(), applyPatchesToRowObj(obj)]);
  }

  out.sort((a, b) => a[0] - b[0]);
  return out.map(x => x[1]);
}

function leadCacheKey(params) {
  const zoneWanted = normalizeZone(params.zone || "ALL");
  const typeFilter = String(params.type || "ALL").toUpperCase();
  const q = String(params.q || "").trim().toUpperCase().replace(/\s+/g, "");
  const opsDay = normalizeOpsDay(params.opsDay);
  return `lead:${zoneWanted}|${typeFilter}|${q}|${opsDay}`;
}

async function leadRows(env, params) {
  return cachedRows(leadCacheKey(params), () => leadRowsImpl(env, params));
}

async function mgmtRowsImpl(env, opsDay) {
  const rows = await getDbRows(env);
  const hdr = await getHeaderMap(env);
  const ackCol = hdr["Dispatch_Ack"] || null; // 1-based
  const scanCounts = await getScanCounts(env);

  const tz = env.TIMEZONE || DEFAULT_TZ;
  const win = operationalWindow(env, opsDay);

  const out = [];
  for (const r of rows) {
    if (!r || !r.length) continue;
    const t = r[IX.time];
    if (t == null || t === "") continue;

    const dt = parseDbTime(t, tz);
    if (!dt || isNaN(dt.getTime())) continue;
    if (dt < win.start || dt > win.end) continue;

    const dispatchAcked = ackCol ? isTrue(r[ackCol - 1]) : false;
    const key = String(r[IX.key] || "");

    const obj = {
      key,
      type:       String(r[IX.type] || ""),
      flight:     String(r[IX.flight] || ""),
      timeEst:    dt.toISOString(),
      sched:      toIso(r[IX.sched], tz),
      origin:     String(r[IX.origin] || ""),
      gate:       String(r[IX.gate] || ""),
      zone:       String(r[IX.zoneCur] || ""),
      alert:      dispatchAcked ? "" : String(r[IX.alertText] || ""),

      wchr:       (r[IX.wchr] ?? "").toString(),
      wchc:       (r[IX.wchc] ?? "").toString(),
      comment:    (r[IX.comment] ?? "").toString(),
      assignment: (r[IX.assignment] ?? "").toString(),
      pax:        (r[IX.pax] ?? "").toString(),
      scanCount:  String(scanCounts.get(key) ?? ""),

      gateChanged: dispatchAcked ? false : (r[IX.gateChanged] === true),
      timeChanged: dispatchAcked ? false : (r[IX.timeChanged] === true),
      zoneChanged: dispatchAcked ? false : (r[IX.zoneChanged] === true),

      timePrev:  toIso(r[IX.timePrev], tz),
      timeDelta: (r[IX.timeDelta] ?? "").toString(),
      timeChgAt: toIso(r[IX.timeChgAt], tz),
    };

    out.push([dt.getTime(), applyPatchesToRowObj(obj)]);
  }

  out.sort((a, b) => a[0] - b[0]);
  return out.map(x => x[1]);
}

async function mgmtRows(env, params) {
  const opsDay = normalizeOpsDay(params?.opsDay);
  return cachedRows(`mgmt:${opsDay}`, () => mgmtRowsImpl(env, opsDay));
}


// ---------- Writes ----------
async function updateDispatch(env, payload) {
  if (!payload || !payload.key) throw new Error("Missing key");
  const key = String(payload.key);

  const idx = await getKeyIndex(env);
  const rowNum = idx.get(key);
  if (!rowNum) throw new Error("Key not found in Dispatch_DB");

  const sheet = env.DISPATCH_DB_SHEET_NAME || "Dispatch_DB";
  const hdr = await getHeaderMap(env);

  const updates = [];

  // We'll read current WCHR/WCHC only if needed to track prev values.
  let oldWchr = null, oldWchc = null;
  const needPrev = (payload.wchr !== undefined) || (payload.wchc !== undefined);

  if (needPrev) {
    const wchrCol = hdr["WCHR"] || 8; // H
    const wchcCol = hdr["WCHC"] || 9; // I
    const a1 = `${sheet}!${colToA1(wchrCol)}${rowNum}:${colToA1(wchcCol)}${rowNum}`;
    const vals = await sheetsGetValues(env, a1);
    const row = vals[0] || [];
    oldWchr = row[0];
    oldWchc = row[1];
  }

  if (payload.wchr !== undefined) {
    const wchrCol = hdr["WCHR"] || 8;
    const prevCol = hdr["prevWCHR"] || hdr["PrevWCHR"] || null;
    const newVal = payload.wchr;

    if (prevCol && String(oldWchr ?? "") !== String(newVal ?? "")) {
      updates.push({ range: `${sheet}!${colToA1(prevCol)}${rowNum}`, values: [[oldWchr ?? ""]] });
    }
    updates.push({ range: `${sheet}!${colToA1(wchrCol)}${rowNum}`, values: [[newVal]] });
  }

  if (payload.wchc !== undefined) {
    const wchcCol = hdr["WCHC"] || 9;
    const prevCol = hdr["prevWCHC"] || hdr["PrevWCHC"] || null;
    const newVal = payload.wchc;

    if (prevCol && String(oldWchc ?? "") !== String(newVal ?? "")) {
      updates.push({ range: `${sheet}!${colToA1(prevCol)}${rowNum}`, values: [[oldWchc ?? ""]] });
    }
    updates.push({ range: `${sheet}!${colToA1(wchcCol)}${rowNum}`, values: [[newVal]] });
  }

  if (payload.comment !== undefined) {
    const commentCol = hdr["Comment"] || 10;
    updates.push({ range: `${sheet}!${colToA1(commentCol)}${rowNum}`, values: [[payload.comment]] });
  }

  if (!updates.length) return { ok:true };

  await sheetsBatchUpdate(env, updates);

  // write-through patch for UI
  const patch = {};
  if (payload.wchr !== undefined) patch.wchr = String(payload.wchr ?? "");
  if (payload.wchc !== undefined) patch.wchc = String(payload.wchc ?? "");
  if (payload.comment !== undefined) patch.comment = String(payload.comment ?? "");
  setPatch(key, patch);

  return { ok:true };
}

async function updateLead(env, user, payload) {
  if (!payload || !payload.key) throw new Error("Missing key");
  const key = String(payload.key);

  const idx = await getKeyIndex(env);
  const rowNum = idx.get(key);
  if (!rowNum) throw new Error("Key not found in Dispatch_DB");

  const sheet = env.DISPATCH_DB_SHEET_NAME || "Dispatch_DB";
  const hdr = await getHeaderMap(env);

  const updates = [];
  const patch = {};

  if (payload.assignment !== undefined) {
    const colAssignment = hdr["Assignment"] || 14;
    updates.push({ range: `${sheet}!${colToA1(colAssignment)}${rowNum}`, values: [[payload.assignment]] });

    // audit columns (present in your header)
    const colBy = hdr["assignEditedBy"] || null;
    const colAt = hdr["assignEditedAt"] || null;
    if (colBy) updates.push({ range: `${sheet}!${colToA1(colBy)}${rowNum}`, values: [[user.username || ""]] });
    if (colAt) updates.push({ range: `${sheet}!${colToA1(colAt)}${rowNum}`, values: [[new Date().toISOString()]] });
    patch.assignment = String(payload.assignment ?? "");
  }

  if (payload.pax !== undefined) {
    const colPax = hdr["Pax_Assisted"] || 15;
    updates.push({ range: `${sheet}!${colToA1(colPax)}${rowNum}`, values: [[payload.pax]] });
    patch.pax = String(payload.pax ?? "");
  }

  if (payload.watchlist !== undefined) {
    const colWatch = hdr["Watchlist"] || hdr["Watch List"] || hdr["Watch"];
    if (!colWatch) throw new Error("Watchlist column not found in header.");
    updates.push({ range: `${sheet}!${colToA1(colWatch)}${rowNum}`, values: [[payload.watchlist]] });
    patch.watchlist = String(payload.watchlist ?? "");
  }

  if (!updates.length) return { ok:true };
  if (Object.keys(patch).length) setPatch(key, patch);
  try {
    await sheetsBatchUpdate(env, updates);
  } catch (err) {
    cachesState.patches.delete(key);
    throw err;
  }

  return { ok:true };
}

async function ackDispatch(env, key) {
  const idx = await getKeyIndex(env);
  const rowNum = idx.get(String(key));
  if (!rowNum) throw new Error("Key not found in Dispatch_DB");

  const sheet = env.DISPATCH_DB_SHEET_NAME || "Dispatch_DB";
  const hdr = await getHeaderMap(env);

  const ackCol = hdr["Dispatch_Ack"];
  if (!ackCol) throw new Error("Dispatch_Ack column not found.");

  const updates = [{ range: `${sheet}!${colToA1(ackCol)}${rowNum}`, values: [[true]] }];

  // optional AckAt column
  const ackAtName = "Dispatch_AckAt";
  const ackAtCol = hdr[ackAtName] || null;
  if (ackAtCol) updates.push({ range: `${sheet}!${colToA1(ackAtCol)}${rowNum}`, values: [[new Date().toISOString()]] });

  await sheetsBatchUpdate(env, updates);

  setPatch(key, { alert:"", gateChanged:false, timeChanged:false, zoneChanged:false });
  return { ok:true };
}

async function ackLead(env, key, zone) {
  const ackZone = normalizeZone(zone || "");
  const colName = ZONE_ACK_COL[String(ackZone).toUpperCase()];
  if (!colName) throw new Error("Unknown zone for ACK: " + zone);

  const idx = await getKeyIndex(env);
  const rowNum = idx.get(String(key));
  if (!rowNum) throw new Error("Key not found in Dispatch_DB");

  const sheet = env.DISPATCH_DB_SHEET_NAME || "Dispatch_DB";
  const hdr = await getHeaderMap(env);

  const ackCol = hdr[colName];
  if (!ackCol) throw new Error(`Ack column not found in header: ${colName}`);

  const updates = [{ range: `${sheet}!${colToA1(ackCol)}${rowNum}`, values: [[true]] }];

  const ackAtCol = hdr[`${colName}At`] || hdr[`${colName.replace(/_Ack$/,"_AckAt")}`] || null;
  if (ackAtCol) updates.push({ range: `${sheet}!${colToA1(ackAtCol)}${rowNum}`, values: [[new Date().toISOString()]] });

  await sheetsBatchUpdate(env, updates);

  setPatch(key, { alert:"", gateChanged:false, timeChanged:false, zoneChanged:false });
  return { ok:true };
}

// ---------- Router ----------
export default {
  async fetch(req, env, ctx) {
    const origin = req.headers.get("origin") || "*";

    if (req.method === "OPTIONS") {
      return withCors(new Response(null, { status: 204 }), origin);
    }

    try {
      const url = new URL(req.url);
      const path = url.pathname.replace(/\/+$/,"") || "/";

      if (path === "/" || path === "/health") {
        return withCors(json({ ok:true, name:"prm-api-worker", time: new Date().toISOString() }), origin);
      }

      // ---- auth ----
      if (path === "/auth/login" && req.method === "POST") {
        return withCors(await handleLogin(req, env), origin);
      }
      if (path === "/auth/validate" && req.method === "GET") {
        return withCors(await handleValidate(req, env), origin);
      }

      // ---- dispatch ----
      if (path === "/dispatch/rows" && req.method === "GET") {
        await requireAuth(req, env, "dispatch");
        const params = {
          opsDay: url.searchParams.get("opsDay") || "current",
        };
        const rows = await dispatchRows(env, params);
        return withCors(json({ ok:true, rows, generatedAt: new Date().toISOString() }), origin);
      }

      if (path === "/dispatch/update" && req.method === "PATCH") {
        await requireAuth(req, env, "dispatch");
        const payload = await req.json().catch(() => ({}));
        const out = await updateDispatch(env, payload);
        return withCors(json(out), origin);
      }

      if (path === "/dispatch/ack" && req.method === "POST") {
        await requireAuth(req, env, "dispatch");
        const payload = await req.json().catch(() => ({}));
        const out = await ackDispatch(env, payload.key);
        return withCors(json(out), origin);
      }

      // ---- lead ----
      if (path === "/lead/init" && req.method === "GET") {
        await requireAuth(req, env, "lead");
        const zones = ["TB","Gates","Pier A","T1","Unassigned"];
        return withCors(json({ ok:true, zones, serverTime: new Date().toISOString() }), origin);
      }

      if (path === "/lead/rows" && req.method === "GET") {
        await requireAuth(req, env, "lead");
        const params = {
          zone: url.searchParams.get("zone") || "TB",
          type: url.searchParams.get("type") || "ALL",
          q: url.searchParams.get("q") || "",
          opsDay: url.searchParams.get("opsDay") || "current",
        };
        const rows = await leadRows(env, params);
        return withCors(json({ ok:true, rows, generatedAt: new Date().toISOString() }), origin);
      }

      if (path === "/lead/update" && req.method === "PATCH") {
        const v = await requireAuth(req, env, "lead");
        const payload = await req.json().catch(() => ({}));
        const out = await updateLead(env, v.user, payload);
        return withCors(json(out), origin);
      }

      if (path === "/lead/ack" && req.method === "POST") {
        await requireAuth(req, env, "lead");
        const payload = await req.json().catch(() => ({}));
        const out = await ackLead(env, payload.key, payload.zone);
        return withCors(json(out), origin);
      }

      // ---- management ----
      if (path === "/mgmt/rows" && req.method === "GET") {
        await requireAuth(req, env, "mgmt");
        const params = {
          opsDay: url.searchParams.get("opsDay") || "current",
        };
        const rows = await mgmtRows(env, params);
        return withCors(json({ ok:true, rows, generatedAt: new Date().toISOString() }), origin);
      }

      return withCors(json({ ok:false, error:"Not found" }, { status: 404 }), origin);

    } catch (err) {
      const msg = (err && err.message) ? err.message : String(err);
      return withCors(json({ ok:false, error: msg }, { status: /missing authorization|unauthorized|expired|no access/i.test(msg) ? 401 : 500 }), origin);
    }
  }
};
