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
const AVG_CACHE_MS = 10 * 60_000;
const PRMGO_CACHE_MS = 30_000;

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
const _avgCache = { map: null, ts: 0 };
const _prmgoRowsCache = { rows: null, ts: 0 };
const _prmgoCountsCache = new Map();

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

function normalizeFlightNorm(flight) {
  return String(flight || "").toUpperCase().replace(/\s+/g, "");
}

function normalizeType(type) {
  return String(type || "").trim().toUpperCase();
}

function buildFlightKey(type, flight) {
  const t = normalizeType(type);
  const f = normalizeFlightNorm(flight);
  if (!t || !f) return "";
  return `${t}|${f}`;
}

function inferTerminalFromRow(obj) {
  const gate = String(obj?.gate || "").trim().toUpperCase();
  if (/^[ABC]/.test(gate)) return "T3";
  if (/^[DEF]/.test(gate)) return "T1";

  const zone = String(obj?.zone || "").trim().toUpperCase();
  if (zone.includes("T1")) return "T1";
  if (zone.includes("T3")) return "T3";
  return "";
}

function parseFlightParts(flight) {
  const cleaned = String(flight || "").toUpperCase().replace(/\s+/g, "");
  const match = cleaned.match(/^([A-Z]+)([0-9]+)$/);
  if (!match) return { airline: "", flightNumber: "", cleaned };
  return { airline: match[1], flightNumber: match[2], cleaned };
}

function formatYmd({ year, month, day }) {
  const mm = String(month).padStart(2, "0");
  const dd = String(day).padStart(2, "0");
  return `${year}-${mm}-${dd}`;
}

function parseYmd(s) {
  const m = String(s || "").match(/^(\d{4})-(\d{2})-(\d{2})$/);
  if (!m) return null;
  return { year: Number(m[1]), month: Number(m[2]), day: Number(m[3]) };
}

function toNumber(v) {
  if (v == null || v === "") return null;
  const n = Number(v);
  return Number.isFinite(n) ? n : null;
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

const _timeOnlyCache = new Map();
function formatTimeOnly(date, tz) {
  let fmt = _timeOnlyCache.get(tz);
  if (!fmt) {
    fmt = new Intl.DateTimeFormat("en-CA", {
      timeZone: tz,
      hour: "2-digit",
      minute: "2-digit",
      hour12: false,
    });
    _timeOnlyCache.set(tz, fmt);
  }
  return fmt.format(date);
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
  if (p.hour < 3) opDate = addDaysLocal(opDate, -1, tz);

  const opsMode = normalizeOpsDay(mode);
  if (opsMode === "next") opDate = addDaysLocal(opDate, 1, tz);

  const opStartUtc = zonedTimeToUtc({ ...opDate, hour: 3, minute: 0, second: 0 }, tz);
  const opEndDate = addDaysLocal(opDate, 1, tz);
  const opEndUtc = zonedTimeToUtc({ ...opEndDate, hour: 2, minute: 59, second: 59 }, tz);
  opEndUtc.setUTCMilliseconds(999);

  let start = opStartUtc;
  const lookbackStart = new Date(now.getTime() - 60 * 60 * 1000);
  if (lookbackStart > start) start = lookbackStart;

  return {
    start,
    end: opEndUtc,
    opsDateYmd: formatYmd(opDate),
    startISO: start.toISOString(),
    endISO: opEndUtc.toISOString(),
    startMs: start.getTime(),
    endMs: opEndUtc.getTime(),
  };
}

function computeMgmtWindowToronto(now = new Date()) {
  const tz = DEFAULT_TZ;
  const p = getTzParts(now, tz);
  let opDate = { year: p.year, month: p.month, day: p.day };
  if (p.hour < 3) opDate = addDaysLocal(opDate, -1, tz);

  const startUtc = zonedTimeToUtc({ ...opDate, hour: 1, minute: 0, second: 0 }, tz);
  const endDate = addDaysLocal(opDate, 1, tz);
  const endUtc = zonedTimeToUtc({ ...endDate, hour: 2, minute: 59, second: 59 }, tz);
  endUtc.setUTCMilliseconds(999);

  return {
    start: startUtc,
    end: endUtc,
    startISO: startUtc.toISOString(),
    endISO: endUtc.toISOString(),
    startMs: startUtc.getTime(),
    endMs: endUtc.getTime(),
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

async function sheetsGetValuesFor(env, spreadsheetId, rangeA1) {
  const token = await getGoogleAccessToken(env);
  const sid = spreadsheetId;
  if (!sid) throw new Error("Missing spreadsheetId.");
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

async function sheetsBatchUpdateFor(env, spreadsheetId, dataRanges) {
  const token = await getGoogleAccessToken(env);
  const sid = spreadsheetId;
  if (!sid) throw new Error("Missing spreadsheetId.");

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

async function sheetsClearValuesFor(env, spreadsheetId, rangeA1) {
  const token = await getGoogleAccessToken(env);
  const sid = spreadsheetId;
  if (!sid) throw new Error("Missing spreadsheetId.");
  const url = `https://sheets.googleapis.com/v4/spreadsheets/${sid}/values/${encodeURIComponent(rangeA1)}:clear`;
  const resp = await fetch(url, {
    method: "POST",
    headers: { authorization: `Bearer ${token}` },
  });
  const out = await resp.json();
  if (!resp.ok) throw new Error(`Sheets CLEAR error: ${out.error?.message || resp.status}`);
  return out;
}

async function sheetsBatchUpdateSpreadsheet(env, spreadsheetId, requests) {
  const token = await getGoogleAccessToken(env);
  const sid = spreadsheetId;
  if (!sid) throw new Error("Missing spreadsheetId.");
  const url = `https://sheets.googleapis.com/v4/spreadsheets/${sid}:batchUpdate`;
  const resp = await fetch(url, {
    method: "POST",
    headers: {
      authorization: `Bearer ${token}`,
      "content-type": "application/json",
    },
    body: JSON.stringify({ requests }),
  });
  const out = await resp.json();
  if (!resp.ok) throw new Error(`Sheets batchUpdate error: ${out.error?.message || resp.status}`);
  return out;
}

async function sheetsGetSpreadsheetMeta(env, spreadsheetId) {
  const token = await getGoogleAccessToken(env);
  const sid = spreadsheetId;
  if (!sid) throw new Error("Missing spreadsheetId.");
  const url = new URL(`https://sheets.googleapis.com/v4/spreadsheets/${sid}`);
  url.searchParams.set("fields", "sheets.properties.title");
  const resp = await fetch(url.toString(), {
    headers: { authorization: `Bearer ${token}` },
  });
  const data = await resp.json();
  if (!resp.ok) throw new Error(`Sheets metadata error: ${data.error?.message || resp.status}`);
  return data;
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

async function getAvg30dMap(env) {
  const now = Date.now();
  if (_avgCache.map && (now - _avgCache.ts) < AVG_CACHE_MS) return _avgCache.map;

  const sheet = env.FLIGHT_AVG_30D_SHEET_NAME || "flight_avg_30d";
  try {
    const values = await sheetsGetValues(env, `${sheet}!A2:H`);
    const map = new Map();
    for (const row of values) {
      const key = String(row?.[0] ?? "").trim();
      if (!key) continue;
      map.set(key, {
        avgPrm30: toNumber(row?.[1]),
        avgWchr30: toNumber(row?.[2]),
        avgWchc30: toNumber(row?.[3]),
        avgN30: toNumber(row?.[4]),
      });
    }
    _avgCache.map = map;
    _avgCache.ts = now;
    return map;
  } catch {
    const map = new Map();
    _avgCache.map = map;
    _avgCache.ts = now;
    return map;
  }
}

async function listPrmgoFlightCountsRows(env) {
  const now = Date.now();
  if (_prmgoRowsCache.rows && (now - _prmgoRowsCache.ts) < PRMGO_CACHE_MS) return _prmgoRowsCache.rows;

  const sheetId = env.DB_SHEET_ID || env.SPREADSHEET_ID;
  if (!sheetId) throw new Error("Missing DB_SHEET_ID/SPREADSHEET_ID.");

  const values = await sheetsGetValuesFor(env, sheetId, "PRMGO_FlightCounts!A1:G");
  _prmgoRowsCache.rows = values;
  _prmgoRowsCache.ts = now;
  return values;
}

async function getPrmgoCountsMap(env, opsMode) {
  const opsWindow = computeOpsWindowToronto(opsMode);
  const opsDateYmd = opsWindow.opsDateYmd;
  const now = Date.now();

  const cached = _prmgoCountsCache.get(opsDateYmd);
  if (cached && (now - cached.ts) < PRMGO_CACHE_MS) return cached.map;

  const rows = await listPrmgoFlightCountsRows(env);
  const map = new Map();

  const hdr = (rows[0] || []).map(x => String(x || "").trim().toLowerCase());
  const ixOpsDate = hdr.indexOf("ops_date");
  const ixDirection = hdr.indexOf("direction");
  const ixTerminal = hdr.indexOf("terminal");
  const ixAirline = hdr.indexOf("airline");
  const ixFlight = hdr.indexOf("flight");
  const ixScanned = hdr.indexOf("scanned_count");
  const ixUpdated = hdr.indexOf("last_updated_toronto");

  if ([ixOpsDate, ixDirection, ixTerminal, ixAirline, ixFlight, ixScanned].some(ix => ix < 0)) {
    _prmgoCountsCache.set(opsDateYmd, { map, ts: now });
    return map;
  }

  const tz = env.TIMEZONE || DEFAULT_TZ;

  for (let i = 1; i < rows.length; i++) {
    const row = rows[i] || [];
    const opsDate = parseDbTime(row[ixOpsDate], tz);
    if (!opsDate) continue;

    const rowYmd = formatYmd(getTzParts(opsDate, tz));
    if (rowYmd !== opsDateYmd) continue;

    const direction = normalizeType(row[ixDirection]);
    const terminal = String(row[ixTerminal] ?? "").trim().toUpperCase();
    const airline = String(row[ixAirline] ?? "").trim().toUpperCase();
    const flightNumber = String(row[ixFlight] ?? "").trim().replace(/\D/g, "");
    if (!direction || !terminal || !airline || !flightNumber) continue;

    const scannedRaw = toNumber(row[ixScanned]);
    const scannedCount = Number.isFinite(scannedRaw) ? Math.round(scannedRaw) : 0;
    const lastUpdated = row[ixUpdated] ?? "";
    const key = `${opsDateYmd}|${direction}|${terminal}|${airline}${flightNumber}`;

    map.set(key, { scanned_count: scannedCount, last_updated_toronto: lastUpdated });
  }

  _prmgoCountsCache.set(opsDateYmd, { map, ts: now });
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
  const avgMap = await getAvg30dMap(env);

  const tz = env.TIMEZONE || DEFAULT_TZ;
  const win = operationalWindow(env, opsDay);
  const opsDateYmd = win.opsDateYmd;
  const countsMap = await getPrmgoCountsMap(env, opsDay);

  const out = []; // store [timeMs, rowObj] so sort is cheap
  for (const r of rows) {
    if (!r || !r.length) continue;
    const t = r[IX.time];
    if (t == null || t === "") continue;

    const dt = parseDbTime(t, tz);
    if (!dt || isNaN(dt.getTime())) continue;
    if (dt < win.start || dt > win.end) continue;

    const dispatchAcked = ackCol ? isTrue(r[ackCol - 1]) : false;

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

      gateChanged: dispatchAcked ? false : (r[IX.gateChanged] === true),
      timeChanged: dispatchAcked ? false : (r[IX.timeChanged] === true),
      zoneChanged: dispatchAcked ? false : (r[IX.zoneChanged] === true),

      timePrev:  toIso(r[IX.timePrev], tz),
      timeDelta: (r[IX.timeDelta] ?? "").toString(),
      timeChgAt: toIso(r[IX.timeChgAt], tz),
    };

    const avgKey = buildFlightKey(obj.type, obj.flight);
    const avg = avgKey ? avgMap.get(avgKey) : null;
    obj.avgPrm30 = avg?.avgPrm30 ?? null;
    obj.avgN30 = avg?.avgN30 ?? null;

    const terminal = inferTerminalFromRow(obj);
    const { airline, flightNumber, cleaned } = parseFlightParts(obj.flight);
    const flightStr = airline && flightNumber ? `${airline}${flightNumber}` : cleaned;
    const countsKey = `${opsDateYmd}|${normalizeType(obj.type)}|${terminal}|${flightStr}`;
    const counts = countsMap.get(countsKey);
    obj.scanned_count = counts?.scanned_count ?? 0;
    const paxValue = toNumber(obj.pax);
    obj.scan_rate = (paxValue && paxValue > 0) ? (obj.scanned_count / paxValue) : null;

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
  const avgMap = await getAvg30dMap(env);

  const tz = env.TIMEZONE || DEFAULT_TZ;   // moved OUT of the loop
  const win = operationalWindow(env, opsDay);
  const opsDateYmd = win.opsDateYmd;
  const countsMap = await getPrmgoCountsMap(env, opsDay);

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

    const obj = {
      key:        String(r[IX.key] || ""),
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

      alert: ackedHere ? "" : String(r[IX.alertText] || ""),

      gateChanged: ackedHere ? false : (r[IX.gateChanged] === true),
      timeChanged: ackedHere ? false : (r[IX.timeChanged] === true),
      zoneChanged: ackedHere ? false : (r[IX.zoneChanged] === true),

      zoneFrom,
      zoneTo,
    };

    const avgKey = buildFlightKey(obj.type, obj.flight);
    const avg = avgKey ? avgMap.get(avgKey) : null;
    obj.avgPrm30 = avg?.avgPrm30 ?? null;
    obj.avgN30 = avg?.avgN30 ?? null;

    const terminal = inferTerminalFromRow(obj);
    const { airline, flightNumber, cleaned } = parseFlightParts(obj.flight);
    const flightStr = airline && flightNumber ? `${airline}${flightNumber}` : cleaned;
    const countsKey = `${opsDateYmd}|${normalizeType(obj.type)}|${terminal}|${flightStr}`;
    const counts = countsMap.get(countsKey);
    obj.scanned_count = counts?.scanned_count ?? 0;
    const paxValue = toNumber(obj.pax);
    obj.scan_rate = (paxValue && paxValue > 0) ? (obj.scanned_count / paxValue) : null;

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

// ---------- Mgmt pre-alerts ----------
const MGMT_ZONE_ORDER = ["TB", "Gates", "Pier A", "T1", "Unassigned"];

function parseNumber(v) {
  if (v == null || v === "") return 0;
  const n = Number(v);
  return Number.isFinite(n) ? n : 0;
}

function mgmtZoneList(seenZones) {
  const extras = Array.from(seenZones).filter(z => !MGMT_ZONE_ORDER.includes(z));
  extras.sort((a, b) => a.localeCompare(b));
  return [...MGMT_ZONE_ORDER, ...extras];
}

async function mgmtPrealerts(env, params) {
  const bucketMinRaw = parseInt(params.bucketMin || "15", 10);
  const bucketMin = Number.isFinite(bucketMinRaw) && bucketMinRaw > 0 ? bucketMinRaw : 15;
  const zoneWanted = normalizeZone(params.zone || "ALL") || "ALL";
  const typeFilter = String(params.type || "ALL").toUpperCase();
  const q = String(params.q || "").trim().toUpperCase().replace(/\s+/g, "");

  const tz = env.TIMEZONE || DEFAULT_TZ;
  const win = computeMgmtWindowToronto(new Date());
  const rows = await getDbRows(env);

  const bucketMs = bucketMin * 60_000;
  const buckets = new Map(); // bucketMs -> { byZone, total }
  const timeTotals = new Map(); // bucketMs -> prm
  const zoneTotals = {};
  const flights = [];
  const zoneSet = new Set();

  let totalWchr = 0;
  let totalWchc = 0;
  let totalPrm = 0;

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

    const wchr = parseNumber(r[IX.wchr]);
    const wchc = parseNumber(r[IX.wchc]);
    const prm = wchr + wchc;
    if (prm <= 0) continue;

    let zone = normalizeZone(r[IX.zoneCur] || "");
    if (!zone) zone = "Unassigned";
    if (zoneWanted !== "ALL" && zone !== zoneWanted) continue;

    let planMs = dt.getTime();
    if (rowType === "DEP") {
      const dest = String(r[IX.origin] || "").trim().toUpperCase();
      const offsetMin = dest.startsWith("Y") ? 60 : 90;
      planMs -= offsetMin * 60_000;
    }

    const bucketStartMs = Math.floor(planMs / bucketMs) * bucketMs;
    let bucket = buckets.get(bucketStartMs);
    if (!bucket) {
      bucket = { byZone: {}, total: 0 };
      buckets.set(bucketStartMs, bucket);
    }

    bucket.byZone[zone] = (bucket.byZone[zone] || 0) + prm;
    bucket.total += prm;

    timeTotals.set(bucketStartMs, (timeTotals.get(bucketStartMs) || 0) + prm);
    zoneTotals[zone] = (zoneTotals[zone] || 0) + prm;
    zoneSet.add(zone);

    totalWchr += wchr;
    totalWchc += wchc;
    totalPrm += prm;

    flights.push({
      plan: formatTimeOnly(new Date(planMs), tz),
      est: formatTimeOnly(dt, tz),
      flight,
      type: rowType,
      gate: String(r[IX.gate] || ""),
      zone,
      wchr,
      wchc,
      prm,
    });
  }

  flights.sort((a, b) => {
    if (a.plan === b.plan) return a.flight.localeCompare(b.flight);
    return a.plan.localeCompare(b.plan);
  });

  const zones = mgmtZoneList(zoneSet);
  const bucketEntries = Array.from(buckets.entries()).sort((a, b) => a[0] - b[0]);
  const heatRows = bucketEntries.map(([bucketMsStart, bucket]) => {
    const byZone = {};
    for (const z of zones) byZone[z] = bucket.byZone[z] || 0;
    return {
      bucket: formatTimeOnly(new Date(bucketMsStart), tz),
      byZone,
      total: bucket.total,
    };
  });

  const timeTotalsArr = Array.from(timeTotals.entries())
    .sort((a, b) => a[0] - b[0])
    .map(([bucketMsStart, prm]) => ({
      bucket: formatTimeOnly(new Date(bucketMsStart), tz),
      prm,
    }));

  const bucketKeys = heatRows.map(row => row.bucket);

  return {
    ok: true,
    generatedAt: new Date().toISOString(),
    window: { startISO: win.startISO, endISO: win.endISO },
    params: { bucketMin, zone: zoneWanted, type: typeFilter, q },
    kpis: { wchr: totalWchr, wchc: totalWchc, prm: totalPrm, flights: flights.length },
    zones,
    bucketKeys,
    heatRows,
    zoneTotals,
    timeTotals: timeTotalsArr,
    flights,
  };
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

// ---------- Flight 30-day rolling averages ----------
const DAILY_STATS_HEADER = ["date", "key", "sum_prm", "sum_wchr", "sum_wchc", "n", "updated_at"];
const AVG_30D_HEADER = ["key", "avg_prm_30d", "avg_wchr_30d", "avg_wchc_30d", "n_30d", "window_start", "window_end", "updated_at"];

async function ensureFlightStatsSheets(env) {
  const dailySheet = env.FLIGHT_DAILY_STATS_SHEET_NAME || "flight_daily_stats";
  const avgSheet = env.FLIGHT_AVG_30D_SHEET_NAME || "flight_avg_30d";
  const sid = env.SPREADSHEET_ID;

  const meta = await sheetsGetSpreadsheetMeta(env, sid);
  const existing = new Set((meta.sheets || []).map(s => s.properties?.title).filter(Boolean));

  const requests = [];
  if (!existing.has(dailySheet)) requests.push({ addSheet: { properties: { title: dailySheet } } });
  if (!existing.has(avgSheet)) requests.push({ addSheet: { properties: { title: avgSheet } } });
  if (requests.length) await sheetsBatchUpdateSpreadsheet(env, sid, requests);

  const updates = [];
  if (!existing.has(dailySheet)) {
    updates.push({ range: `${dailySheet}!A1:G1`, values: [DAILY_STATS_HEADER] });
  }
  if (!existing.has(avgSheet)) {
    updates.push({ range: `${avgSheet}!A1:H1`, values: [AVG_30D_HEADER] });
    updates.push({ range: `${avgSheet}!J1`, values: [["last_run_date"]] });
  }
  if (updates.length) await sheetsBatchUpdate(env, updates);
}

function parseArchiveHeaders(headerRow) {
  const map = {};
  (headerRow || []).forEach((h, idx) => {
    const key = String(h || "").trim().toLowerCase();
    if (key) map[key] = idx;
  });
  return {
    type: map.type,
    flight: map.flight,
    wchr: map.wchr,
    wchc: map.wchc,
  };
}

async function loadArchiveDaily(env, targetDate) {
  const archivesId = env.ARCHIVES_SPREADSHEET_ID;
  if (!archivesId) throw new Error("Missing ARCHIVES_SPREADSHEET_ID.");
  const values = await sheetsGetValuesFor(env, archivesId, `${targetDate}!A1:Q`);
  if (!values.length) return { rows: [], keys: 0 };

  const header = values[0];
  const idx = parseArchiveHeaders(header);
  if (idx.type == null || idx.flight == null || idx.wchr == null || idx.wchc == null) {
    throw new Error(`Archive sheet ${targetDate} missing required headers.`);
  }

  const byKey = new Map();
  for (let i = 1; i < values.length; i++) {
    const row = values[i] || [];
    const type = String(row[idx.type] || "").trim();
    const flight = String(row[idx.flight] || "").trim();
    if (!type || !flight) continue;

    const wchr = parseNumber(row[idx.wchr]);
    const wchc = parseNumber(row[idx.wchc]);
    const prm = wchr + wchc;
    if (prm <= 0) continue;

    const key = buildFlightKey(type, flight);
    if (!key) continue;
    const entry = byKey.get(key) || { sumPrm: 0, sumWchr: 0, sumWchc: 0, n: 0 };
    entry.sumPrm += prm;
    entry.sumWchr += wchr;
    entry.sumWchc += wchc;
    entry.n += 1;
    byKey.set(key, entry);
  }

  const updatedAt = new Date().toISOString();
  const rows = Array.from(byKey.entries()).map(([key, entry]) => ([
    targetDate,
    key,
    entry.sumPrm,
    entry.sumWchr,
    entry.sumWchc,
    entry.n,
    updatedAt,
  ]));
  return { rows, keys: byKey.size };
}

async function updateDailyStats(env, targetDate, dailyRows, tz) {
  const sheet = env.FLIGHT_DAILY_STATS_SHEET_NAME || "flight_daily_stats";
  const existing = await sheetsGetValues(env, `${sheet}!A1:G`);
  const existingRows = existing.slice(1);

  const targetParts = parseYmd(targetDate);
  const pruneDate = targetParts ? formatYmd(addDaysLocal(targetParts, -40, tz)) : "";

  const kept = [];
  for (const row of existingRows) {
    const date = String(row?.[0] ?? "").trim();
    const key = String(row?.[1] ?? "").trim();
    if (!date || !key) continue;
    if (pruneDate && date < pruneDate) continue;
    if (date === targetDate) continue;
    kept.push(row.slice(0, 7));
  }

  const combined = [...kept, ...dailyRows];
  combined.sort((a, b) => {
    const dateA = String(a?.[0] ?? "");
    const dateB = String(b?.[0] ?? "");
    if (dateA === dateB) return String(a?.[1] ?? "").localeCompare(String(b?.[1] ?? ""));
    return dateA.localeCompare(dateB);
  });

  await sheetsClearValuesFor(env, env.SPREADSHEET_ID, `${sheet}!A:G`);
  const updates = [{ range: `${sheet}!A1:G1`, values: [DAILY_STATS_HEADER] }];
  if (combined.length) updates.push({ range: `${sheet}!A2:G`, values: combined });
  await sheetsBatchUpdate(env, updates);
  return combined;
}

async function updateAvg30d(env, targetDate, dailyRows, tz) {
  const sheet = env.FLIGHT_AVG_30D_SHEET_NAME || "flight_avg_30d";
  const targetParts = parseYmd(targetDate);
  if (!targetParts) throw new Error(`Invalid targetDate: ${targetDate}`);

  const windowStart = formatYmd(addDaysLocal(targetParts, -29, tz));
  const windowEnd = targetDate;

  const agg = new Map();
  for (const row of dailyRows) {
    const date = String(row?.[0] ?? "").trim();
    if (!date || date < windowStart || date > windowEnd) continue;
    const key = String(row?.[1] ?? "").trim();
    if (!key) continue;

    const sumPrm = parseNumber(row?.[2]);
    const sumWchr = parseNumber(row?.[3]);
    const sumWchc = parseNumber(row?.[4]);
    const n = parseNumber(row?.[5]);
    if (n <= 0) continue;

    const entry = agg.get(key) || { sumPrm: 0, sumWchr: 0, sumWchc: 0, n: 0 };
    entry.sumPrm += sumPrm;
    entry.sumWchr += sumWchr;
    entry.sumWchc += sumWchc;
    entry.n += n;
    agg.set(key, entry);
  }

  const updatedAt = new Date().toISOString();
  const rows = Array.from(agg.entries()).map(([key, entry]) => ([
    key,
    Number((entry.sumPrm / entry.n).toFixed(2)),
    Number((entry.sumWchr / entry.n).toFixed(2)),
    Number((entry.sumWchc / entry.n).toFixed(2)),
    entry.n,
    windowStart,
    windowEnd,
    updatedAt,
  ]));

  rows.sort((a, b) => Number(b[1]) - Number(a[1]) || String(a[0]).localeCompare(String(b[0])));

  await sheetsClearValuesFor(env, env.SPREADSHEET_ID, `${sheet}!A:H`);
  const updates = [
    { range: `${sheet}!A1:H1`, values: [AVG_30D_HEADER] },
  ];
  if (rows.length) updates.push({ range: `${sheet}!A2:H`, values: rows });
  updates.push({ range: `${sheet}!J1`, values: [["last_run_date"]] });
  updates.push({ range: `${sheet}!J2`, values: [[targetDate]] });
  await sheetsBatchUpdate(env, updates);

  _avgCache.map = null;
  _avgCache.ts = 0;

  return { rowsWritten: rows.length, keys: agg.size, windowStart, windowEnd };
}

function getDefaultTargetDate(tz) {
  const now = new Date();
  const todayParts = getTzParts(now, tz);
  const targetParts = addDaysLocal({ year: todayParts.year, month: todayParts.month, day: todayParts.day }, -1, tz);
  return formatYmd(targetParts);
}

async function writeDailyStatsSheet(env, rows) {
  const sheet = env.FLIGHT_DAILY_STATS_SHEET_NAME || "flight_daily_stats";
  await sheetsClearValuesFor(env, env.SPREADSHEET_ID, `${sheet}!A:G`);
  const updates = [{ range: `${sheet}!A1:G1`, values: [DAILY_STATS_HEADER] }];
  if (rows.length) updates.push({ range: `${sheet}!A2:G`, values: rows });
  await sheetsBatchUpdate(env, updates);
}

async function backfillFlightAvg(env, options) {
  const tz = env.TIMEZONE || DEFAULT_TZ;
  const daysRaw = parseInt(options?.days ?? "", 10);
  const days = Math.min(Math.max(Number.isFinite(daysRaw) ? daysRaw : 30, 1), 60);
  const endDate = options?.endDate || getDefaultTargetDate(tz);
  const endParts = parseYmd(endDate);
  if (!endParts) throw new Error("Invalid end date format. Use YYYY-MM-DD.");

  await ensureFlightStatsSheets(env);

  const dailySheet = env.FLIGHT_DAILY_STATS_SHEET_NAME || "flight_daily_stats";
  const existing = await sheetsGetValues(env, `${dailySheet}!A1:G`);
  const existingRows = existing.slice(1).map(row => row.slice(0, 7));
  const existingDates = new Set(
    existingRows.map(row => String(row?.[0] ?? "").trim()).filter(Boolean)
  );

  const combined = [...existingRows];
  const startParts = addDaysLocal(endParts, -(days - 1), tz);

  let datesProcessed = 0;
  let datesSkipped = 0;
  for (let i = 0; i < days; i++) {
    const date = formatYmd(addDaysLocal(startParts, i, tz));
    if (existingDates.has(date)) {
      datesSkipped += 1;
      continue;
    }
    const daily = await loadArchiveDaily(env, date);
    if (daily.rows.length) {
      combined.push(...daily.rows);
    }
    datesProcessed += 1;
  }

  const pruneDate = formatYmd(addDaysLocal(endParts, -40, tz));
  const pruned = combined.filter(row => {
    const date = String(row?.[0] ?? "").trim();
    const key = String(row?.[1] ?? "").trim();
    if (!date || !key) return false;
    return date >= pruneDate;
  });

  pruned.sort((a, b) => {
    const dateA = String(a?.[0] ?? "");
    const dateB = String(b?.[0] ?? "");
    if (dateA === dateB) return String(a?.[1] ?? "").localeCompare(String(b?.[1] ?? ""));
    return dateA.localeCompare(dateB);
  });

  await writeDailyStatsSheet(env, pruned);
  const avg = await updateAvg30d(env, endDate, pruned, tz);

  return {
    ok: true,
    windowStart: avg.windowStart,
    windowEnd: avg.windowEnd,
    datesProcessed,
    datesSkipped,
    rowsWrittenAvg: avg.rowsWritten,
    dailyRowsTotal: pruned.length,
  };
}

async function updateFlightAvgForDate(env, targetDate, tz) {
  const daily = await loadArchiveDaily(env, targetDate);
  const dailyRows = await updateDailyStats(env, targetDate, daily.rows, tz);
  const avg = await updateAvg30d(env, targetDate, dailyRows, tz);

  return {
    rowsWritten: avg.rowsWritten,
    keys: daily.keys,
    windowStart: avg.windowStart,
    windowEnd: avg.windowEnd,
  };
}

async function runFlightAvgJob(env, targetDateOverride) {
  const tz = env.TIMEZONE || DEFAULT_TZ;
  let targetDate = targetDateOverride;
  if (!targetDate) {
    targetDate = getDefaultTargetDate(tz);
  }

  await ensureFlightStatsSheets(env);

  const avgSheet = env.FLIGHT_AVG_30D_SHEET_NAME || "flight_avg_30d";
  const lastRun = await sheetsGetValues(env, `${avgSheet}!J2:J2`);
  const lastRunDate = String(lastRun?.[0]?.[0] ?? "").trim();
  if (!targetDateOverride && lastRunDate === targetDate) {
    return { ok: true, skipped: true, processedDate: targetDate };
  }

  const avg = await updateFlightAvgForDate(env, targetDate, tz);

  return {
    ok: true,
    processedDate: targetDate,
    rowsWritten: avg.rowsWritten,
    keys: avg.keys,
    windowStart: avg.windowStart,
    windowEnd: avg.windowEnd,
  };
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

      // ---- mgmt ----
      if (path === "/mgmt/prealerts" && req.method === "GET") {
        await requireAuth(req, env, "mgmt");
        const params = {
          bucketMin: url.searchParams.get("bucketMin") || "15",
          zone: url.searchParams.get("zone") || "ALL",
          type: url.searchParams.get("type") || "ALL",
          q: url.searchParams.get("q") || "",
        };
        const out = await mgmtPrealerts(env, params);
        return withCors(json(out), origin);
      }

      if (path === "/jobs/flight-avg/run" && req.method === "GET") {
        await requireAuth(req, env, "mgmt");
        const date = String(url.searchParams.get("date") || "").trim();
        if (date && !parseYmd(date)) {
          return withCors(json({ ok:false, error:"Invalid date format. Use YYYY-MM-DD." }, { status: 400 }), origin);
        }
        const out = await runFlightAvgJob(env, date || null);
        return withCors(json(out), origin);
      }

      if (path === "/jobs/flight-avg/backfill" && req.method === "GET") {
        await requireAuth(req, env, "mgmt");
        const daysParam = String(url.searchParams.get("days") || "").trim();
        const endParam = String(url.searchParams.get("end") || "").trim();
        if (endParam && !parseYmd(endParam)) {
          return withCors(json({ ok:false, error:"Invalid end date format. Use YYYY-MM-DD." }, { status: 400 }), origin);
        }
        const out = await backfillFlightAvg(env, {
          days: daysParam || null,
          endDate: endParam || null,
        });
        return withCors(json(out), origin);
      }

      return withCors(json({ ok:false, error:"Not found" }, { status: 404 }), origin);

    } catch (err) {
      const msg = (err && err.message) ? err.message : String(err);
      return withCors(json({ ok:false, error: msg }, { status: /missing authorization|unauthorized|expired|no access/i.test(msg) ? 401 : 500 }), origin);
    }
  },
  async scheduled(event, env, ctx) {
    const tz = "America/Toronto";
    const now = new Date();
    const parts = getTzParts(now, tz);
    if (parts.hour !== 4) return;

    const targetDate = formatYmd(addDaysLocal({
      year: parts.year,
      month: parts.month,
      day: parts.day,
    }, -1, tz));

    await ensureFlightStatsSheets(env);

    const avgSheet = env.FLIGHT_AVG_30D_SHEET_NAME || "flight_avg_30d";
    const lastRun = await sheetsGetValues(env, `${avgSheet}!J2:J2`);
    const lastRunDate = String(lastRun?.[0]?.[0] ?? "").trim();
    if (lastRunDate === targetDate) return;

    ctx.waitUntil(updateFlightAvgForDate(env, targetDate, tz));
  }
};
