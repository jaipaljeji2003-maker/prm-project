const DEFAULT_AIRPORT_ICAO = "CYYZ";
const DEFAULT_HOST = "aerodatabox.p.rapidapi.com";
const PAGE_LIMIT = 100;

function cleanString(value) {
  return String(value ?? "").trim();
}

function isCodeshareFlight(flight) {
  if (!flight || typeof flight !== "object") return false;
  if (flight.isCodeshare === true) return true;
  if (flight.codeshareStatus && String(flight.codeshareStatus).toLowerCase() !== "main") return true;
  if (flight.number && typeof flight.number === "object" && flight.number.isCodeshare === true) return true;
  return false;
}

function pickFlightNumber(flight) {
  if (!flight) return "";
  if (typeof flight.number === "string") return cleanString(flight.number);
  if (flight.number && typeof flight.number === "object") {
    return cleanString(flight.number.default || flight.number.iata || flight.number.icao || flight.number.number || "");
  }
  return cleanString(flight.flightNumber || flight.flight || "");
}

function pickMovement(flight, direction) {
  return direction === "ARR" ? flight.arrival : flight.departure;
}

function pickOtherAirport(flight, direction) {
  const other = direction === "ARR" ? flight.departure : flight.arrival;
  return other?.airport?.iata || other?.airport?.icao || other?.airport?.name || "";
}

function pickGate(movement) {
  return cleanString(movement?.gate || movement?.gateNumber || movement?.terminal?.gate || "");
}

function pickTime(movement, fallback) {
  return cleanString(
    movement?.estimatedTimeLocal ||
    movement?.estimatedTimeUtc ||
    movement?.estimatedTime ||
    fallback ||
    ""
  );
}

function pickSched(movement) {
  return cleanString(
    movement?.scheduledTimeLocal ||
    movement?.scheduledTimeUtc ||
    movement?.scheduledTime ||
    ""
  );
}

function formatParts(parts) {
  const y = String(parts.year).padStart(4, "0");
  const m = String(parts.month).padStart(2, "0");
  const d = String(parts.day).padStart(2, "0");
  const hh = String(parts.hour).padStart(2, "0");
  const mm = String(parts.minute).padStart(2, "0");
  return `${y}-${m}-${d}T${hh}:${mm}`;
}

function buildKeyFromRecord(record, opDateYmd, parseDbTime, getTzParts, tz) {
  const dt = parseDbTime(record.schedTimeLocal || record.timeEst || "", tz);
  let hhmm = "0000";
  if (dt) {
    const parts = getTzParts(dt, tz);
    hhmm = `${String(parts.hour).padStart(2, "0")}${String(parts.minute).padStart(2, "0")}`;
  }
  return `${opDateYmd}-${record.type}-${record.flight}-${hhmm}`;
}

function makeSignature(record, parseDbTime, tz) {
  const sched = parseDbTime(record.schedTimeLocal || record.timeEst || "", tz);
  const stamp = sched ? sched.toISOString().slice(0, 16) : cleanString(record.schedTimeLocal || record.timeEst);
  return `${record.type}|${record.flight}|${stamp}`;
}

async function fetchFlightsPage(env, airportIcao, fromLocal, toLocal, direction, offset) {
  const host = env.AERODATABOX_HOST || DEFAULT_HOST;
  const key = env.AERODATABOX_KEY || "";
  if (!key) throw new Error("Missing AERODATABOX_KEY secret.");

  const url = new URL(`https://${host}/flights/airports/icao/${airportIcao}/${fromLocal}/${toLocal}`);
  url.searchParams.set("withLeg", "true");
  url.searchParams.set("direction", direction === "ARR" ? "arrivals" : "departures");
  url.searchParams.set("limit", String(PAGE_LIMIT));
  url.searchParams.set("offset", String(offset));

  const resp = await fetch(url.toString(), {
    headers: {
      "x-rapidapi-host": host,
      "x-rapidapi-key": key,
    },
  });

  const data = await resp.json();
  if (!resp.ok) {
    throw new Error(`AeroDataBox error: ${data?.message || resp.status}`);
  }

  const flights = Array.isArray(data?.flights) ? data.flights : (Array.isArray(data) ? data : []);
  return flights;
}

async function fetchFlightsForWindow(env, window, getTzParts, direction) {
  const airportIcao = env.FIDS_AIRPORT_ICAO || DEFAULT_AIRPORT_ICAO;
  const fromLocal = formatParts(getTzParts(window.startUtc, env.TIMEZONE || "America/Toronto"));
  const toLocal = formatParts(getTzParts(window.endUtc, env.TIMEZONE || "America/Toronto"));

  const all = [];
  let offset = 0;
  while (true) {
    const page = await fetchFlightsPage(env, airportIcao, fromLocal, toLocal, direction, offset);
    all.push(...page);
    if (page.length < PAGE_LIMIT) break;
    offset += PAGE_LIMIT;
  }
  return all;
}

function normalizeFlightRecord(flight, direction) {
  if (isCodeshareFlight(flight)) return null;
  const movement = pickMovement(flight, direction);
  const sched = pickSched(movement);
  const timeEst = pickTime(movement, sched);

  const record = {
    type: direction,
    flight: pickFlightNumber(flight),
    schedTimeLocal: sched,
    timeEst,
    originDest: pickOtherAirport(flight, direction),
    gate: pickGate(movement),
  };

  if (!record.flight || !record.timeEst) return null;
  return record;
}

function detectChange(oldValue, newValue) {
  const oldStr = cleanString(oldValue);
  const newStr = cleanString(newValue);
  if (!newStr) return false;
  return oldStr !== newStr;
}

function detectTimeChange(oldValue, newValue, parseDbTime, tz) {
  const oldDt = parseDbTime(oldValue, tz);
  const newDt = parseDbTime(newValue, tz);
  if (!newDt) return false;
  if (!oldDt) return true;
  return oldDt.getTime() !== newDt.getTime();
}

function calcTimeDeltaMinutes(oldValue, newValue, parseDbTime, tz) {
  const oldDt = parseDbTime(oldValue, tz);
  const newDt = parseDbTime(newValue, tz);
  if (!oldDt || !newDt) return "";
  return Math.round((newDt.getTime() - oldDt.getTime()) / 60000);
}

function pickHeaderName(headerMap, names) {
  for (const name of names) {
    if (headerMap[name]) return name;
  }
  return null;
}

function buildRowArray(headerMap, maxCol) {
  return Array.from({ length: maxCol }, () => "");
}

export async function syncFidsToDispatchDb(env, { lens, window, helpers }) {
  const { getHeaderMap, getKeyIndex, getDbRows, sheetsBatchUpdate, colToA1, parseDbTime, getTzParts, normalizeZone } = helpers;
  const tz = env.TIMEZONE || "America/Toronto";
  const sheet = env.DISPATCH_DB_SHEET_NAME || "Dispatch_DB";

  const [headerMap, keyIndex, rows] = await Promise.all([
    getHeaderMap(env),
    getKeyIndex(env),
    getDbRows(env),
  ]);

  const maxCol = Math.max(1, ...Object.values(headerMap));
  const existingRowByKey = new Map();
  const signatureToKey = new Map();

  for (const row of rows) {
    const key = cleanString(row?.[0]);
    if (!key) continue;
    existingRowByKey.set(key, row);
    const type = cleanString(row?.[1]);
    const flight = cleanString(row?.[2]);
    const timeVal = row?.[3];
    if (type && flight && timeVal != null) {
      const sig = makeSignature({ type, flight, timeEst: timeVal }, parseDbTime, tz);
      if (!signatureToKey.has(sig)) signatureToKey.set(sig, key);
    }
  }

  const [arrivals, departures] = await Promise.all([
    fetchFlightsForWindow(env, window, getTzParts, "ARR"),
    fetchFlightsForWindow(env, window, getTzParts, "DEP"),
  ]);

  const records = [...arrivals.map(f => normalizeFlightRecord(f, "ARR")), ...departures.map(f => normalizeFlightRecord(f, "DEP"))]
    .filter(Boolean);

  const updates = [];
  let appended = 0;
  let updated = 0;

  const colKey = headerMap.Key || 1;
  const colType = pickHeaderName(headerMap, ["Type"]);
  const colFlight = pickHeaderName(headerMap, ["Flight"]);
  const colTime = pickHeaderName(headerMap, ["Time", "Time_Est", "TimeEst"]);
  const colSched = pickHeaderName(headerMap, ["Sched", "Scheduled"]);
  const colOrigin = pickHeaderName(headerMap, ["Origin", "Origin/Dest", "OriginDest"]);
  const colGate = pickHeaderName(headerMap, ["Gate"]);
  const colZone = pickHeaderName(headerMap, ["Zone", "Zone_Cur", "ZoneCur", "Zone_Current"]);
  const colGateChanged = pickHeaderName(headerMap, ["GateChanged", "Gate_Changed"]);
  const colTimeChanged = pickHeaderName(headerMap, ["TimeChanged", "Time_Changed"]);
  const colTimePrev = pickHeaderName(headerMap, ["TimePrev", "Time_Prev", "PrevTime"]);
  const colTimeDelta = pickHeaderName(headerMap, ["TimeDelta", "Time_Delta"]);
  const colTimeChgAt = pickHeaderName(headerMap, ["TimeChgAt", "TimeChangedAt", "Time_Changed_At"]);
  const colZoneChanged = pickHeaderName(headerMap, ["ZoneChanged", "Zone_Changed"]);
  const colZoneFrom = pickHeaderName(headerMap, ["ZoneFrom", "Zone_From"]);
  const colZoneTo = pickHeaderName(headerMap, ["ZoneTo", "Zone_To"]);

  const zoneAckMap = {
    "PIER A": "PierA_Ack",
    "TB": "TB_Ack",
    "GATES": "Gates_Ack",
    "T1": "T1_Ack",
    "UNASSIGNED": "Unassigned_Ack",
  };

  for (const record of records) {
    const signature = makeSignature(record, parseDbTime, tz);
    const existingKey = signatureToKey.get(signature);
    const key = existingKey || buildKeyFromRecord(record, window.opDateYmd, parseDbTime, getTzParts, tz);

    const rowNum = keyIndex.get(key);
    const row = rowNum ? existingRowByKey.get(key) : null;

    const oldGate = row ? row[(colGate ? headerMap[colGate] : 0) - 1] : "";
    const oldTime = row ? row[(colTime ? headerMap[colTime] : 0) - 1] : "";
    const oldZone = row ? row[(colZone ? headerMap[colZone] : 0) - 1] : "";

    const gateChanged = detectChange(oldGate, record.gate);
    const timeChanged = detectTimeChange(oldTime, record.timeEst, parseDbTime, tz);

    const newZoneRaw = colZone ? normalizeZone(record.zone || oldZone || "") : "";
    const zoneChanged = record.zone ? detectChange(oldZone, newZoneRaw) : false;

    const needsAckReset = gateChanged || timeChanged || zoneChanged;

    if (rowNum) {
      if (colType) updates.push({ range: `${sheet}!${colToA1(headerMap[colType])}${rowNum}`, values: [[record.type]] });
      if (colFlight) updates.push({ range: `${sheet}!${colToA1(headerMap[colFlight])}${rowNum}`, values: [[record.flight]] });
      if (colTime) updates.push({ range: `${sheet}!${colToA1(headerMap[colTime])}${rowNum}`, values: [[record.timeEst]] });
      if (colSched) updates.push({ range: `${sheet}!${colToA1(headerMap[colSched])}${rowNum}`, values: [[record.schedTimeLocal]] });
      if (colOrigin) updates.push({ range: `${sheet}!${colToA1(headerMap[colOrigin])}${rowNum}`, values: [[record.originDest]] });
      if (colGate) updates.push({ range: `${sheet}!${colToA1(headerMap[colGate])}${rowNum}`, values: [[record.gate]] });
      if (colZone && record.zone) updates.push({ range: `${sheet}!${colToA1(headerMap[colZone])}${rowNum}`, values: [[record.zone]] });

      if (gateChanged && colGateChanged) {
        updates.push({ range: `${sheet}!${colToA1(headerMap[colGateChanged])}${rowNum}`, values: [[true]] });
      }
      if (timeChanged && colTimeChanged) {
        updates.push({ range: `${sheet}!${colToA1(headerMap[colTimeChanged])}${rowNum}`, values: [[true]] });
      }
      if (timeChanged && colTimePrev) {
        updates.push({ range: `${sheet}!${colToA1(headerMap[colTimePrev])}${rowNum}`, values: [[oldTime ?? ""]] });
      }
      if (timeChanged && colTimeDelta) {
        updates.push({ range: `${sheet}!${colToA1(headerMap[colTimeDelta])}${rowNum}`, values: [[calcTimeDeltaMinutes(oldTime, record.timeEst, parseDbTime, tz)]] });
      }
      if (timeChanged && colTimeChgAt) {
        updates.push({ range: `${sheet}!${colToA1(headerMap[colTimeChgAt])}${rowNum}`, values: [[new Date().toISOString()]] });
      }
      if (zoneChanged && colZoneChanged) {
        updates.push({ range: `${sheet}!${colToA1(headerMap[colZoneChanged])}${rowNum}`, values: [[true]] });
      }
      if (zoneChanged && colZoneFrom) {
        updates.push({ range: `${sheet}!${colToA1(headerMap[colZoneFrom])}${rowNum}`, values: [[oldZone ?? ""]] });
      }
      if (zoneChanged && colZoneTo) {
        updates.push({ range: `${sheet}!${colToA1(headerMap[colZoneTo])}${rowNum}`, values: [[newZoneRaw ?? ""]] });
      }

      if (needsAckReset) {
        const dispatchAckCol = headerMap.Dispatch_Ack;
        if (dispatchAckCol) updates.push({ range: `${sheet}!${colToA1(dispatchAckCol)}${rowNum}`, values: [[false]] });

        const oldZoneNorm = normalizeZone(oldZone || "").toUpperCase();
        const newZoneNorm = normalizeZone(newZoneRaw || "").toUpperCase();
        const ackTargets = new Set([zoneAckMap[oldZoneNorm], zoneAckMap[newZoneNorm]].filter(Boolean));
        for (const colName of ackTargets) {
          const col = headerMap[colName];
          if (col) updates.push({ range: `${sheet}!${colToA1(col)}${rowNum}`, values: [[false]] });
        }
      }

      updated += 1;
      continue;
    }

    const rowValues = buildRowArray(headerMap, maxCol);
    rowValues[colKey - 1] = key;
    if (colType) rowValues[headerMap[colType] - 1] = record.type;
    if (colFlight) rowValues[headerMap[colFlight] - 1] = record.flight;
    if (colTime) rowValues[headerMap[colTime] - 1] = record.timeEst;
    if (colSched) rowValues[headerMap[colSched] - 1] = record.schedTimeLocal;
    if (colOrigin) rowValues[headerMap[colOrigin] - 1] = record.originDest;
    if (colGate) rowValues[headerMap[colGate] - 1] = record.gate;
    if (colZone && record.zone) rowValues[headerMap[colZone] - 1] = record.zone;

    const rowNumNew = rows.length + 2 + appended;
    updates.push({
      range: `${sheet}!A${rowNumNew}:${colToA1(maxCol)}${rowNumNew}`,
      values: [rowValues],
    });
    appended += 1;
  }

  if (updates.length) {
    await sheetsBatchUpdate(env, updates);
  }

  return {
    ok: true,
    lens,
    window: { startUtc: window.startUtc.toISOString(), endUtc: window.endUtc.toISOString(), opDateYmd: window.opDateYmd },
    totals: { records: records.length, updated, appended },
  };
}
