# PRM Operations Portal

This repository pairs a Cloudflare Worker API with a lightweight static frontend for PRM (Passenger Required Mobility) operations. Google Sheets is treated as the system of record, while the Worker provides authenticated JSON endpoints and the static pages poll those endpoints for dispatch and lead workflows.

## Project layout

- **api/** – Cloudflare Worker code that exposes authentication, dispatch, and lead APIs backed by Google Sheets. `wrangler.toml` configures deployment.
- **web/** – Static HTML/CSS/JS pages for login, dispatch, and lead views. `config.js` points the frontend at the deployed Worker.

## Worker API (api/src/index.js)

The Worker fronts a single Google Spreadsheet whose sheets hold user credentials and the dispatch database. Key behaviors:

- **Auth** – `/auth/login` verifies username + PIN against a `USERS` sheet and issues short-lived HMAC tokens; `/auth/validate` checks token validity and app access level (dispatch vs. lead).【F:api/src/index.js†L250-L312】【F:api/src/index.js†L511-L555】【F:api/src/index.js†L917-L944】
- **Dispatch flows** – `/dispatch/rows` returns a filtered snapshot of dispatch records with per-zone alert flags; `/dispatch/update` writes WCHR/WCHC/comment updates back to the sheet while maintaining previous value columns; `/dispatch/ack` clears dispatch alerts for a record.【F:api/src/index.js†L578-L639】【F:api/src/index.js†L742-L848】【F:api/src/index.js†L925-L944】
- **Lead flows** – `/lead/init` exposes zone metadata; `/lead/rows` filters rows by zone/type/query and applies per-zone acknowledgement logic; `/lead/update` writes assignment/pax counts with audit columns; `/lead/ack` records acknowledgements per zone.【F:api/src/index.js†L647-L739】【F:api/src/index.js†L810-L898】【F:api/src/index.js†L946-L975】
- **Ops + sync controls** – `/ops/now` returns Toronto-local time parts and banner hints (no auth). `/admin/refresh` runs the scheduled FIDS sync on demand for lens 1, lens 2, or both (Mgmt-only).【F:api/src/index.js†L909-L1007】
- **Caching + patches** – Short-lived caches smooth Google Sheets reads, and write-through “patches” keep the UI responsive while Sheets updates propagate.【F:api/src/index.js†L439-L524】【F:api/src/index.js†L842-L898】
- **Environment** – Requires spreadsheet IDs and service account credentials; `AUTH_SECRET` signs HMAC tokens. Defaults assume sheet names `Dispatch_DB` and `USERS`. See the header block in `index.js` for required variables.【F:api/src/index.js†L1-L44】

Run locally with Wrangler from `api/`:

```sh
npm install
npm run dev
```

Set the required environment variables/secrets via `wrangler.toml` and `wrangler secret put` before deploying.

### Secrets and FIDS sync

The scheduled sync (and `/admin/refresh`) pull FIDS data from AeroDataBox via RapidAPI and upsert it into `Dispatch_DB`. Configure these secrets in the Worker:

- `AERODATABOX_KEY` (RapidAPI key)
- `AERODATABOX_HOST` (optional, defaults to `aerodatabox.p.rapidapi.com`)
- `GOOGLE_PRIVATE_KEY`, `AUTH_SECRET`, and existing Google Sheets secrets

Optional variables:

- `FIDS_AIRPORT_ICAO` (defaults to `CYYZ`)

Manual refresh example (Mgmt-only):

```sh
curl -X POST \"$API_BASE/admin/refresh\" \\
  -H \"authorization: Bearer $TOKEN\" \\
  -H \"content-type: application/json\" \\
  -d '{\"lens\":\"both\"}'
```

## Frontend (web/)

Static pages poll the Worker API and manage local auth tokens stored in `localStorage`:

- **Login (index.html)** – Captures username and PIN, calls `/auth/login`, and stores the returned token for subsequent pages.【F:web/index.html†L190-L273】
- **Dispatch dashboard (dispatch.html)** – Authenticates via `/auth/validate?app=dispatch`, polls `/dispatch/rows`, lets dispatchers edit WCHR/WCHC/comments, and posts acks/updates back to the API. Auto-refresh backs off on errors and pauses while typing a search query.【F:web/dispatch.html†L1-L172】【F:web/dispatch.html†L174-L326】
- **Lead dashboard (lead.html)** – Similar polling flow for lead users, with zone/type filters, assignment/pax editing, and per-zone acknowledgements via the lead endpoints.【F:web/lead.html†L1-L152】【F:web/lead.html†L199-L335】
- **Config (config.js)** – `API_BASE` must point to the deployed Worker URL for the frontend to reach the API.【F:web/config.js†L1-L7】

## Deployment notes

- Host the `web/` directory on Cloudflare Pages or any static host; ensure `config.js` references the live Worker URL.
- Provision the required Google service account and share the spreadsheet with it so read/write calls succeed.
- Tokens are short-lived and HMAC-signed; keep `AUTH_SECRET` and Google private key in Worker secrets.
