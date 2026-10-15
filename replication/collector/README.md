# OpenHookbin

Request bin + webhook inspector with live console, historical API, Neon storage, and 30-day TTL cleanup.

## Routes

- Webhook ingest: `/{binId}` and `/{binId}/...`
- Console: `/console/{binId}`
- Logs API: `/api/{binId}`
- SSE stream: `/api/stream/{binId}`
- Cleanup endpoint (cron): `/api/internal/cleanup`

## Setup

1. Install dependencies:

```bash
npm install
```

2. Configure environment variables:

```bash
cp .env.example .env.local
```

Set:
- `DATABASE_URL`: Neon pooled connection string
- `CRON_SECRET`: shared secret used by Vercel Cron

3. Create schema in Neon using `db/schema.sql`.
4. Run locally:

```bash
npm run dev
```

## Deployment (Vercel + Neon)

1. Create Neon project (free plan) and copy pooled `DATABASE_URL`.
2. Deploy this repo to Vercel.
3. Add `DATABASE_URL` and `CRON_SECRET` in Vercel environment variables.
4. Keep `vercel.json` cron (`0 0 * * *`) to trigger cleanup daily (Vercel Hobby-compatible).

If `CRON_SECRET` is set, Vercel sends `Authorization: Bearer <CRON_SECRET>` for cron requests automatically.

Expired rows are still hidden immediately by read-time filtering (`last 30 days`), and writes also run opportunistic cleanup. The daily cron handles bulk physical deletion.

## API response

`GET /api/{binId}?limit=100&before=<ISO>`

```json
{
  "binId": "demo",
  "items": [],
  "nextBefore": null
}
```

`nextBefore` is set when more pages may exist.
