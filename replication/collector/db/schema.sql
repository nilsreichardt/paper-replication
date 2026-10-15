CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE TABLE IF NOT EXISTS requests (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  bin_id TEXT NOT NULL,
  method TEXT NOT NULL,
  path TEXT NOT NULL,
  query JSONB NOT NULL,
  headers JSONB NOT NULL,
  content_type TEXT,
  body_text TEXT,
  body_base64 TEXT,
  truncated BOOLEAN NOT NULL DEFAULT FALSE,
  received_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  expires_at TIMESTAMPTZ NOT NULL DEFAULT (NOW() + INTERVAL '30 days')
);

CREATE INDEX IF NOT EXISTS requests_bin_received_idx ON requests (bin_id, received_at DESC);
CREATE INDEX IF NOT EXISTS requests_expires_idx ON requests (expires_at);
