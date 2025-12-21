-- Device authentication for MCP
-- Allows users to authenticate MCP from IDE/terminal via a simple link

CREATE TABLE device_auth (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),

  -- Unique token for the auth link
  token TEXT NOT NULL UNIQUE,

  -- Once authenticated, links to user and stores their GitHub token
  user_id UUID REFERENCES auth.users(id) ON DELETE CASCADE,
  github_token TEXT,  -- Encrypted

  -- Status: pending, authenticated, expired, used
  status TEXT NOT NULL DEFAULT 'pending',

  -- Expiry (10 minutes from creation)
  expires_at TIMESTAMPTZ NOT NULL,

  -- Timestamps
  created_at TIMESTAMPTZ DEFAULT now(),
  authenticated_at TIMESTAMPTZ
);

CREATE INDEX idx_device_auth_token ON device_auth(token);
CREATE INDEX idx_device_auth_status ON device_auth(status);

-- No RLS needed - this is accessed via service role only
