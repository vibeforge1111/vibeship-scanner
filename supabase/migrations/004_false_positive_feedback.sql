-- False Positive Feedback Table
-- Ultra-privacy design: NO code, NO identifiers, NO repo info
--
-- This table stores ONLY:
-- - Rule metadata (public information)
-- - AST structure (no actual code tokens)
-- - Reason category (enum value)
-- - Framework hints (single words)

CREATE TABLE false_positive_feedback (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),

  -- Rule identification (public info)
  rule_id TEXT NOT NULL,
  rule_message TEXT,  -- Sanitized generic description only
  severity TEXT CHECK (severity IN ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL', 'INFO', 'WARNING', 'ERROR')),
  language TEXT,  -- e.g., 'solidity', 'javascript', 'python'

  -- Structural data ONLY - no code tokens
  ast_structure TEXT NOT NULL,  -- e.g., 'FunctionDef>RequireStmt>LowLevelCall'
  pattern_hash TEXT NOT NULL,   -- SHA256 of AST for deduplication

  -- Hints (single words only, no identifiers)
  structural_hints TEXT[] DEFAULT '{}',  -- ['low-level-call', 'loop']
  framework_hints TEXT[] DEFAULT '{}',   -- ['OpenZeppelin', 'Foundry']

  -- Feedback classification
  reason_category TEXT NOT NULL CHECK (reason_category IN (
    'safe_pattern',      -- Code is actually safe
    'framework_handled', -- Framework provides protection
    'test_code',         -- This is test/mock code
    'intentional',       -- Developer intentionally wrote this way
    'wrong_context',     -- Rule doesn't apply to this context
    'other'              -- Other reason
  )),

  -- Privacy consent level
  consent_level INTEGER DEFAULT 1 CHECK (consent_level IN (1, 2, 3)),
  -- 1 = anonymous (default, maximum privacy)
  -- 2 = with context (slightly more detail)
  -- 3 = full share (still heavily sanitized)

  -- Processing status
  processed BOOLEAN DEFAULT false,
  processed_at TIMESTAMPTZ,

  -- Metadata (NO user or repo identification)
  created_at TIMESTAMPTZ DEFAULT now()

  -- INTENTIONALLY OMITTED (privacy by design):
  -- NO user_id - cannot identify who submitted
  -- NO scan_id - cannot link back to specific scan
  -- NO repo_url - cannot identify repository
  -- NO repo_hash - even hashed URLs are unnecessary
  -- NO file_path - cannot identify codebase structure
  -- NO code_snippet - zero code collection
  -- NO ip_address - no user tracking
);

-- Indexes for pattern analysis (not for user tracking)
CREATE INDEX idx_fp_rule ON false_positive_feedback(rule_id);
CREATE INDEX idx_fp_pattern_hash ON false_positive_feedback(pattern_hash);
CREATE INDEX idx_fp_reason ON false_positive_feedback(reason_category);
CREATE INDEX idx_fp_processed ON false_positive_feedback(processed) WHERE processed = false;
CREATE INDEX idx_fp_language ON false_positive_feedback(language);

-- Enable RLS but allow anonymous inserts (no auth required)
ALTER TABLE false_positive_feedback ENABLE ROW LEVEL SECURITY;

-- Anyone can submit feedback (anonymous)
CREATE POLICY "Anyone can submit false positive feedback" ON false_positive_feedback
  FOR INSERT WITH CHECK (true);

-- Only service role can read (for aggregation)
CREATE POLICY "Service role can read feedback" ON false_positive_feedback
  FOR SELECT USING (auth.role() = 'service_role');

-- Aggregated statistics table (what we keep after processing)
CREATE TABLE rule_statistics (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),

  rule_id TEXT NOT NULL,
  reason_category TEXT NOT NULL,
  language TEXT,

  -- Aggregate counts only
  total_count INTEGER DEFAULT 0,
  last_updated_at TIMESTAMPTZ DEFAULT now(),

  UNIQUE(rule_id, reason_category, language)
);

CREATE INDEX idx_stats_rule ON rule_statistics(rule_id);

-- Enable RLS
ALTER TABLE rule_statistics ENABLE ROW LEVEL SECURITY;

-- Statistics are public (aggregated, anonymized data)
CREATE POLICY "Rule statistics are public" ON rule_statistics
  FOR SELECT USING (true);

-- Function to aggregate and delete old feedback (privacy by design)
CREATE OR REPLACE FUNCTION process_old_feedback()
RETURNS void AS $$
BEGIN
  -- Aggregate unprocessed feedback older than 7 days into statistics
  INSERT INTO rule_statistics (rule_id, reason_category, language, total_count, last_updated_at)
  SELECT
    rule_id,
    reason_category,
    language,
    COUNT(*),
    now()
  FROM false_positive_feedback
  WHERE processed = false
    AND created_at < now() - INTERVAL '7 days'
  GROUP BY rule_id, reason_category, language
  ON CONFLICT (rule_id, reason_category, language)
  DO UPDATE SET
    total_count = rule_statistics.total_count + EXCLUDED.total_count,
    last_updated_at = now();

  -- Mark as processed
  UPDATE false_positive_feedback
  SET processed = true, processed_at = now()
  WHERE processed = false
    AND created_at < now() - INTERVAL '7 days';

  -- Delete processed feedback older than 30 days
  DELETE FROM false_positive_feedback
  WHERE processed = true
    AND created_at < now() - INTERVAL '30 days';
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- Schedule cleanup (requires pg_cron extension)
-- Run weekly on Sundays at 3 AM UTC
-- SELECT cron.schedule('process-feedback', '0 3 * * 0', 'SELECT process_old_feedback()');

COMMENT ON TABLE false_positive_feedback IS 'Ultra-privacy false positive feedback. NO code, NO identifiers, NO repo info. Only AST structure and reason categories.';
COMMENT ON TABLE rule_statistics IS 'Aggregated rule statistics. All individual data is deleted after aggregation.';
