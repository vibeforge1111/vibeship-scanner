-- Vibeship Scanner Database Schema

-- Enable pgvector extension for future embeddings
CREATE EXTENSION IF NOT EXISTS vector;

-- Scans table
CREATE TABLE scans (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),

  target_type TEXT NOT NULL CHECK (target_type IN ('github', 'gitlab', 'url')),
  target_url TEXT NOT NULL,
  target_url_hash TEXT NOT NULL,
  target_branch TEXT DEFAULT 'main',
  is_private BOOLEAN DEFAULT false,

  status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'queued', 'scanning', 'complete', 'failed')),
  error_message TEXT,

  score INTEGER CHECK (score >= 0 AND score <= 100),
  grade CHAR(1) CHECK (grade IN ('A', 'B', 'C', 'D', 'F')),
  ship_status TEXT CHECK (ship_status IN ('ship', 'review', 'fix', 'danger')),

  findings JSONB DEFAULT '[]',
  finding_counts JSONB DEFAULT '{"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}',

  tier TEXT DEFAULT 'standard' CHECK (tier IN ('standard', 'deep')),

  detected_stack JSONB DEFAULT '{}',
  stack_signature TEXT,

  started_at TIMESTAMPTZ,
  completed_at TIMESTAMPTZ,
  duration_ms INTEGER,

  user_id UUID REFERENCES auth.users(id) ON DELETE SET NULL,
  session_id TEXT,
  is_pro BOOLEAN DEFAULT false,

  is_public BOOLEAN DEFAULT true,

  created_at TIMESTAMPTZ DEFAULT now(),
  updated_at TIMESTAMPTZ DEFAULT now()
);

CREATE INDEX idx_scans_user ON scans(user_id);
CREATE INDEX idx_scans_status ON scans(status) WHERE status NOT IN ('complete', 'failed');
CREATE INDEX idx_scans_stack ON scans(stack_signature);
CREATE INDEX idx_scans_url_hash ON scans(target_url_hash);
CREATE INDEX idx_scans_created ON scans(created_at DESC);

-- Scan progress for realtime updates
CREATE TABLE scan_progress (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  scan_id UUID NOT NULL REFERENCES scans(id) ON DELETE CASCADE,

  step TEXT NOT NULL,
  step_number INTEGER NOT NULL,
  total_steps INTEGER DEFAULT 5,
  message TEXT,

  created_at TIMESTAMPTZ DEFAULT now()
);

CREATE INDEX idx_progress_scan ON scan_progress(scan_id);

-- Enable realtime for scan_progress
ALTER PUBLICATION supabase_realtime ADD TABLE scan_progress;

-- Rules table with shadow mode support
CREATE TABLE rules (
  id TEXT PRIMARY KEY,

  rule_yaml TEXT NOT NULL,
  version INTEGER DEFAULT 1,

  status TEXT DEFAULT 'shadow' CHECK (status IN ('shadow', 'validating', 'active', 'deprecated', 'retired')),
  source TEXT CHECK (source IN ('manual', 'ai_generated', 'imported')),

  shadow_matches INTEGER DEFAULT 0,
  active_matches INTEGER DEFAULT 0,
  true_positives INTEGER DEFAULT 0,
  false_positives INTEGER DEFAULT 0,

  precision NUMERIC(5,4) GENERATED ALWAYS AS (
    CASE WHEN (true_positives + false_positives) > 0
    THEN true_positives::NUMERIC / (true_positives + false_positives)
    ELSE 0 END
  ) STORED,

  shadow_started_at TIMESTAMPTZ,
  promoted_at TIMESTAMPTZ,
  deprecated_at TIMESTAMPTZ,

  created_at TIMESTAMPTZ DEFAULT now(),
  updated_at TIMESTAMPTZ DEFAULT now()
);

-- Learning signals from user feedback
CREATE TABLE learning_signals (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),

  signal_type TEXT NOT NULL CHECK (signal_type IN (
    'true_positive',
    'false_positive',
    'fix_applied',
    'fix_verified',
    'fix_failed'
  )),

  scan_id UUID REFERENCES scans(id) ON DELETE SET NULL,
  finding_id TEXT,
  rule_id TEXT REFERENCES rules(id) ON DELETE SET NULL,

  context JSONB DEFAULT '{}',
  processed BOOLEAN DEFAULT false,

  created_at TIMESTAMPTZ DEFAULT now()
);

CREATE INDEX idx_signals_type ON learning_signals(signal_type);
CREATE INDEX idx_signals_rule ON learning_signals(rule_id);

-- Fix templates with effectiveness tracking
CREATE TABLE fix_templates (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),

  finding_type TEXT NOT NULL,
  stack_signature TEXT,

  title TEXT NOT NULL,
  description TEXT NOT NULL,
  code_template TEXT NOT NULL,
  estimated_minutes INTEGER,

  times_shown INTEGER DEFAULT 0,
  times_copied INTEGER DEFAULT 0,
  times_verified INTEGER DEFAULT 0,

  success_rate NUMERIC(5,4) GENERATED ALWAYS AS (
    CASE WHEN times_copied > 0
    THEN times_verified::NUMERIC / times_copied
    ELSE 0 END
  ) STORED,

  created_at TIMESTAMPTZ DEFAULT now()
);

CREATE INDEX idx_fixes_type ON fix_templates(finding_type);
CREATE INDEX idx_fixes_stack ON fix_templates(stack_signature);

-- Community benchmarks by stack
CREATE TABLE stack_benchmarks (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),

  stack_signature TEXT NOT NULL,
  week DATE NOT NULL,

  scan_count INTEGER DEFAULT 0,
  avg_score NUMERIC(5,2),
  median_score INTEGER,
  p25_score INTEGER,
  p75_score INTEGER,

  top_issues JSONB DEFAULT '[]',

  UNIQUE(stack_signature, week)
);

CREATE INDEX idx_benchmarks_stack ON stack_benchmarks(stack_signature);

-- Badges for embedding
CREATE TABLE badges (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  scan_id UUID NOT NULL REFERENCES scans(id) ON DELETE CASCADE,

  tier TEXT DEFAULT 'scanned',
  style TEXT DEFAULT 'flat',

  svg_cache TEXT,
  cached_at TIMESTAMPTZ,

  view_count INTEGER DEFAULT 0,
  embed_count INTEGER DEFAULT 0,

  created_at TIMESTAMPTZ DEFAULT now()
);

CREATE INDEX idx_badges_scan ON badges(scan_id);

-- Rate limiting
CREATE TABLE rate_limits (
  identifier TEXT PRIMARY KEY,
  identifier_type TEXT NOT NULL CHECK (identifier_type IN ('ip', 'user', 'session')),

  scans_this_hour INTEGER DEFAULT 0,
  scans_this_day INTEGER DEFAULT 0,

  hour_reset_at TIMESTAMPTZ,
  day_reset_at TIMESTAMPTZ,

  flagged BOOLEAN DEFAULT false,
  flag_reason TEXT,

  updated_at TIMESTAMPTZ DEFAULT now()
);

-- Row Level Security Policies

ALTER TABLE scans ENABLE ROW LEVEL SECURITY;
ALTER TABLE scan_progress ENABLE ROW LEVEL SECURITY;
ALTER TABLE learning_signals ENABLE ROW LEVEL SECURITY;
ALTER TABLE badges ENABLE ROW LEVEL SECURITY;

-- Public scans are readable by anyone
CREATE POLICY "Public scans are viewable by anyone" ON scans
  FOR SELECT USING (is_public = true);

-- Users can view their own scans
CREATE POLICY "Users can view own scans" ON scans
  FOR SELECT USING (auth.uid() = user_id);

-- Users can insert scans
CREATE POLICY "Anyone can create scans" ON scans
  FOR INSERT WITH CHECK (true);

-- Scan progress is viewable for accessible scans
CREATE POLICY "Progress viewable for accessible scans" ON scan_progress
  FOR SELECT USING (
    EXISTS (
      SELECT 1 FROM scans
      WHERE scans.id = scan_progress.scan_id
      AND (scans.is_public = true OR scans.user_id = auth.uid())
    )
  );

-- Badges are public
CREATE POLICY "Badges are public" ON badges
  FOR SELECT USING (true);

-- Learning signals can be inserted by anyone
CREATE POLICY "Anyone can submit feedback" ON learning_signals
  FOR INSERT WITH CHECK (true);

-- Functions

-- Update updated_at timestamp
CREATE OR REPLACE FUNCTION update_updated_at()
RETURNS TRIGGER AS $$
BEGIN
  NEW.updated_at = now();
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER scans_updated_at
  BEFORE UPDATE ON scans
  FOR EACH ROW EXECUTE FUNCTION update_updated_at();

CREATE TRIGGER rules_updated_at
  BEFORE UPDATE ON rules
  FOR EACH ROW EXECUTE FUNCTION update_updated_at();

-- Calculate grade from score
CREATE OR REPLACE FUNCTION calculate_grade(score INTEGER)
RETURNS CHAR(1) AS $$
BEGIN
  RETURN CASE
    WHEN score >= 90 THEN 'A'
    WHEN score >= 80 THEN 'B'
    WHEN score >= 70 THEN 'C'
    WHEN score >= 60 THEN 'D'
    ELSE 'F'
  END;
END;
$$ LANGUAGE plpgsql IMMUTABLE;

-- Calculate ship status from score
CREATE OR REPLACE FUNCTION calculate_ship_status(score INTEGER)
RETURNS TEXT AS $$
BEGIN
  RETURN CASE
    WHEN score >= 90 THEN 'ship'
    WHEN score >= 70 THEN 'review'
    WHEN score >= 50 THEN 'fix'
    ELSE 'danger'
  END;
END;
$$ LANGUAGE plpgsql IMMUTABLE;
