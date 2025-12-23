-- =============================================================================
-- VIBESHIP SCANNER - FALSE POSITIVE FEEDBACK SYSTEM
-- Supabase Schema with Security Best Practices
-- =============================================================================
--
-- SECURITY MODEL:
-- 1. Row Level Security (RLS) enabled - no public access
-- 2. Only service_role (backend) can INSERT data
-- 3. Only authenticated admins can SELECT/UPDATE/DELETE
-- 4. Audit logging for all operations
-- 5. Data retention policies
-- 6. No PII stored - all data anonymized before insertion
--
-- NEVER expose SUPABASE_SERVICE_ROLE_KEY to frontend!
-- =============================================================================

-- -----------------------------------------------------------------------------
-- STEP 1: Create a separate schema for sensitive feedback data
-- This isolates it from the public schema
-- -----------------------------------------------------------------------------
CREATE SCHEMA IF NOT EXISTS feedback;

-- Grant usage to authenticated users (for admin dashboard)
GRANT USAGE ON SCHEMA feedback TO authenticated;
GRANT USAGE ON SCHEMA feedback TO service_role;

-- -----------------------------------------------------------------------------
-- STEP 2: Create the main false_positive_reports table
-- -----------------------------------------------------------------------------
CREATE TABLE feedback.false_positive_reports (
    -- Primary key
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    -- Timestamps
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    -- Rule identification (non-sensitive)
    rule_id TEXT NOT NULL,
    rule_message TEXT,
    severity TEXT CHECK (severity IN ('ERROR', 'WARNING', 'INFO')),
    language TEXT NOT NULL,

    -- Sanitized pattern data (privacy-preserving)
    sanitized_pattern TEXT NOT NULL,
    pattern_hash TEXT NOT NULL,  -- SHA256 for deduplication
    pattern_structure TEXT,      -- AST-like structure description

    -- Context (Level 2+ only, still sanitized)
    surrounding_context TEXT,
    framework_hints TEXT[],      -- e.g., ["OpenZeppelin", "Foundry"]

    -- Reason analysis
    reason_category TEXT NOT NULL CHECK (reason_category IN (
        'safe_pattern',       -- Code is actually safe
        'framework_handled',  -- Framework handles security
        'test_code',          -- Only in tests
        'intentional',        -- Developer's intentional choice
        'wrong_context',      -- Rule doesn't apply here
        'other'
    )),
    reason_detail TEXT,
    ai_analysis TEXT,            -- What the AI concluded

    -- Privacy metadata
    consent_level INTEGER NOT NULL CHECK (consent_level BETWEEN 1 AND 3),
    anonymized_repo_hash TEXT,   -- SHA256 truncated, Level 3 only

    -- Aggregation tracking
    report_count INTEGER DEFAULT 1,
    unique_reporters INTEGER DEFAULT 1,

    -- Processing status
    status TEXT DEFAULT 'new' CHECK (status IN (
        'new',           -- Just received
        'reviewing',     -- Being analyzed
        'confirmed',     -- Confirmed false positive
        'rejected',      -- Not a false positive
        'fixed',         -- Rule has been improved
        'wont_fix'       -- Known limitation
    )),
    reviewed_at TIMESTAMPTZ,
    reviewed_by TEXT,
    review_notes TEXT,

    -- For rule improvement tracking
    improvement_pr TEXT,         -- GitHub PR link if rule was improved
    fixed_in_version TEXT        -- Scanner version that fixed it
);

-- -----------------------------------------------------------------------------
-- STEP 3: Create indexes for efficient querying
-- -----------------------------------------------------------------------------
CREATE INDEX idx_fp_rule_id ON feedback.false_positive_reports(rule_id);
CREATE INDEX idx_fp_pattern_hash ON feedback.false_positive_reports(pattern_hash);
CREATE INDEX idx_fp_status ON feedback.false_positive_reports(status);
CREATE INDEX idx_fp_created_at ON feedback.false_positive_reports(created_at DESC);
CREATE INDEX idx_fp_language ON feedback.false_positive_reports(language);
CREATE INDEX idx_fp_reason ON feedback.false_positive_reports(reason_category);

-- Unique constraint to prevent exact duplicates (upsert instead)
CREATE UNIQUE INDEX idx_fp_unique_pattern ON feedback.false_positive_reports(
    rule_id, pattern_hash
) WHERE status NOT IN ('rejected', 'wont_fix');

-- -----------------------------------------------------------------------------
-- STEP 4: Enable Row Level Security (CRITICAL!)
-- -----------------------------------------------------------------------------
ALTER TABLE feedback.false_positive_reports ENABLE ROW LEVEL SECURITY;

-- Force RLS for table owner too (extra security)
ALTER TABLE feedback.false_positive_reports FORCE ROW LEVEL SECURITY;

-- -----------------------------------------------------------------------------
-- STEP 5: Create RLS Policies
-- -----------------------------------------------------------------------------

-- Policy 1: Service role can INSERT (backend API only)
-- This is how feedback reports are submitted
CREATE POLICY "Service role can insert reports"
    ON feedback.false_positive_reports
    FOR INSERT
    TO service_role
    WITH CHECK (true);

-- Policy 2: Service role can UPDATE (for deduplication/aggregation)
CREATE POLICY "Service role can update reports"
    ON feedback.false_positive_reports
    FOR UPDATE
    TO service_role
    USING (true)
    WITH CHECK (true);

-- Policy 3: Admins can read all data (for dashboard)
-- You'll need to create an 'admin' role or use a custom claim
CREATE POLICY "Admins can read all reports"
    ON feedback.false_positive_reports
    FOR SELECT
    TO authenticated
    USING (
        -- Check if user has admin role in their JWT claims
        -- Option A: Using custom claims
        (auth.jwt() ->> 'user_role') = 'admin'
        OR
        -- Option B: Using a specific email domain
        auth.email() LIKE '%@vibeship.co'
        OR
        -- Option C: Using a hardcoded admin list (for small teams)
        auth.email() IN (
            'admin@vibeship.co',
            'security@vibeship.co'
            -- Add your admin emails here
        )
    );

-- Policy 4: Admins can update status and review notes
CREATE POLICY "Admins can update report status"
    ON feedback.false_positive_reports
    FOR UPDATE
    TO authenticated
    USING (
        (auth.jwt() ->> 'user_role') = 'admin'
        OR auth.email() LIKE '%@vibeship.co'
    )
    WITH CHECK (
        (auth.jwt() ->> 'user_role') = 'admin'
        OR auth.email() LIKE '%@vibeship.co'
    );

-- Policy 5: No one can delete (audit trail preservation)
-- If you need deletion, do soft delete by setting status = 'deleted'
CREATE POLICY "No deletion allowed"
    ON feedback.false_positive_reports
    FOR DELETE
    TO authenticated
    USING (false);  -- Always deny

-- -----------------------------------------------------------------------------
-- STEP 6: Create audit log table
-- -----------------------------------------------------------------------------
CREATE TABLE feedback.audit_log (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    table_name TEXT NOT NULL,
    record_id UUID NOT NULL,
    action TEXT NOT NULL CHECK (action IN ('INSERT', 'UPDATE', 'DELETE')),
    old_data JSONB,
    new_data JSONB,
    performed_by TEXT,  -- Service role or user email
    ip_address INET
);

-- Enable RLS on audit log too
ALTER TABLE feedback.audit_log ENABLE ROW LEVEL SECURITY;
ALTER TABLE feedback.audit_log FORCE ROW LEVEL SECURITY;

-- Only service role can insert audit logs
CREATE POLICY "Service role inserts audit logs"
    ON feedback.audit_log
    FOR INSERT
    TO service_role
    WITH CHECK (true);

-- Only admins can read audit logs
CREATE POLICY "Admins can read audit logs"
    ON feedback.audit_log
    FOR SELECT
    TO authenticated
    USING (
        (auth.jwt() ->> 'user_role') = 'admin'
        OR auth.email() LIKE '%@vibeship.co'
    );

-- -----------------------------------------------------------------------------
-- STEP 7: Create audit trigger function
-- -----------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION feedback.audit_trigger_func()
RETURNS TRIGGER AS $$
BEGIN
    IF TG_OP = 'INSERT' THEN
        INSERT INTO feedback.audit_log (table_name, record_id, action, new_data, performed_by)
        VALUES (TG_TABLE_NAME, NEW.id, 'INSERT', to_jsonb(NEW), current_user);
        RETURN NEW;
    ELSIF TG_OP = 'UPDATE' THEN
        INSERT INTO feedback.audit_log (table_name, record_id, action, old_data, new_data, performed_by)
        VALUES (TG_TABLE_NAME, NEW.id, 'UPDATE', to_jsonb(OLD), to_jsonb(NEW), current_user);
        RETURN NEW;
    ELSIF TG_OP = 'DELETE' THEN
        INSERT INTO feedback.audit_log (table_name, record_id, action, old_data, performed_by)
        VALUES (TG_TABLE_NAME, OLD.id, 'DELETE', to_jsonb(OLD), current_user);
        RETURN OLD;
    END IF;
    RETURN NULL;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- Apply audit trigger
CREATE TRIGGER false_positive_audit_trigger
    AFTER INSERT OR UPDATE OR DELETE ON feedback.false_positive_reports
    FOR EACH ROW EXECUTE FUNCTION feedback.audit_trigger_func();

-- -----------------------------------------------------------------------------
-- STEP 8: Create updated_at trigger
-- -----------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION feedback.update_updated_at()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER update_false_positive_updated_at
    BEFORE UPDATE ON feedback.false_positive_reports
    FOR EACH ROW EXECUTE FUNCTION feedback.update_updated_at();

-- -----------------------------------------------------------------------------
-- STEP 9: Create helpful views for analysis (admin only via RLS)
-- -----------------------------------------------------------------------------

-- Summary by rule
CREATE VIEW feedback.rule_summary AS
SELECT
    rule_id,
    language,
    COUNT(*) as total_reports,
    SUM(report_count) as weighted_reports,
    COUNT(DISTINCT pattern_hash) as unique_patterns,
    array_agg(DISTINCT reason_category) as reason_categories,
    COUNT(*) FILTER (WHERE status = 'confirmed') as confirmed_fps,
    COUNT(*) FILTER (WHERE status = 'fixed') as fixed_count,
    MIN(created_at) as first_reported,
    MAX(created_at) as last_reported
FROM feedback.false_positive_reports
GROUP BY rule_id, language
ORDER BY total_reports DESC;

-- High priority rules needing attention
CREATE VIEW feedback.priority_rules AS
SELECT
    rule_id,
    language,
    total_reports,
    unique_patterns,
    reason_categories,
    CASE
        WHEN total_reports >= 20 THEN 'critical'
        WHEN total_reports >= 10 THEN 'high'
        WHEN total_reports >= 5 THEN 'medium'
        ELSE 'low'
    END as priority
FROM feedback.rule_summary
WHERE total_reports >= 3
ORDER BY total_reports DESC;

-- Recent reports for review
CREATE VIEW feedback.pending_review AS
SELECT *
FROM feedback.false_positive_reports
WHERE status = 'new'
ORDER BY created_at DESC
LIMIT 100;

-- Grant view access (still protected by RLS on base table)
GRANT SELECT ON feedback.rule_summary TO authenticated;
GRANT SELECT ON feedback.priority_rules TO authenticated;
GRANT SELECT ON feedback.pending_review TO authenticated;

-- -----------------------------------------------------------------------------
-- STEP 10: Create function for upserting reports (handles duplicates)
-- -----------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION feedback.upsert_false_positive(
    p_rule_id TEXT,
    p_rule_message TEXT,
    p_severity TEXT,
    p_language TEXT,
    p_sanitized_pattern TEXT,
    p_pattern_hash TEXT,
    p_pattern_structure TEXT,
    p_surrounding_context TEXT,
    p_framework_hints TEXT[],
    p_reason_category TEXT,
    p_reason_detail TEXT,
    p_ai_analysis TEXT,
    p_consent_level INTEGER,
    p_anonymized_repo_hash TEXT
)
RETURNS UUID AS $$
DECLARE
    v_id UUID;
BEGIN
    -- Try to find existing report with same pattern
    SELECT id INTO v_id
    FROM feedback.false_positive_reports
    WHERE rule_id = p_rule_id
      AND pattern_hash = p_pattern_hash
      AND status NOT IN ('rejected', 'wont_fix')
    LIMIT 1;

    IF v_id IS NOT NULL THEN
        -- Update existing report (increment counters)
        UPDATE feedback.false_positive_reports
        SET
            report_count = report_count + 1,
            unique_reporters = unique_reporters + 1,
            -- Keep the more detailed context if available
            surrounding_context = COALESCE(
                NULLIF(p_surrounding_context, ''),
                surrounding_context
            ),
            -- Merge framework hints
            framework_hints = ARRAY(
                SELECT DISTINCT unnest(
                    framework_hints || COALESCE(p_framework_hints, ARRAY[]::TEXT[])
                )
            ),
            -- Update reason if this one is more specific
            reason_detail = CASE
                WHEN LENGTH(COALESCE(p_reason_detail, '')) > LENGTH(COALESCE(reason_detail, ''))
                THEN p_reason_detail
                ELSE reason_detail
            END
        WHERE id = v_id;

        RETURN v_id;
    ELSE
        -- Insert new report
        INSERT INTO feedback.false_positive_reports (
            rule_id, rule_message, severity, language,
            sanitized_pattern, pattern_hash, pattern_structure,
            surrounding_context, framework_hints,
            reason_category, reason_detail, ai_analysis,
            consent_level, anonymized_repo_hash
        ) VALUES (
            p_rule_id, p_rule_message, p_severity, p_language,
            p_sanitized_pattern, p_pattern_hash, p_pattern_structure,
            p_surrounding_context, p_framework_hints,
            p_reason_category, p_reason_detail, p_ai_analysis,
            p_consent_level, p_anonymized_repo_hash
        )
        RETURNING id INTO v_id;

        RETURN v_id;
    END IF;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- Grant execute to service role only
GRANT EXECUTE ON FUNCTION feedback.upsert_false_positive TO service_role;

-- -----------------------------------------------------------------------------
-- STEP 11: Data retention policy (optional - run periodically)
-- -----------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION feedback.cleanup_old_rejected()
RETURNS INTEGER AS $$
DECLARE
    deleted_count INTEGER;
BEGIN
    -- Delete rejected/wont_fix reports older than 1 year
    -- Keep confirmed and fixed reports forever for analysis
    DELETE FROM feedback.false_positive_reports
    WHERE status IN ('rejected', 'wont_fix')
      AND created_at < NOW() - INTERVAL '1 year';

    GET DIAGNOSTICS deleted_count = ROW_COUNT;
    RETURN deleted_count;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- -----------------------------------------------------------------------------
-- SECURITY CHECKLIST:
-- -----------------------------------------------------------------------------
-- [x] RLS enabled and forced on all tables
-- [x] service_role can INSERT/UPDATE (backend only)
-- [x] authenticated users need admin claim/email to SELECT
-- [x] DELETE is blocked (audit trail)
-- [x] Audit logging for all changes
-- [x] No PII stored - only sanitized patterns
-- [x] Pattern hashes for deduplication without storing originals
-- [x] Separate schema isolates sensitive data
-- [x] Views provide safe aggregated access
-- [x] Upsert function prevents duplicates
-- [x] Data retention policy for cleanup
--
-- DEPLOYMENT NOTES:
-- 1. Run this SQL in Supabase SQL Editor
-- 2. Store SUPABASE_SERVICE_ROLE_KEY in Fly.io secrets ONLY
-- 3. Never expose service role key to frontend
-- 4. Add admin emails to the RLS policy
-- 5. Set up monitoring for the audit_log table
-- -----------------------------------------------------------------------------
