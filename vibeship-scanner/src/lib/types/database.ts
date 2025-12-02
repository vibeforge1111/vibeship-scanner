export type Json =
  | string
  | number
  | boolean
  | null
  | { [key: string]: Json | undefined }
  | Json[];

export type Database = {
  public: {
    Tables: {
      scans: {
        Row: {
          id: string;
          target_type: 'github' | 'gitlab' | 'url';
          target_url: string;
          target_url_hash: string;
          target_branch: string;
          is_private: boolean;
          status: 'pending' | 'queued' | 'scanning' | 'complete' | 'failed';
          error_message: string | null;
          score: number | null;
          grade: 'A' | 'B' | 'C' | 'D' | 'F' | null;
          ship_status: 'ship' | 'review' | 'fix' | 'danger' | null;
          findings: Json;
          finding_counts: Json;
          tier: 'standard' | 'deep';
          detected_stack: Json;
          stack_signature: string | null;
          started_at: string | null;
          completed_at: string | null;
          duration_ms: number | null;
          user_id: string | null;
          session_id: string | null;
          is_pro: boolean;
          is_public: boolean;
          created_at: string;
          updated_at: string;
        };
        Insert: {
          id?: string;
          target_type: 'github' | 'gitlab' | 'url';
          target_url: string;
          target_url_hash: string;
          target_branch?: string;
          is_private?: boolean;
          status?: 'pending' | 'queued' | 'scanning' | 'complete' | 'failed';
          error_message?: string | null;
          score?: number | null;
          grade?: 'A' | 'B' | 'C' | 'D' | 'F' | null;
          ship_status?: 'ship' | 'review' | 'fix' | 'danger' | null;
          findings?: Json;
          finding_counts?: Json;
          tier?: 'standard' | 'deep';
          detected_stack?: Json;
          stack_signature?: string | null;
          started_at?: string | null;
          completed_at?: string | null;
          duration_ms?: number | null;
          user_id?: string | null;
          session_id?: string | null;
          is_pro?: boolean;
          is_public?: boolean;
        };
        Update: {
          status?: 'pending' | 'queued' | 'scanning' | 'complete' | 'failed';
          error_message?: string | null;
          score?: number | null;
          grade?: 'A' | 'B' | 'C' | 'D' | 'F' | null;
          ship_status?: 'ship' | 'review' | 'fix' | 'danger' | null;
          findings?: Json;
          finding_counts?: Json;
          detected_stack?: Json;
          stack_signature?: string | null;
          started_at?: string | null;
          completed_at?: string | null;
          duration_ms?: number | null;
        };
      };
      scan_progress: {
        Row: {
          id: string;
          scan_id: string;
          step: string;
          step_number: number;
          total_steps: number;
          percent: number;
          message: string | null;
          created_at: string;
        };
        Insert: {
          id?: string;
          scan_id: string;
          step: string;
          step_number?: number;
          total_steps?: number;
          percent?: number;
          message?: string | null;
        };
        Update: {
          step?: string;
          step_number?: number;
          percent?: number;
          message?: string | null;
        };
      };
      rules: {
        Row: {
          id: string;
          rule_yaml: string;
          version: number;
          status: 'shadow' | 'validating' | 'active' | 'deprecated' | 'retired';
          source: 'manual' | 'ai_generated' | 'imported' | null;
          shadow_matches: number;
          active_matches: number;
          true_positives: number;
          false_positives: number;
          precision: number;
          shadow_started_at: string | null;
          promoted_at: string | null;
          deprecated_at: string | null;
          created_at: string;
          updated_at: string;
        };
        Insert: {
          id: string;
          rule_yaml: string;
          version?: number;
          status?: 'shadow' | 'validating' | 'active' | 'deprecated' | 'retired';
          source?: 'manual' | 'ai_generated' | 'imported' | null;
        };
        Update: {
          rule_yaml?: string;
          version?: number;
          status?: 'shadow' | 'validating' | 'active' | 'deprecated' | 'retired';
          shadow_matches?: number;
          active_matches?: number;
          true_positives?: number;
          false_positives?: number;
        };
      };
      learning_signals: {
        Row: {
          id: string;
          signal_type: 'true_positive' | 'false_positive' | 'fix_applied' | 'fix_verified' | 'fix_failed';
          scan_id: string | null;
          finding_id: string | null;
          rule_id: string | null;
          context: Json;
          processed: boolean;
          created_at: string;
        };
        Insert: {
          id?: string;
          signal_type: 'true_positive' | 'false_positive' | 'fix_applied' | 'fix_verified' | 'fix_failed';
          scan_id?: string | null;
          finding_id?: string | null;
          rule_id?: string | null;
          context?: Json;
        };
        Update: {
          processed?: boolean;
        };
      };
      fix_templates: {
        Row: {
          id: string;
          finding_type: string;
          stack_signature: string | null;
          title: string;
          description: string;
          code_template: string;
          estimated_minutes: number | null;
          times_shown: number;
          times_copied: number;
          times_verified: number;
          success_rate: number;
          created_at: string;
        };
        Insert: {
          id?: string;
          finding_type: string;
          stack_signature?: string | null;
          title: string;
          description: string;
          code_template: string;
          estimated_minutes?: number | null;
        };
        Update: {
          times_shown?: number;
          times_copied?: number;
          times_verified?: number;
        };
      };
      badges: {
        Row: {
          id: string;
          scan_id: string;
          tier: string;
          style: string;
          svg_cache: string | null;
          cached_at: string | null;
          view_count: number;
          embed_count: number;
          created_at: string;
        };
        Insert: {
          id?: string;
          scan_id: string;
          tier?: string;
          style?: string;
          svg_cache?: string | null;
        };
        Update: {
          svg_cache?: string | null;
          cached_at?: string | null;
          view_count?: number;
          embed_count?: number;
        };
      };
    };
  };
};

export type Scan = Database['public']['Tables']['scans']['Row'];
export type ScanInsert = Database['public']['Tables']['scans']['Insert'];
export type ScanUpdate = Database['public']['Tables']['scans']['Update'];

export type ScanProgress = Database['public']['Tables']['scan_progress']['Row'];
export type Rule = Database['public']['Tables']['rules']['Row'];
export type LearningSignal = Database['public']['Tables']['learning_signals']['Row'];
export type FixTemplate = Database['public']['Tables']['fix_templates']['Row'];
export type Badge = Database['public']['Tables']['badges']['Row'];

export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';
export type Category = 'code' | 'dependencies' | 'secrets';

export interface Finding {
  id: string;
  ruleId: string;
  severity: Severity;
  category: Category;
  title: string;
  description: string;
  location: {
    file: string;
    line: number;
    column?: number;
  };
  snippet?: {
    code: string;
    highlightLines: number[];
  };
  fix: {
    available: boolean;
    template?: string;
    aiGenerated?: boolean;
  };
  references?: string[];
  contextNotes?: string;
}

export interface ScanResult {
  id: string;
  score: number;
  grade: 'A' | 'B' | 'C' | 'D' | 'F';
  shipStatus: 'ship' | 'review' | 'fix' | 'danger';
  summary: {
    critical: number;
    high: number;
    medium: number;
    low: number;
    info: number;
  };
  stack: {
    languages: string[];
    frameworks: string[];
    signature: string;
  };
  findings: Finding[];
  tier: 'standard' | 'deep';
  completedAt: string;
  duration: number;
}
