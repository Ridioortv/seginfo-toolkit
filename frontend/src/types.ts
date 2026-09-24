// Tipos compartidos entre paginas, en espejo de los schemas Pydantic de
// cada microservicio (ver backend/services/*/app/schemas.py).

export interface AssetOut {
  id: string;
  hostname: string;
  ip_address: string;
  mac_address: string;
  os_name: string;
  os_version: string;
  environment: string;
  criticality: string;
  owner: string;
  tags: string[];
  is_active: boolean;
  notes: string;
}

export interface ScanJobOut {
  id: string;
  name: string;
  scanner_type: string;
  target: string;
  asset_id: string | null;
  status: string;
  options: Record<string, unknown>;
  findings: Record<string, unknown>[];
  error_message: string;
  created_by: string;
  created_at: string;
  started_at: string | null;
}

export interface ScanScheduleOut {
  id: string;
  name: string;
  scanner_type: string;
  target: string;
  options: Record<string, unknown>;
  frequency: string;
  hour: number;
  minute: number;
  day_of_week: number | null;
  enabled: boolean;
  created_by: string;
  created_at: string;
  last_run_at: string | null;
  last_status: string;
}

export interface ScanAgentOut {
  id: string;
  name: string;
  created_by: string;
  created_at: string;
  last_seen_at: string | null;
}

export interface ScanAgentCreated extends ScanAgentOut {
  api_key: string;
}

export interface AgentScanJobOut {
  id: string;
  agent_id: string;
  name: string;
  scanner_type: string;
  target: string;
  options: Record<string, unknown>;
  status: string;
  findings: Record<string, unknown>[];
  error_message: string;
  created_by: string;
  created_at: string;
  assigned_at: string | null;
  finished_at: string | null;
}

export interface VulnerabilityOut {
  id: string;
  cve_id: string | null;
  title: string;
  description: string;
  severity: string;
  source_scanner: string;
  asset_id: string | null;
  package: string;
  installed_version: string;
  fixed_version: string;
  cvss_score: number | null;
  epss_score: number | null;
  is_kev: boolean;
  priority_score: number;
}

export interface VulnerabilityStatsOut {
  total: number;
  by_status: Record<string, number>;
  by_severity: Record<string, number>;
  kev_count: number;
  avg_priority_score: number;
}

export interface SigmaRuleOut {
  id: string;
  name: string;
  description: string;
  severity: string;
  tags: string[];
  detection: Record<string, unknown>;
  is_enabled: boolean;
}

export interface AlertOut {
  id: string;
  rule_id: string;
  rule_name: string;
  severity: string;
  matched_event: Record<string, unknown>;
  status: string;
  soar_triggered: boolean;
  acknowledged_by: string;
  notes: string;
  created_at: string;
}

export interface PlaybookOut {
  id: string;
  name: string;
  description: string;
  min_severity: string;
  rule_tags: string[];
  steps: Record<string, unknown>[];
  is_enabled: boolean;
  source_file: string;
}

export interface PlaybookRunOut {
  id: string;
  playbook_id: string;
  playbook_name: string;
  alert_id: string | null;
  status: string;
  steps_log: Record<string, unknown>[];
  triggered_by: string;
  created_at: string;
  finished_at: string | null;
}

export interface TimelineEntryOut {
  id: string;
  actor: string;
  action: string;
  notes: string;
  created_at: string;
}

export interface CaseOut {
  id: string;
  title: string;
  description: string;
  priority: string;
  status: string;
  assignee: string;
  alert_id: string | null;
  source: string;
  sla_due_at: string | null;
  created_at: string;
  resolved_at: string | null;
  timeline: TimelineEntryOut[];
}

export interface TechniqueOut {
  technique_id: string;
  name: string;
  tactic: string;
}

export interface TechniqueCoverage extends TechniqueOut {
  covered: boolean;
  matching_rules: string[];
}

export interface CoverageResult {
  exercise_id: string | null;
  total_techniques: number;
  covered_count: number;
  coverage_pct: number;
  by_tactic: Record<string, { total: number; covered: number }>;
  techniques: TechniqueCoverage[];
  gaps: TechniqueCoverage[];
}

export interface ExerciseOut {
  id: string;
  name: string;
  description: string;
  declared_technique_ids: string[];
  last_coverage_result: Record<string, unknown>;
  created_at: string;
}

export interface GeneratedReportOut {
  id: string;
  report_type: string;
  generated_by: string;
  data: Record<string, unknown>;
  errors: string[];
  created_at: string;
}

export interface ReportScheduleOut {
  id: string;
  report_type: string;
  notification_channel_id: string;
  frequency: string;
  hour: number;
  minute: number;
  day_of_week: number | null;
  enabled: boolean;
  created_by: string;
  created_at: string;
  last_run_at: string | null;
  last_status: string;
}

export interface ChannelOut {
  id: string;
  name: string;
  channel_type: string;
  config: Record<string, unknown>;
  enabled: boolean;
  created_at: string;
}

export interface NotifyLogOut {
  id: string;
  channel_id: string;
  channel_type: string;
  subject: string;
  status: string;
  error: string;
  created_at: string;
}

export interface ConnectorOut {
  id: string;
  name: string;
  kind: string;
  config: Record<string, unknown>;
  enabled: boolean;
  created_at: string;
}

export interface ActionLogOut {
  id: string;
  connector_id: string;
  action: string;
  target: string;
  status: string;
  error: string;
  created_at: string;
}

export interface TicketLogOut {
  id: string;
  connector_id: string;
  title: string;
  priority: string;
  status: string;
  external_key: string;
  external_url: string;
  error: string;
  created_at: string;
}

// --- Organizaciones (tenants) y SSO empresarial (OIDC) ---
// Espejo de backend/services/auth-service/app/schemas.py.

export interface OrganizationOut {
  id: string;
  name: string;
  slug: string;
  is_active: boolean;
  // Presentes solo en la respuesta de GET/POST .../subscription* (ver
  // backend/services/auth-service/app/schemas.py::OrganizationOut) --
  // el listado de GET /auth/organizations no los necesita.
  subscription_expires_at?: string;
  license_last_checked_at?: string | null;
}

export interface SubscriptionCancelOut {
  cancelled: boolean;
  valid_until: string;
}

export interface SubscriptionPayLinkOut {
  payment_url: string;
}

export interface SubscriptionHistoryOut {
  history: string[];
}

export interface OrganizationCreateResult {
  organization: OrganizationOut;
  admin_user: {
    id: string;
    email: string;
    full_name: string;
    role_name: string;
    is_active: boolean;
    mfa_enabled: boolean;
    organization_id: string | null;
  };
}

export interface SsoConfigOut {
  organization_id: string;
  issuer: string;
  client_id: string;
  default_role: string;
  enabled: boolean;
}
