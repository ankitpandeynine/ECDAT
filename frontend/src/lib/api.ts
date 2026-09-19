export type EnvironmentEvidence = {
  status: string;
  signals: {
    category: string;
    value: string;
    evidence: string;
    source: string;
    confidence: string;
  }[];
  limitations?: string[];
};
export type PQEvidence = {
  status: string;
  reason: string;
  scanner_version?: string;
  supported_groups: string[];
  scope: string;
  tests: {
    group: string;
    status: string;
    reason?: string;
    evidence?: string;
    negotiated_group?: string;
  }[];
};
export type Finding = {
  primitive: string;
  severity?: string;
  file?: string;
  line?: number;
  offset?: string;
  confidence?: string;
  issue?: string;
  description?: string;
  engine?: string;
};
export type PcapSession = {
  client_ip: string;
  server_ip: string;
  client_port: number;
  server_port: number;
  sni?: string;
  tls_version?: string;
  offered_ciphers?: string[];
  selected_cipher?: string;
  supported_groups?: string[];
  selected_group?: string;
  ja3_string?: string;
  ja3_fingerprint?: string;
  ja4_fingerprint?: string;
  has_pqc_hybrid?: boolean;
  is_quantum_vulnerable?: boolean;
};

export type ScanResult = {
  findings?: Finding[];
  detections?: Finding[];
  target?: string;
  protocol?: string;
  cipher_name?: string;
  pqc_status?: string;
  quantum_vulnerable?: boolean | null;
  hndl_risk?: string;
  hndl_rationale?: string;
  post_quantum?: PQEvidence;
  certificate?: Record<string, unknown>;
  coverage?: unknown;
  dependencies?: unknown[];
  status?: string;
  limitations?: string[];
  deployment?: {
    environment?: EnvironmentEvidence;
    status: string;
    status_code?: number;
    hosting_hints?: {
      provider: string;
      confidence: string;
      evidence: string;
    }[];
    headers?: Record<string, string>;
    limitations?: string[];
  };
  protocol_tests?: unknown[];
  cipher_tests?: unknown[];
  members?: unknown[];
  sessions?: PcapSession[];
  packets_analyzed?: number;
  tls_handshakes_detected?: number;
  pqc_sessions_count?: number;
  quantum_vulnerable_count?: number;
  evidence_records?: EvidenceRecord[];
  summary?: Record<string, unknown>;
  assets?: any[];
};
export type Scan = {
  id: string;
  project: string;
  kind: "code" | "source" | "network" | "binary" | "pcap" | string;
  status: "queued" | "running" | "completed" | "failed" | "cancelled";
  created_at: string;
  finished_at?: string | null;
  input_hash: string;
  engine_version: string;
  payload?: any;
  result: ScanResult | null;
  error: string | null;
};

export type EvidenceRecord = {
  asset_id: string;
  asset_type: string;
  algorithm: string;
  cryptographic_role: string;
  source_surface: string;
  evidence_type: string;
  location_endpoint: string;
  confidence: string;
  timestamp: string;
  input_hash: string;
  engine_version: string;
  severity: string;
  description: string;
  quantum_vulnerable: boolean | null;
  provenance: {
    detector_engine: string;
    detection_technique?: string;
    rule_or_signature?: string;
    raw_match?: string;
    parameters?: Record<string, unknown>;
  };
};

export type DiffItem = {
  primitive: string;
  category: string;
  surface: string;
  location: string;
  severity: string;
  description: string;
  evidence_id?: string;
};

export type VerificationReport = {
  verdict: "VERIFIED" | "NOT_VERIFIED" | "INCONCLUSIVE";
  confidence: string;
  rationale: string;
  baseline_scan_ids: string[];
  post_migration_scan_ids: string[];
  timestamp: string;
  retired_weaknesses: DiffItem[];
  introduced_protections: DiffItem[];
  persisting_risks: DiffItem[];
  regressions: DiffItem[];
  summary: {
    baseline_total: number;
    post_migration_total: number;
    baseline_weak_count: number;
    retired_weaknesses_count: number;
    persisting_risks_count: number;
    regressions_count: number;
    introduced_protections_count: number;
    risk_reduction_percentage: number;
  };
  audit_notes: string[];
};

export type RegulatoryControl = {
  standard: string;
  jurisdiction: string;
  requirement: string;
  deadline_or_milestone?: string;
  applies_to: string;
  status: string;
  source_url: string;
};

export type StandardMapping = {
  category: string;
  legacy_primitive: string;
  target_standard: string;
  security_strength_bits: number;
  controls: RegulatoryControl[];
  guidance: string;
};

export type QuantumResourceEstimate = {
  target_algorithm: string;
  key_size_bits: number;
  attack_type: string;
  logical_qubits: number;
  physical_qubits_estimate: number;
  toffoli_gate_count: number;
  surface_code_distance: number;
  physical_error_rate_assumed: number;
  surface_code_cycle_time_us: number;
  estimated_runtime_hours: number;
  uncertainty_range_hours: string;
  literature_citations: string[];
  assumptions: string[];
  disclaimer: string;
};

export type MigrationPatch = {
  pattern_id: string;
  target_language: string;
  file_path: string;
  original_code: string;
  patched_code: string;
  unified_diff: string;
  transformation_description: string;
  generated_regression_test: string;
  verification_status: string;
  test_output?: string;
  re_scan_summary?: {
    previous_findings_count: number;
    remaining_findings_count: number;
    status: string;
  };
};

export type CustomCryptoFinding = {
  file_path: string;
  line_number: number;
  candidate_snippet: string;
  classification: string;
  is_custom_crypto: boolean;
  confidence: number;
  explanation: string;
  human_review_status: string;
  detection_method: string;
};

export type BenchmarkMetrics = {
  total_samples: number;
  true_positives: number;
  false_positives: number;
  true_negatives: number;
  false_negatives: number;
  precision: number;
  recall: number;
  f1_score: number;
  accuracy: number;
  details: Array<{
    id: string;
    name: string;
    actual: boolean;
    predicted: boolean;
    verdict: string;
    confidence: number;
    explanation: string;
  }>;
};

export type SihDemoStep = {
  step_number: number;
  title: string;
  summary: string;
  data: Record<string, unknown>;
};

export type SihDemoExecution = {
  status: string;
  total_steps: number;
  steps: SihDemoStep[];
  cbom: {
    components?: Array<Record<string, unknown>>;
    [key: string]: unknown;
  };
  verification: VerificationReport;
  runtime_trace_summary: Record<string, unknown>;
};

export type Project = {
  id: string;
  name: string;
  description?: string;
  organization?: string;
  environment: "Production" | "Staging" | "Development" | "Research" | "Other";
  business_criticality: "Critical" | "High" | "Medium" | "Low" | "Unknown";
  data_sensitivity: "Public" | "Internal" | "Confidential" | "Sensitive" | "Classified" | "Unknown";
  data_lifetime_years: number;
  migration_target_date?: string;
  owner?: string;
  tags?: string[];
  is_demo?: boolean;
  created_at?: string;
  updated_at?: string;
  metrics?: {
    asset_count: number;
    scan_count: number;
    quantum_risk_count: number;
    last_scan_at?: string;
  };
};

export type User = {
  user_id: string;
  email: string;
  name: string;
  role: "OWNER" | "ADMIN" | "SECURITY_ANALYST" | "VIEWER";
  token?: string;
};

export type ArchiveAnalysis = {
  analysis_id: string;
  filename: string;
  format: string;
  sha256: string;
  size_bytes: number;
  encryption_detected: boolean;
  encryption_type: string;
  kdf_detected: string;
  content_status: string;
  file_count: number;
  uncompressed_size_bytes: number;
  files?: Array<{ filename: string; file_size: number; is_encrypted: boolean }>;
  discovered_assets?: Array<Record<string, unknown>>;
  discovered_evidence?: Array<Record<string, unknown>>;
  security_assessment?: {
    verdict?: string;
    severity?: string;
    explanation?: string;
  };
  recommendations?: string[];
};

export type VaultContainer = {
  format: "ECVAULT";
  format_version: string;
  vault_id: string;
  name: string;
  mode: "PASSWORD_VAULT" | "RECIPIENT_KEY_VAULT" | "PQC_HYBRID_VAULT";
  created_at: string;
  manifest: {
    bulk_cipher: string;
    key_wrap_cipher?: string;
    kdf?: string;
    payload_sha256: string;
    payload_size_bytes: number;
    encrypted_size_bytes: number;
    pqc_status?: string;
  };
  envelopes?: Array<Record<string, unknown>>;
  encrypted_payload?: {
    nonce_hex: string;
    ciphertext_b64: string;
  };
};

export async function requestApi<T>(
  path: string,
  project: string,
  token: string,
  body?: unknown,
  method?: string
): Promise<T> {
  const headers: Record<string, string> = {};
  if (token) headers.Authorization = `Bearer ${token}`;
  if (body && !(body instanceof FormData))
    headers["Content-Type"] = "application/json";

  const separator = path.includes("?") ? "&" : "?";
  const url = `/api${path}${separator}project=${encodeURIComponent(project)}`;

  const response = await fetch(url, {
    method: method || (body === undefined ? "GET" : "POST"),
    headers,
    body:
      body instanceof FormData
        ? body
        : body === undefined
          ? undefined
          : JSON.stringify(body),
    signal: AbortSignal.timeout(35000),
    cache: "no-store",
  });

  let data: any;
  const text = await response.text();
  try {
    data = text ? JSON.parse(text) : {};
  } catch {
    data = { detail: text || `HTTP ${response.status} ${response.statusText}` };
  }

  if (!response.ok)
    throw new Error(
      typeof data.detail === "string"
        ? data.detail
        : JSON.stringify(data.detail || data),
    );
  return data;
}

