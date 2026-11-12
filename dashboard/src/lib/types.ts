/** Shapes returned by the CipherCompute API (see /openapi.json). */

export type Role = "owner" | "admin" | "analyst" | "viewer";
export type JobStatus = "queued" | "running" | "succeeded" | "failed" | "cancelled";

export interface Page<T> {
  items: T[];
  next_cursor: string | null;
}

export interface Me {
  principal_type: "user" | "api_key";
  principal_id: string;
  organization_id: string;
  role: Role;
  scopes: string[];
  email: string | null;
}

export interface Project {
  id: string;
  name: string;
  description: string;
  created_at: string;
}

export interface CkksParams {
  poly_modulus_degree: number;
  coeff_mod_bit_sizes: number[];
  scale_bits: number;
  security_level: number;
}

export interface KeyBundle {
  id: string;
  project_id: string;
  ring_id: string | null;
  fingerprint: string | null;
  params: CkksParams | null;
  size_bytes: number | null;
  status: "pending" | "active" | "revoked";
  created_at: string;
  revoked_at: string | null;
}

export interface Dataset {
  id: string;
  project_id: string;
  key_bundle_id: string;
  name: string;
  description: string;
  created_at: string;
}

export interface Ciphertext {
  id: string;
  dataset_id: string;
  label: string;
  status: "pending" | "ready";
  size_bytes: number | null;
  declared_size_bytes: number;
  fingerprint: string | null;
  length: number | null;
  levels_consumed: number | null;
  created_at: string;
}

export interface DepthReport {
  poly_modulus_degree: number;
  security_level: number;
  scale_bits: number;
  levels_total: number;
  levels_consumed: number;
  levels_remaining: number;
  precision_bits: number;
  precision_measured: boolean;
}

export interface Job {
  id: string;
  project_id: string;
  key_bundle_id: string;
  operation: string;
  args: Record<string, unknown>;
  input_ids: string[];
  input_fingerprints: string[];
  manifest_hash: string;
  status: JobStatus;
  attempts: number;
  plan: { params: CkksParams; report: DepthReport; steps: Array<{ operation: string; cost: number }> };
  depth_report: DepthReport | null;
  result_fingerprint: string | null;
  result_length: number | null;
  result_size_bytes: number | null;
  error: { code: string; message: string } | null;
  created_at: string;
  started_at: string | null;
  finished_at: string | null;
  compute_seconds: number | null;
}

export interface Operation {
  name: string;
  summary: string;
  min_inputs: number;
  max_inputs: number | null;
  reveals: string[];
}

export interface ParameterSet extends CkksParams {
  profile: "balanced" | "deep";
  depth: number;
  slots: number;
  integer_headroom_bits: number;
  precision_bits_by_level: Record<string, number>;
  precision_measured: boolean;
}

export interface Advice {
  params: CkksParams;
  profile: "balanced" | "deep";
  required_depth: number;
  report: DepthReport;
  alternatives: Array<{ profile: string; params: CkksParams }>;
}

export interface AuditEvent {
  seq: number;
  id: string;
  occurred_at: string;
  actor_type: string;
  actor_id: string | null;
  action: string;
  resource_type: string;
  resource_id: string | null;
  ip: string | null;
  request_id: string | null;
  trace_id: string | null;
  details: Record<string, unknown>;
  prev_hash: string;
  hash: string;
}

export interface ChainVerification {
  valid: boolean;
  checked: number;
  head_hash: string | null;
  first_broken_seq: number | null;
  reason: string | null;
}

export interface ApiKey {
  id: string;
  name: string;
  prefix: string;
  role: Role;
  scopes: string[];
  created_at: string;
  expires_at: string | null;
  revoked_at: string | null;
  last_used_at: string | null;
}

export interface Usage {
  window_days: number;
  jobs_by_status: Partial<Record<JobStatus, number>>;
  jobs_by_operation: Array<{ operation: string; jobs: number; compute_seconds: number }>;
  jobs_per_day: Array<{ date: string; jobs: number }>;
  compute_seconds: number;
  storage_bytes: { ciphertexts: number; key_bundles: number; results: number; total: number };
}
