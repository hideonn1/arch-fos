import type { components } from "./schema";

export type AuthStatus = components["schemas"]["AuthStatus"];
export type OverviewSummary = components["schemas"]["OverviewSummary"];
export type TimeSeriesPoint = components["schemas"]["TimeSeriesPoint"];
export type Package = components["schemas"]["Package"];
export type PackagesPage = components["schemas"]["PackagesPage"];
export type Finding = components["schemas"]["Finding"];
export type FindingsPage = components["schemas"]["FindingsPage"];
export type Event = components["schemas"]["Event"];
export type EventsPage = components["schemas"]["EventsPage"];
export type Service = components["schemas"]["Service"];
export type ServicesPage = components["schemas"]["ServicesPage"];
export type Flow1m = components["schemas"]["Flow1m"];
export type FlowsPage = components["schemas"]["FlowsPage"];
export type Listener = components["schemas"]["Listener"];
export type ListenersPage = components["schemas"]["ListenersPage"];
export type Suppression = components["schemas"]["Suppression"];
export type SuppressionsPage = components["schemas"]["SuppressionsPage"];
export type FindingAuditResponse = components["schemas"]["FindingAuditResponse"];
export type CollectorHealth = components["schemas"]["CollectorHealth"];
export type MutationAck = components["schemas"]["MutationAck"];
export type DnsQuery = components["schemas"]["DnsQuery"];
export type DnsQueriesPage = components["schemas"]["DnsQueriesPage"];
export type ThreatIntelStatusResponse = components["schemas"]["ThreatIntelStatusResponse"];
export type EntityTimelineResponse = components["schemas"]["EntityTimelineResponse"];
export type TimelineEntitiesResponse = components["schemas"]["TimelineEntitiesResponse"];
export type RulesPage = components["schemas"]["RulesPage"];
export type Severity = components["schemas"]["Severity"];
export type FindingStatus = components["schemas"]["FindingStatus"];

export class ApiError extends Error {
  status: number;
  code: string;

  constructor(status: number, code: string, message: string) {
    super(message);
    this.status = status;
    this.code = code;
  }
}

let csrfTokenMemory: string | null = null;

export function setCsrfToken(token: string | null | undefined) {
  csrfTokenMemory = token ?? null;
}

async function apiFetch<T>(path: string, init?: RequestInit): Promise<T> {
  const headers = new Headers(init?.headers);
  const method = (init?.method ?? "GET").toUpperCase();
  if (method !== "GET" && method !== "HEAD") {
    if (!headers.has("Content-Type") && init?.body) {
      headers.set("Content-Type", "application/json");
    }
    if (csrfTokenMemory) {
      headers.set("X-CSRF-Token", csrfTokenMemory);
    }
  }

  const res = await fetch(path, {
    ...init,
    credentials: "same-origin",
    headers,
  });

  if (!res.ok) {
    let code = "http_error";
    let message = `HTTP ${res.status}`;
    try {
      const errBody = (await res.json()) as { error?: string; message?: string };
      code = errBody.error ?? code;
      message = errBody.message ?? message;
    } catch {
      // ignore non-JSON error body
    }
    throw new ApiError(res.status, code, message);
  }

  return (await res.json()) as T;
}

export async function fetchAuthMe(): Promise<AuthStatus> {
  const status = await apiFetch<AuthStatus>("/api/v1/auth/me");
  setCsrfToken(status.csrf_token);
  return status;
}

export async function loginWithToken(token: string): Promise<AuthStatus> {
  const status = await apiFetch<AuthStatus>("/api/v1/auth/login", {
    method: "POST",
    body: JSON.stringify({ token }),
  });
  setCsrfToken(status.csrf_token);
  return status;
}

export async function logout(): Promise<AuthStatus> {
  const status = await apiFetch<AuthStatus>("/api/v1/auth/logout", {
    method: "POST",
  });
  setCsrfToken(null);
  return status;
}

export function fetchSummary(): Promise<OverviewSummary> {
  return apiFetch<OverviewSummary>("/api/v1/summary");
}

export function fetchPackages(params: {
  q?: string;
  foreignOnly?: boolean;
  cursor?: string;
  limit?: number;
}): Promise<PackagesPage> {
  const qs = new URLSearchParams();
  if (params.q) qs.set("q", params.q);
  if (params.foreignOnly) qs.set("foreign_only", "true");
  if (params.cursor) qs.set("cursor", params.cursor);
  if (params.limit) qs.set("limit", String(params.limit));
  return apiFetch<PackagesPage>(`/api/v1/packages?${qs.toString()}`);
}

export function fetchFindings(params: {
  severity?: Severity | "";
  status?: FindingStatus | "";
  cursor?: string;
  limit?: number;
}): Promise<FindingsPage> {
  const qs = new URLSearchParams();
  if (params.severity) qs.set("severity", params.severity);
  if (params.status) qs.set("status", params.status);
  if (params.cursor) qs.set("cursor", params.cursor);
  if (params.limit) qs.set("limit", String(params.limit));
  return apiFetch<FindingsPage>(`/api/v1/findings?${qs.toString()}`);
}

export function fetchEvents(params: {
  severity?: Severity | "";
  entityType?: string;
  cursor?: string;
  limit?: number;
}): Promise<EventsPage> {
  const qs = new URLSearchParams();
  if (params.severity) qs.set("severity", params.severity);
  if (params.entityType) qs.set("entity_type", params.entityType);
  if (params.cursor) qs.set("cursor", params.cursor);
  if (params.limit) qs.set("limit", String(params.limit));
  return apiFetch<EventsPage>(`/api/v1/events?${qs.toString()}`);
}

export function fetchServices(limit = 50): Promise<ServicesPage> {
  return apiFetch<ServicesPage>(`/api/v1/services?limit=${limit}`);
}

export function fetchFlows(limit = 50): Promise<FlowsPage> {
  return apiFetch<FlowsPage>(`/api/v1/flows?limit=${limit}`);
}

export function fetchListeners(limit = 100): Promise<ListenersPage> {
  return apiFetch<ListenersPage>(`/api/v1/listeners?limit=${limit}`);
}

export function fetchCollectorHealth(): Promise<CollectorHealth> {
  return apiFetch<CollectorHealth>("/api/v1/health/collector");
}

export function updateFindingStatus(
  id: number,
  status: FindingStatus,
  note?: string
): Promise<MutationAck> {
  return apiFetch<MutationAck>(`/api/v1/findings/${id}`, {
    method: "PATCH",
    body: JSON.stringify({ status, note: note ?? "" }),
  });
}

export function fetchFindingAudit(id: number): Promise<FindingAuditResponse> {
  return apiFetch<FindingAuditResponse>(`/api/v1/findings/${id}/audit`);
}

export function fetchSuppressions(): Promise<SuppressionsPage> {
  return apiFetch<SuppressionsPage>("/api/v1/suppressions");
}

export function createSuppression(payload: {
  rule_id: string;
  entity_type: string;
  entity_id: string;
  reason?: string;
  expires_at?: number | null;
}): Promise<MutationAck> {
  return apiFetch<MutationAck>("/api/v1/suppressions", {
    method: "POST",
    body: JSON.stringify(payload),
  });
}

export function deleteSuppression(id: number): Promise<MutationAck> {
  return apiFetch<MutationAck>(`/api/v1/suppressions/${id}`, {
    method: "DELETE",
  });
}

export function fetchDnsQueries(limit = 50): Promise<DnsQueriesPage> {
  return apiFetch<DnsQueriesPage>(`/api/v1/dns?limit=${limit}`);
}

export function fetchThreatIntelStatus(): Promise<ThreatIntelStatusResponse> {
  return apiFetch<ThreatIntelStatusResponse>("/api/v1/threat-intel/status");
}

export function fetchTimelineEntities(): Promise<TimelineEntitiesResponse> {
  return apiFetch<TimelineEntitiesResponse>("/api/v1/timeline/entities");
}

export function fetchEntityTimeline(
  entityType: string,
  entityId: string
): Promise<EntityTimelineResponse> {
  const qs = new URLSearchParams({ entity_type: entityType, entity_id: entityId });
  return apiFetch<EntityTimelineResponse>(`/api/v1/timeline?${qs.toString()}`);
}

export function fetchRules(): Promise<RulesPage> {
  return apiFetch<RulesPage>("/api/v1/rules");
}
