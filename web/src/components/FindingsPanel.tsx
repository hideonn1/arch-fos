import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
  createSuppression,
  deleteSuppression,
  explainFinding,
  fetchFindingAudit,
  fetchFindings,
  fetchSuppressions,
  updateFindingStatus,
  type Finding,
  type FindingStatus,
  type LlmExplanation,
  type Severity,
} from "../api/client";
import {
  Ban,
  BookOpen,
  CheckCircle2,
  Eye,
  History,
  RotateCcw,
  Sparkles,
  Trash2,
} from "lucide-react";

function SeverityBadge({ severity }: { severity: string }) {
  const styles: Record<string, string> = {
    critical: "bg-rose-500/20 text-rose-300",
    high: "bg-orange-500/20 text-orange-300",
    medium: "bg-amber-500/20 text-amber-300",
    low: "bg-sky-500/20 text-sky-300",
    info: "bg-slate-700/60 text-slate-300",
  };
  return (
    <span
      className={`rounded px-2 py-0.5 text-[11px] font-medium uppercase ${
        styles[severity] ?? styles.info
      }`}
    >
      {severity}
    </span>
  );
}

function StatusBadge({ status }: { status: string }) {
  const styles: Record<string, string> = {
    new: "bg-rose-500/15 text-rose-300 border-rose-700/50",
    acknowledged: "bg-sky-500/15 text-sky-300 border-sky-700/50",
    ignored: "bg-slate-700/40 text-slate-400 border-slate-700",
    resolved: "bg-emerald-500/15 text-emerald-300 border-emerald-700/50",
  };
  return (
    <span
      className={`rounded border px-2 py-0.5 text-[11px] font-medium ${
        styles[status] ?? styles.new
      }`}
    >
      {status}
    </span>
  );
}

function AuditDrawer({ findingId }: { findingId: number }) {
  const auditQuery = useQuery({
    queryKey: ["finding-audit", findingId],
    queryFn: () => fetchFindingAudit(findingId),
  });

  if (auditQuery.isLoading) {
    return <p className="mt-2 text-xs text-slate-400">Cargando auditoría...</p>;
  }
  const items = auditQuery.data?.items ?? [];
  if (items.length === 0) {
    return (
      <p className="mt-2 text-xs text-slate-500">
        Sin cambios registrados en el historial de auditoría.
      </p>
    );
  }
  return (
    <div className="mt-2 space-y-1.5 rounded-lg border border-slate-800 bg-slate-950/70 p-3 text-xs">
      {items.map((entry) => (
        <div key={entry.id} className="flex flex-wrap items-center justify-between gap-2">
          <div>
            <span className="font-medium text-slate-200">{entry.actor}</span>{" "}
            <span className="text-slate-400">({entry.action})</span>:{" "}
            <span className="font-mono text-slate-300">
              {entry.old_status ?? "-"} → {entry.new_status ?? "-"}
            </span>
            {entry.note && (
              <span className="ml-2 text-slate-400">— &quot;{entry.note}&quot;</span>
            )}
          </div>
          <span className="text-slate-500">{new Date(entry.ts).toLocaleString()}</span>
        </div>
      ))}
    </div>
  );
}

export function FindingsPanel() {
  const queryClient = useQueryClient();
  const [statusFilter, setStatusFilter] = useState<FindingStatus | "">("");
  const [severityFilter, setSeverityFilter] = useState<Severity | "">("");
  const [expandedAuditId, setExpandedAuditId] = useState<number | null>(null);
  const [explanations, setExplanations] = useState<Record<number, LlmExplanation>>({});
  const [explainingId, setExplainingId] = useState<number | null>(null);
  const [suppressDays, setSuppressDays] = useState<number>(30);
  const [actionError, setActionError] = useState<string | null>(null);

  const findingsQuery = useQuery({
    queryKey: ["findings", statusFilter, severityFilter],
    queryFn: () =>
      fetchFindings({
        status: statusFilter,
        severity: severityFilter,
        limit: 50,
      }),
  });

  const suppressionsQuery = useQuery({
    queryKey: ["suppressions"],
    queryFn: fetchSuppressions,
  });

  const statusMutation = useMutation({
    mutationFn: ({ id, status, note }: { id: number; status: FindingStatus; note?: string }) =>
      updateFindingStatus(id, status, note),
    onSuccess: async () => {
      setActionError(null);
      await queryClient.invalidateQueries({ queryKey: ["findings"] });
      await queryClient.invalidateQueries({ queryKey: ["summary"] });
      await queryClient.invalidateQueries({ queryKey: ["finding-audit"] });
    },
    onError: (err: Error) => setActionError(err.message),
  });

  const suppressMutation = useMutation({
    mutationFn: (finding: Finding) => {
      const expiresAt =
        suppressDays > 0 ? Date.now() + suppressDays * 24 * 60 * 60 * 1000 : null;
      return createSuppression({
        rule_id: finding.rule_id,
        entity_type: finding.entity_type,
        entity_id: finding.entity_id,
        reason: `Suprimido desde dashboard (${suppressDays > 0 ? `${suppressDays}d` : "permanente"})`,
        expires_at: expiresAt,
      });
    },
    onSuccess: async () => {
      setActionError(null);
      await queryClient.invalidateQueries({ queryKey: ["findings"] });
      await queryClient.invalidateQueries({ queryKey: ["suppressions"] });
      await queryClient.invalidateQueries({ queryKey: ["summary"] });
    },
    onError: (err: Error) => setActionError(err.message),
  });

  const deleteSupMutation = useMutation({
    mutationFn: (id: number) => deleteSuppression(id),
    onSuccess: async () => {
      setActionError(null);
      await queryClient.invalidateQueries({ queryKey: ["suppressions"] });
    },
    onError: (err: Error) => setActionError(err.message),
  });

  async function handleExplain(findingId: number) {
    setActionError(null);
    setExplainingId(findingId);
    try {
      const result = await explainFinding(findingId);
      setExplanations((prev) => ({ ...prev, [findingId]: result }));
      await queryClient.invalidateQueries({ queryKey: ["suggested-actions"] });
    } catch (err) {
      setActionError(err instanceof Error ? err.message : "Error consultando Ollama");
    } finally {
      setExplainingId(null);
    }
  }

  return (
    <div className="space-y-6">
      <div className="rounded-xl border border-slate-800 bg-slate-900/70 p-5">
        <div className="mb-4 flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
          <div>
            <h2 className="text-base font-semibold text-slate-100">
              Gestión de hallazgos (US-23)
            </h2>
            <p className="text-xs text-slate-400">
              Cambia estados, consulta auditoría o suprime reglas por entidad con expiración
            </p>
          </div>

          <div className="flex flex-wrap items-center gap-2 text-xs">
            <select
              value={statusFilter}
              onChange={(e) => setStatusFilter(e.target.value as FindingStatus | "")}
              className="rounded-lg border border-slate-700 bg-slate-950 px-2.5 py-1.5 text-slate-200"
            >
              <option value="">Todos los estados</option>
              <option value="new">new</option>
              <option value="acknowledged">acknowledged</option>
              <option value="ignored">ignored</option>
              <option value="resolved">resolved</option>
            </select>
            <select
              value={severityFilter}
              onChange={(e) => setSeverityFilter(e.target.value as Severity | "")}
              className="rounded-lg border border-slate-700 bg-slate-950 px-2.5 py-1.5 text-slate-200"
            >
              <option value="">Todas las severidades</option>
              <option value="critical">critical</option>
              <option value="high">high</option>
              <option value="medium">medium</option>
              <option value="low">low</option>
              <option value="info">info</option>
            </select>
            <label className="flex items-center gap-1.5 text-slate-400">
              Supresión (días):
              <input
                type="number"
                min={0}
                max={3650}
                value={suppressDays}
                onChange={(e) => setSuppressDays(Number(e.target.value) || 0)}
                className="w-16 rounded border border-slate-700 bg-slate-950 px-2 py-1 text-slate-200"
              />
            </label>
          </div>
        </div>

        {actionError && (
          <div className="mb-4 rounded-lg border border-rose-800/70 bg-rose-950/50 px-3 py-2 text-xs text-rose-300">
            {actionError}
          </div>
        )}

        {findingsQuery.isLoading ? (
          <div className="py-10 text-center text-sm text-slate-400">Cargando hallazgos...</div>
        ) : (findingsQuery.data?.items.length ?? 0) === 0 ? (
          <div className="py-10 text-center text-sm text-slate-500">
            No hay hallazgos para los filtros seleccionados.
          </div>
        ) : (
          <div className="space-y-3">
            {findingsQuery.data?.items.map((f) => (
              <div
                key={f.id}
                className="rounded-lg border border-slate-800 bg-slate-950/60 p-4"
              >
                <div className="flex flex-col gap-3 sm:flex-row sm:items-start sm:justify-between">
                  <div className="space-y-1">
                    <div className="flex flex-wrap items-center gap-2">
                      <SeverityBadge severity={f.severity} />
                      <StatusBadge status={f.status} />
                      <span className="font-mono text-xs text-slate-400">{f.rule_id}</span>
                    </div>
                    <h3 className="text-sm font-semibold text-slate-100">{f.title}</h3>
                    <p className="text-xs text-slate-400">{f.summary}</p>
                    <p className="font-mono text-[11px] text-slate-500">
                      Entidad: {f.entity_type}:{f.entity_id} • Detectado:{" "}
                      {new Date(f.ts).toLocaleString()}
                    </p>
                  </div>

                  <div className="flex flex-wrap gap-1.5 text-xs">
                    {f.status !== "acknowledged" && (
                      <button
                        type="button"
                        onClick={() =>
                          statusMutation.mutate({
                            id: f.id,
                            status: "acknowledged",
                            note: "Reconocido desde dashboard",
                          })
                        }
                        className="flex items-center gap-1 rounded border border-sky-700/60 bg-sky-500/10 px-2.5 py-1 text-sky-300 hover:bg-sky-500/20"
                      >
                        <Eye className="h-3.5 w-3.5" />
                        Reconocer
                      </button>
                    )}
                    {f.status !== "resolved" && (
                      <button
                        type="button"
                        onClick={() =>
                          statusMutation.mutate({
                            id: f.id,
                            status: "resolved",
                            note: "Resuelto desde dashboard",
                          })
                        }
                        className="flex items-center gap-1 rounded border border-emerald-700/60 bg-emerald-500/10 px-2.5 py-1 text-emerald-300 hover:bg-emerald-500/20"
                      >
                        <CheckCircle2 className="h-3.5 w-3.5" />
                        Resolver
                      </button>
                    )}
                    {f.status !== "new" && (
                      <button
                        type="button"
                        onClick={() =>
                          statusMutation.mutate({
                            id: f.id,
                            status: "new",
                            note: "Reabierto desde dashboard",
                          })
                        }
                        className="flex items-center gap-1 rounded border border-slate-700 px-2.5 py-1 text-slate-300 hover:bg-slate-800"
                      >
                        <RotateCcw className="h-3.5 w-3.5" />
                        Reabrir
                      </button>
                    )}
                    <button
                      type="button"
                      onClick={() => suppressMutation.mutate(f)}
                      className="flex items-center gap-1 rounded border border-amber-700/60 bg-amber-500/10 px-2.5 py-1 text-amber-300 hover:bg-amber-500/20"
                    >
                      <Ban className="h-3.5 w-3.5" />
                      Suprimir
                    </button>
                    <button
                      type="button"
                      disabled={explainingId === f.id}
                      onClick={() => handleExplain(f.id)}
                      className="flex items-center gap-1 rounded border border-violet-700/60 bg-violet-500/10 px-2.5 py-1 text-violet-300 hover:bg-violet-500/20 disabled:opacity-50"
                    >
                      <Sparkles className="h-3.5 w-3.5" />
                      {explainingId === f.id ? "Analizando..." : "Explicar con IA"}
                    </button>
                    <button
                      type="button"
                      onClick={() =>
                        setExpandedAuditId((prev) => (prev === f.id ? null : f.id))
                      }
                      className="flex items-center gap-1 rounded border border-slate-700 px-2.5 py-1 text-slate-300 hover:bg-slate-800"
                    >
                      <History className="h-3.5 w-3.5" />
                      Auditoría
                    </button>
                  </div>
                </div>

                {explanations[f.id] && (
                  <div className="mt-3 space-y-2 rounded-lg border border-violet-800/50 bg-violet-950/20 p-3.5 text-xs">
                    <div className="flex flex-wrap items-center justify-between gap-2">
                      <span className="font-semibold text-violet-300">
                        Explicación IA ({explanations[f.id].model})
                      </span>
                      <span className="rounded bg-slate-800 px-2 py-0.5 text-[11px] text-slate-300">
                        {explanations[f.id].cached ? "caché local" : "recién generada"}
                      </span>
                    </div>
                    <p className="text-slate-200">{explanations[f.id].summary}</p>
                    <p className="text-amber-300">
                      <strong>Riesgo:</strong> {explanations[f.id].risk}
                    </p>
                    {explanations[f.id].suggested_actions.length > 0 && (
                      <div>
                        <div className="mb-1 font-medium text-slate-300">
                          Acciones sugeridas (enviadas a revisión manual en estado pending):
                        </div>
                        <ul className="space-y-1 font-mono text-[11px] text-sky-300">
                          {explanations[f.id].suggested_actions.map((cmd, idx) => (
                            <li key={idx} className="rounded bg-slate-950/70 px-2 py-1">
                              $ {cmd}
                            </li>
                          ))}
                        </ul>
                      </div>
                    )}
                    {explanations[f.id].references.length > 0 && (
                      <div className="flex flex-wrap items-center gap-2 pt-1 text-[11px] text-slate-400">
                        <BookOpen className="h-3.5 w-3.5 text-sky-400" />
                        {explanations[f.id].references.map((url, idx) => (
                          <a
                            key={idx}
                            href={url}
                            target="_blank"
                            rel="noreferrer"
                            className="underline hover:text-sky-300"
                          >
                            {url}
                          </a>
                        ))}
                      </div>
                    )}
                  </div>
                )}

                {expandedAuditId === f.id && <AuditDrawer findingId={f.id} />}
              </div>
            ))}
          </div>
        )}
      </div>

      <div className="rounded-xl border border-slate-800 bg-slate-900/70 p-5">
        <h3 className="mb-3 text-sm font-semibold text-slate-100">
          Supresiones activas ({suppressionsQuery.data?.items.length ?? 0})
        </h3>
        {(suppressionsQuery.data?.items.length ?? 0) === 0 ? (
          <p className="text-xs text-slate-500">No hay reglas de supresión registradas.</p>
        ) : (
          <div className="space-y-2 text-xs">
            {suppressionsQuery.data?.items.map((sup) => (
              <div
                key={sup.id}
                className="flex flex-wrap items-center justify-between gap-2 rounded-lg bg-slate-950/60 px-3 py-2"
              >
                <div>
                  <span className="font-mono text-amber-300">{sup.rule_id}</span>{" "}
                  <span className="text-slate-300">
                    ({sup.entity_type}:{sup.entity_id})
                  </span>
                  {sup.reason && <span className="ml-2 text-slate-400">— {sup.reason}</span>}
                </div>
                <div className="flex items-center gap-3">
                  <span className="text-slate-500">
                    {sup.expires_at
                      ? `Expira: ${new Date(sup.expires_at).toLocaleDateString()}`
                      : "Permanente"}
                  </span>
                  <button
                    type="button"
                    onClick={() => deleteSupMutation.mutate(sup.id)}
                    className="rounded border border-slate-700 p-1 text-rose-300 hover:bg-slate-800"
                    title="Eliminar supresión"
                  >
                    <Trash2 className="h-3.5 w-3.5" />
                  </button>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}
