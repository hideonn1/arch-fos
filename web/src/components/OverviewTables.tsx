import { useQuery } from "@tanstack/react-query";
import { fetchEvents, fetchFindings, type OverviewSummary } from "../api/client";

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

export function OverviewTables({ summary }: { summary: OverviewSummary }) {
  const eventsQuery = useQuery({
    queryKey: ["recent-events"],
    queryFn: () => fetchEvents({ limit: 8 }),
  });

  const findingsQuery = useQuery({
    queryKey: ["recent-findings"],
    queryFn: () => fetchFindings({ limit: 8 }),
  });

  return (
    <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
      <div className="rounded-xl border border-slate-800 bg-slate-900/70 p-5">
        <h3 className="mb-3 text-sm font-semibold text-slate-100">
          Top procesos por tráfico
        </h3>
        {summary.top_processes.length === 0 ? (
          <p className="text-xs text-slate-500">
            Sin flujos de red todavía (captura eBPF planificada en Hito 3).
          </p>
        ) : (
          <div className="space-y-2 text-xs">
            {summary.top_processes.map((proc) => (
              <div
                key={proc.comm}
                className="flex items-center justify-between rounded-lg bg-slate-950/60 px-3 py-2"
              >
                <span className="font-mono text-slate-200">{proc.comm}</span>
                <span className="font-mono text-slate-400">
                  {(proc.total_bytes / 1024).toFixed(1)} KiB
                </span>
              </div>
            ))}
          </div>
        )}
      </div>

      <div className="rounded-xl border border-slate-800 bg-slate-900/70 p-5">
        <h3 className="mb-3 text-sm font-semibold text-slate-100">
          Servicios con mayor consumo
        </h3>
        {summary.top_services.length === 0 ? (
          <p className="text-xs text-slate-500">
            Sin métricas de servicios todavía (inventario systemd planificado en Hito 2).
          </p>
        ) : (
          <div className="space-y-2 text-xs">
            {summary.top_services.map((svc) => (
              <div
                key={svc.unit_name}
                className="flex items-center justify-between rounded-lg bg-slate-950/60 px-3 py-2"
              >
                <span className="font-mono text-slate-200">{svc.unit_name}</span>
                <span className="font-mono text-slate-400">
                  {(svc.memory_bytes / (1024 * 1024)).toFixed(1)} MiB
                </span>
              </div>
            ))}
          </div>
        )}
      </div>

      <div className="rounded-xl border border-slate-800 bg-slate-900/70 p-5">
        <h3 className="mb-3 text-sm font-semibold text-slate-100">
          Hallazgos recientes
        </h3>
        {findingsQuery.data?.items.length ? (
          <div className="space-y-2 text-xs">
            {findingsQuery.data.items.map((f) => (
              <div
                key={f.id}
                className="flex items-center justify-between gap-2 rounded-lg bg-slate-950/60 px-3 py-2"
              >
                <div className="min-w-0">
                  <div className="truncate font-medium text-slate-200">
                    {f.title}
                  </div>
                  <div className="text-slate-400">
                    {f.entity_type}: {f.entity_id}
                  </div>
                </div>
                <SeverityBadge severity={f.severity} />
              </div>
            ))}
          </div>
        ) : (
          <p className="text-xs text-slate-500">
            No hay hallazgos registrados aún.
          </p>
        )}
      </div>

      <div className="rounded-xl border border-slate-800 bg-slate-900/70 p-5">
        <h3 className="mb-3 text-sm font-semibold text-slate-100">
          Eventos recientes del colector
        </h3>
        {eventsQuery.data?.items.length ? (
          <div className="space-y-2 text-xs">
            {eventsQuery.data.items.map((ev) => (
              <div
                key={ev.id}
                className="flex items-center justify-between gap-2 rounded-lg bg-slate-950/60 px-3 py-2"
              >
                <div className="min-w-0">
                  <div className="truncate font-mono text-slate-200">
                    {ev.type}
                  </div>
                  <div className="text-slate-400">
                    {ev.entity_type}:{ev.entity_id} •{" "}
                    {new Date(ev.ts).toLocaleString()}
                  </div>
                </div>
                <SeverityBadge severity={ev.severity} />
              </div>
            ))}
          </div>
        ) : (
          <p className="text-xs text-slate-500">No hay eventos recientes.</p>
        )}
      </div>
    </div>
  );
}
