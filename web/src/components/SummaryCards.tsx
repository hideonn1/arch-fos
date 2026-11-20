import type { OverviewSummary } from "../api/client";
import { AlertTriangle, Activity, Package as PackageIcon, ShieldCheck } from "lucide-react";

interface SummaryCardsProps {
  summary: OverviewSummary;
}

export function SummaryCards({ summary }: SummaryCardsProps) {
  const openFindings =
    summary.findings_by_status.new + summary.findings_by_status.acknowledged;

  return (
    <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 xl:grid-cols-4">
      <div className="rounded-xl border border-slate-800 bg-slate-900/70 p-5">
        <div className="flex items-center justify-between text-slate-400">
          <span className="text-xs font-medium uppercase tracking-wider">
            Hallazgos abiertos
          </span>
          <AlertTriangle className="h-4 w-4 text-amber-400" />
        </div>
        <div className="mt-2 flex items-baseline gap-2">
          <span className="text-3xl font-bold text-slate-100">{openFindings}</span>
          <span className="text-xs text-slate-400">
            de {summary.total_findings} totales
          </span>
        </div>
        <div className="mt-3 flex flex-wrap gap-1.5 text-[11px]">
          <span className="rounded bg-rose-500/15 px-1.5 py-0.5 text-rose-300">
            Crit: {summary.findings_by_severity.critical}
          </span>
          <span className="rounded bg-orange-500/15 px-1.5 py-0.5 text-orange-300">
            High: {summary.findings_by_severity.high}
          </span>
          <span className="rounded bg-amber-500/15 px-1.5 py-0.5 text-amber-300">
            Med: {summary.findings_by_severity.medium}
          </span>
        </div>
      </div>

      <div className="rounded-xl border border-slate-800 bg-slate-900/70 p-5">
        <div className="flex items-center justify-between text-slate-400">
          <span className="text-xs font-medium uppercase tracking-wider">
            Paquetes instalados
          </span>
          <PackageIcon className="h-4 w-4 text-sky-400" />
        </div>
        <div className="mt-2 flex items-baseline gap-2">
          <span className="text-3xl font-bold text-slate-100">
            {summary.packages.total}
          </span>
          <span className="text-xs text-slate-400">
            ({summary.packages.explicit} explícitos)
          </span>
        </div>
        <div className="mt-3 flex gap-2 text-xs text-slate-400">
          <span>Repos: {summary.packages.official}</span>
          <span>•</span>
          <span className="text-amber-300">
            AUR / Foráneos: {summary.packages.foreign}
          </span>
        </div>
      </div>

      <div className="rounded-xl border border-slate-800 bg-slate-900/70 p-5">
        <div className="flex items-center justify-between text-slate-400">
          <span className="text-xs font-medium uppercase tracking-wider">
            CVEs pendientes
          </span>
          <ShieldCheck className="h-4 w-4 text-emerald-400" />
        </div>
        <div className="mt-2 flex items-baseline gap-2">
          <span className="text-3xl font-bold text-slate-100">
            {summary.packages.pending_cve_packages}
          </span>
          <span className="text-xs text-slate-400">paquetes afectados</span>
        </div>
        <p className="mt-3 text-xs text-slate-500">
          Sincronización Arch Security Tracker en Hito 2
        </p>
      </div>

      <div className="rounded-xl border border-slate-800 bg-slate-900/70 p-5">
        <div className="flex items-center justify-between text-slate-400">
          <span className="text-xs font-medium uppercase tracking-wider">
            Eventos registrados
          </span>
          <Activity className="h-4 w-4 text-violet-400" />
        </div>
        <div className="mt-2 flex items-baseline gap-2">
          <span className="text-3xl font-bold text-slate-100">
            {summary.total_events.toLocaleString()}
          </span>
        </div>
        <p className="mt-3 text-xs text-slate-400">
          {summary.packages.last_sync_ts
            ? `Último snapshot: ${new Date(summary.packages.last_sync_ts).toLocaleTimeString()}`
            : "Esperando colector"}
        </p>
      </div>
    </div>
  );
}
