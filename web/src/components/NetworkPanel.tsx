import { useQuery } from "@tanstack/react-query";
import { fetchDnsQueries, fetchFlows, fetchThreatIntelStatus } from "../api/client";
import { Globe, ShieldAlert } from "lucide-react";

export function NetworkPanel() {
  const threatQuery = useQuery({
    queryKey: ["threat-intel-status"],
    queryFn: fetchThreatIntelStatus,
  });

  const flowsQuery = useQuery({
    queryKey: ["flows"],
    queryFn: () => fetchFlows(50),
  });

  const dnsQuery = useQuery({
    queryKey: ["dns-queries"],
    queryFn: () => fetchDnsQueries(50),
  });

  return (
    <div className="space-y-6">
      <div className="rounded-xl border border-slate-800 bg-slate-900/70 p-5">
        <div className="mb-3 flex items-center justify-between">
          <div className="flex items-center gap-2">
            <ShieldAlert className="h-4 w-4 text-rose-400" />
            <h2 className="text-base font-semibold text-slate-100">
              Inteligencia de amenazas (US-18)
            </h2>
          </div>
          <span className="rounded bg-slate-800 px-2 py-0.5 text-xs text-slate-300">
            {threatQuery.data?.total_indicators.toLocaleString() ?? 0} indicadores en caché
          </span>
        </div>

        <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
          {threatQuery.data?.feeds.map((feed) => (
            <div
              key={feed.feed_name}
              className="rounded-lg border border-slate-800 bg-slate-950/60 p-4 text-xs"
            >
              <div className="flex items-center justify-between">
                <span className="font-mono font-semibold text-slate-200">
                  {feed.feed_name}
                </span>
                <span className="text-sky-300">
                  {feed.indicator_count.toLocaleString()} indicadores
                </span>
              </div>
              <p className="mt-2 text-slate-400">
                Última actualización:{" "}
                {feed.last_synced_at
                  ? new Date(feed.last_synced_at).toLocaleString()
                  : "Pendiente de sincronización online"}
              </p>
            </div>
          ))}
        </div>
      </div>

      <div className="rounded-xl border border-slate-800 bg-slate-900/70 p-5">
        <div className="mb-3 flex items-center gap-2">
          <Globe className="h-4 w-4 text-sky-400" />
          <div>
            <h2 className="text-base font-semibold text-slate-100">
              Flujos agregados por minuto (US-16)
            </h2>
            <p className="text-xs text-slate-400">
              Conexiones salientes atribuidas por proceso vía eBPF / modo degradado sock_diag
            </p>
          </div>
        </div>

        {flowsQuery.isLoading ? (
          <p className="text-xs text-slate-400">Cargando flujos...</p>
        ) : (flowsQuery.data?.items.length ?? 0) === 0 ? (
          <p className="text-xs text-slate-500">Sin flujos de red registrados todavía.</p>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead className="border-b border-slate-800 uppercase text-slate-400">
                <tr>
                  <th className="py-2 pr-4">Proceso (PID)</th>
                  <th className="py-2 pr-4">Proto</th>
                  <th className="py-2 pr-4">Destino</th>
                  <th className="py-2 pr-4 text-right">TX / RX</th>
                  <th className="py-2 text-right">Paquetes</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/70">
                {flowsQuery.data?.items.map((flow) => (
                  <tr key={flow.id} className="hover:bg-slate-800/40">
                    <td className="py-2 pr-4 font-mono text-slate-200">
                      {flow.comm} ({flow.pid ?? "?"})
                    </td>
                    <td className="py-2 pr-4 font-mono uppercase text-sky-300">
                      {flow.protocol}
                    </td>
                    <td className="py-2 pr-4 font-mono text-slate-300">
                      {flow.dst_ip}:{flow.dst_port}
                    </td>
                    <td className="py-2 pr-4 text-right font-mono text-slate-400">
                      {flow.bytes_tx} / {flow.bytes_rx} B
                    </td>
                    <td className="py-2 text-right font-mono text-slate-400">
                      {flow.packets}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      <div className="rounded-xl border border-slate-800 bg-slate-900/70 p-5">
        <h2 className="mb-1 text-base font-semibold text-slate-100">
          Consultas DNS recientes (US-17)
        </h2>
        <p className="mb-3 text-xs text-slate-400">
          Dominios consultados, entropía de Shannon y tasa NXDOMAIN por proceso
        </p>

        {dnsQuery.isLoading ? (
          <p className="text-xs text-slate-400">Cargando consultas DNS...</p>
        ) : (dnsQuery.data?.items.length ?? 0) === 0 ? (
          <p className="text-xs text-slate-500">Sin consultas DNS capturadas todavía.</p>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead className="border-b border-slate-800 uppercase text-slate-400">
                <tr>
                  <th className="py-2 pr-4">Proceso</th>
                  <th className="py-2 pr-4">Dominio</th>
                  <th className="py-2 pr-4">Tipo</th>
                  <th className="py-2 pr-4">Código</th>
                  <th className="py-2 text-right">Entropía</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/70">
                {dnsQuery.data?.items.map((d) => (
                  <tr key={d.id} className="hover:bg-slate-800/40">
                    <td className="py-2 pr-4 font-mono text-slate-200">{d.comm}</td>
                    <td className="py-2 pr-4 font-mono text-slate-300">{d.qname}</td>
                    <td className="py-2 pr-4 font-mono text-slate-400">{d.qtype}</td>
                    <td className="py-2 pr-4 font-mono">
                      {d.rcode === 3 ? (
                        <span className="rounded bg-amber-500/20 px-1.5 py-0.5 text-amber-300">
                          NXDOMAIN
                        </span>
                      ) : (
                        <span className="text-slate-400">{d.rcode}</span>
                      )}
                    </td>
                    <td className="py-2 text-right font-mono text-slate-300">
                      {d.entropy.toFixed(2)}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
}
