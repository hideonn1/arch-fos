import { useQuery } from "@tanstack/react-query";
import { fetchListeners, fetchServices } from "../api/client";

function formatMb(bytes: number): string {
  return `${(bytes / (1024 * 1024)).toFixed(1)} MiB`;
}

export function ServicesListenersPanel() {
  const servicesQuery = useQuery({
    queryKey: ["services"],
    queryFn: () => fetchServices(100),
  });

  const listenersQuery = useQuery({
    queryKey: ["listeners"],
    queryFn: () => fetchListeners(100),
  });

  return (
    <div className="space-y-6">
      <div className="rounded-xl border border-slate-800 bg-slate-900/70 p-5">
        <h2 className="mb-1 text-base font-semibold text-slate-100">
          Puertos en escucha atribuidos (US-07)
        </h2>
        <p className="mb-4 text-xs text-slate-400">
          Sockets TCP/UDP vía netlink sock_diag resueltos a PID y paquete dueño
        </p>

        {listenersQuery.isLoading ? (
          <p className="text-xs text-slate-400">Cargando puertos...</p>
        ) : (listenersQuery.data?.items.length ?? 0) === 0 ? (
          <p className="text-xs text-slate-500">No hay puertos en escucha registrados.</p>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead className="border-b border-slate-800 uppercase text-slate-400">
                <tr>
                  <th className="py-2 pr-4">Proto</th>
                  <th className="py-2 pr-4">Dirección : Puerto</th>
                  <th className="py-2 pr-4">PID / Proceso</th>
                  <th className="py-2">Paquete dueño</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/70">
                {listenersQuery.data?.items.map((l) => (
                  <tr key={l.id} className="hover:bg-slate-800/40">
                    <td className="py-2 pr-4 font-mono uppercase text-sky-300">
                      {l.protocol}
                    </td>
                    <td className="py-2 pr-4 font-mono text-slate-200">
                      {l.local_addr}:{l.local_port}
                    </td>
                    <td className="py-2 pr-4 text-slate-300">
                      {l.pid ?? "?"} • {l.process_name ?? "desconocido"}
                    </td>
                    <td className="py-2 font-mono text-slate-300">
                      {l.package_name ?? (
                        <span className="text-slate-500">sin paquete</span>
                      )}
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
          Servicios systemd y cgroups (US-06)
        </h2>
        <p className="mb-4 text-xs text-slate-400">
          Estado de habilitación y consumo de recursos vía D-Bus
        </p>

        {servicesQuery.isLoading ? (
          <p className="text-xs text-slate-400">Cargando servicios...</p>
        ) : (servicesQuery.data?.items.length ?? 0) === 0 ? (
          <p className="text-xs text-slate-500">
            Sin servicios registrados (requiere D-Bus systemd en el host).
          </p>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead className="border-b border-slate-800 uppercase text-slate-400">
                <tr>
                  <th className="py-2 pr-4">Unit</th>
                  <th className="py-2 pr-4">Estado</th>
                  <th className="py-2 pr-4">Unit File</th>
                  <th className="py-2 pr-4 text-right">Memoria</th>
                  <th className="py-2 text-right">CPU (ms)</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/70">
                {servicesQuery.data?.items.map((s) => (
                  <tr key={s.unit_name} className="hover:bg-slate-800/40">
                    <td className="py-2 pr-4 font-mono text-slate-200">{s.unit_name}</td>
                    <td className="py-2 pr-4 text-slate-300">
                      {s.active_state} ({s.sub_state})
                    </td>
                    <td className="py-2 pr-4 text-slate-400">{s.unit_file_state}</td>
                    <td className="py-2 pr-4 text-right font-mono text-slate-300">
                      {formatMb(s.memory_bytes)}
                    </td>
                    <td className="py-2 text-right font-mono text-slate-400">
                      {Math.round(s.cpu_usage_ns / 1_000_000)}
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
