import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { fetchPackages } from "../api/client";
import { Search } from "lucide-react";

function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KiB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MiB`;
}

export function PackagesPanel() {
  const [search, setSearch] = useState("");
  const [foreignOnly, setForeignOnly] = useState(false);
  const [cursorStack, setCursorStack] = useState<string[]>([]);
  const currentCursor = cursorStack.at(-1);

  const query = useQuery({
    queryKey: ["packages", search, foreignOnly, currentCursor],
    queryFn: () =>
      fetchPackages({
        q: search.trim() || undefined,
        foreignOnly,
        cursor: currentCursor,
        limit: 25,
      }),
  });

  function handleSearchChange(val: string) {
    setSearch(val);
    setCursorStack([]);
  }

  function handleToggleForeign(val: boolean) {
    setForeignOnly(val);
    setCursorStack([]);
  }

  return (
    <div className="rounded-xl border border-slate-800 bg-slate-900/70 p-5">
      <div className="mb-4 flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
        <div>
          <h2 className="text-base font-semibold text-slate-100">
            Inventario de paquetes (ALPM)
          </h2>
          <p className="text-xs text-slate-400">
            Paquetes de repositorios oficiales y foráneos / AUR
          </p>
        </div>

        <div className="flex flex-wrap items-center gap-2">
          <div className="relative">
            <Search className="pointer-events-none absolute top-2.5 left-3 h-4 w-4 text-slate-500" />
            <input
              type="text"
              value={search}
              onChange={(e) => handleSearchChange(e.target.value)}
              placeholder="Buscar paquete..."
              className="rounded-lg border border-slate-700 bg-slate-950 py-1.5 pr-3 pl-9 text-sm text-slate-100 placeholder-slate-500 focus:border-sky-500 focus:outline-none"
            />
          </div>
          <label className="flex cursor-pointer items-center gap-2 rounded-lg border border-slate-700 bg-slate-950 px-3 py-1.5 text-xs text-slate-300">
            <input
              type="checkbox"
              checked={foreignOnly}
              onChange={(e) => handleToggleForeign(e.target.checked)}
              className="rounded border-slate-600 bg-slate-900 text-sky-500"
            />
            Solo AUR / foráneos
          </label>
        </div>
      </div>

      {query.isLoading ? (
        <div className="py-10 text-center text-sm text-slate-400">
          Cargando inventario...
        </div>
      ) : query.isError ? (
        <div className="py-6 text-sm text-rose-400">
          Error cargando paquetes: {query.error.message}
        </div>
      ) : (
        <>
          <div className="overflow-x-auto">
            <table className="w-full text-left text-sm">
              <thead className="border-b border-slate-800 text-xs uppercase text-slate-400">
                <tr>
                  <th className="py-2 pr-4">Nombre</th>
                  <th className="py-2 pr-4">Versión</th>
                  <th className="py-2 pr-4">Origen</th>
                  <th className="py-2 pr-4">Motivo</th>
                  <th className="py-2 pr-4 text-right">Tamaño</th>
                  <th className="py-2 text-right">Archivos</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/70">
                {query.data?.items.map((pkg) => (
                  <tr key={pkg.name} className="hover:bg-slate-800/40">
                    <td className="py-2.5 pr-4 font-medium text-slate-100">
                      <div>{pkg.name}</div>
                      {pkg.description && (
                        <div className="max-w-md truncate text-xs font-normal text-slate-400">
                          {pkg.description}
                        </div>
                      )}
                    </td>
                    <td className="py-2.5 pr-4 font-mono text-xs text-slate-300">
                      {pkg.version}
                    </td>
                    <td className="py-2.5 pr-4">
                      {pkg.is_foreign ? (
                        <span className="rounded bg-amber-500/15 px-2 py-0.5 text-xs font-medium text-amber-300">
                          foráneo / AUR
                        </span>
                      ) : (
                        <span className="rounded bg-sky-500/15 px-2 py-0.5 text-xs font-medium text-sky-300">
                          {pkg.repo ?? "oficial"}
                        </span>
                      )}
                    </td>
                    <td className="py-2.5 pr-4 text-xs text-slate-400">
                      {pkg.reason === "explicit" ? "explícito" : "dependencia"}
                    </td>
                    <td className="py-2.5 pr-4 text-right font-mono text-xs text-slate-300">
                      {formatBytes(pkg.size_bytes)}
                    </td>
                    <td className="py-2.5 text-right font-mono text-xs text-slate-400">
                      {pkg.files.length}
                    </td>
                  </tr>
                ))}
                {query.data?.items.length === 0 && (
                  <tr>
                    <td
                      colSpan={6}
                      className="py-8 text-center text-sm text-slate-500"
                    >
                      No hay paquetes que coincidan con el filtro actual.
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>

          <div className="mt-4 flex items-center justify-between border-t border-slate-800 pt-3 text-xs text-slate-400">
            <button
              type="button"
              disabled={cursorStack.length === 0}
              onClick={() => setCursorStack((s) => s.slice(0, -1))}
              className="rounded border border-slate-700 px-3 py-1.5 text-slate-200 hover:bg-slate-800 disabled:opacity-40"
            >
              Anterior
            </button>
            <span>Página {cursorStack.length + 1}</span>
            <button
              type="button"
              disabled={!query.data?.has_more || !query.data?.next_cursor}
              onClick={() => {
                const next = query.data?.next_cursor;
                if (next) setCursorStack((s) => [...s, next]);
              }}
              className="rounded border border-slate-700 px-3 py-1.5 text-slate-200 hover:bg-slate-800 disabled:opacity-40"
            >
              Siguiente
            </button>
          </div>
        </>
      )}
    </div>
  );
}
