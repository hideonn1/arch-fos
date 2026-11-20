import { useQuery } from "@tanstack/react-query";
import { fetchRules } from "../api/client";
import { FileCode2 } from "lucide-react";

export function RulesPanel() {
  const rulesQuery = useQuery({
    queryKey: ["rules"],
    queryFn: fetchRules,
  });

  return (
    <div className="rounded-xl border border-slate-800 bg-slate-900/70 p-5">
      <div className="mb-4 flex items-center gap-2">
        <FileCode2 className="h-4 w-4 text-sky-400" />
        <div>
          <h2 className="text-base font-semibold text-slate-100">
            Reglas YAML estilo Sigma (US-29)
          </h2>
          <p className="text-xs text-slate-400">
            Reglas cargadas con recarga en caliente y mapeo opcional a MITRE ATT&CK
          </p>
        </div>
      </div>

      {rulesQuery.isLoading ? (
        <p className="text-xs text-slate-400">Cargando reglas...</p>
      ) : (rulesQuery.data?.items.length ?? 0) === 0 ? (
        <p className="text-xs text-slate-500">
          Sin reglas sincronizadas todavía (ejecuta el colector apuntando a rules/).
        </p>
      ) : (
        <div className="space-y-3">
          {rulesQuery.data?.items.map((rule) => {
            const mitre = rule.mitre_attack as
              | { tactic?: string; technique_id?: string; technique_name?: string }
              | null
              | undefined;
            return (
              <div
                key={rule.id}
                className="rounded-lg border border-slate-800 bg-slate-950/60 p-4 text-xs"
              >
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <div className="flex items-center gap-2">
                    <span className="rounded bg-sky-500/15 px-2 py-0.5 font-mono uppercase text-sky-300">
                      {rule.severity}
                    </span>
                    <span className="font-semibold text-slate-100">{rule.name}</span>
                    <span className="font-mono text-slate-500">{rule.id}</span>
                  </div>
                  <div className="flex items-center gap-2">
                    {mitre?.technique_id && (
                      <span className="rounded bg-violet-500/15 px-2 py-0.5 font-mono text-violet-300">
                        MITRE {mitre.technique_id} ({mitre.tactic})
                      </span>
                    )}
                    {rule.source_file && (
                      <span className="font-mono text-slate-500">{rule.source_file}</span>
                    )}
                  </div>
                </div>
                <p className="mt-1.5 text-slate-400">{rule.description}</p>
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}
