import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
  fetchSuggestedActions,
  reviewSuggestedAction,
  searchWiki,
  type ActionStatus,
} from "../api/client";
import { BookOpen, Check, Copy, Search, ShieldCheck, X } from "lucide-react";

export function AiActionsPanel() {
  const queryClient = useQueryClient();
  const [statusFilter, setStatusFilter] = useState<ActionStatus | "">("pending");
  const [wikiQuery, setWikiQuery] = useState("pacman mtree integrity");
  const [submittedWikiQuery, setSubmittedWikiQuery] = useState("pacman mtree integrity");
  const [copiedId, setCopiedId] = useState<number | null>(null);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);

  const actionsQuery = useQuery({
    queryKey: ["suggested-actions", statusFilter],
    queryFn: () => fetchSuggestedActions(statusFilter),
  });

  const wikiSearchQuery = useQuery({
    queryKey: ["wiki-search", submittedWikiQuery],
    queryFn: () => searchWiki(submittedWikiQuery, 5),
    enabled: submittedWikiQuery.trim().length > 0,
  });

  const reviewMutation = useMutation({
    mutationFn: ({ id, status }: { id: number; status: ActionStatus }) =>
      reviewSuggestedAction(id, status),
    onSuccess: async () => {
      setErrorMsg(null);
      await queryClient.invalidateQueries({ queryKey: ["suggested-actions"] });
    },
    onError: (err: Error) => setErrorMsg(err.message),
  });

  function copyCommand(id: number, cmd: string) {
    void navigator.clipboard?.writeText(cmd);
    setCopiedId(id);
    setTimeout(() => setCopiedId((cur) => (cur === id ? null : cur)), 1500);
  }

  return (
    <div className="space-y-6">
      <div className="rounded-xl border border-slate-800 bg-slate-900/70 p-5">
        <div className="mb-4 flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
          <div className="flex items-center gap-2">
            <ShieldCheck className="h-4 w-4 text-emerald-400" />
            <div>
              <h2 className="text-base font-semibold text-slate-100">
                Acciones sugeridas con aprobación humana (US-28)
              </h2>
              <p className="text-xs text-slate-400">
                Ningún comando se ejecuta automáticamente; revisa, aprueba o rechaza y ejecuta manualmente si corresponde
              </p>
            </div>
          </div>

          <select
            value={statusFilter}
            onChange={(e) => setStatusFilter(e.target.value as ActionStatus | "")}
            className="rounded-lg border border-slate-700 bg-slate-950 px-2.5 py-1.5 text-xs text-slate-200"
          >
            <option value="">Todos los estados</option>
            <option value="pending">pending</option>
            <option value="approved">approved</option>
            <option value="rejected">rejected</option>
          </select>
        </div>

        {errorMsg && (
          <div className="mb-3 rounded-lg border border-rose-800/70 bg-rose-950/50 px-3 py-2 text-xs text-rose-300">
            {errorMsg}
          </div>
        )}

        {actionsQuery.isLoading ? (
          <p className="text-xs text-slate-400">Cargando acciones sugeridas...</p>
        ) : (actionsQuery.data?.items.length ?? 0) === 0 ? (
          <p className="text-xs text-slate-500">
            No hay acciones en este estado. Genera una explicación con IA sobre un hallazgo para proponer acciones revisables.
          </p>
        ) : (
          <div className="space-y-3">
            {actionsQuery.data?.items.map((act) => (
              <div
                key={act.id}
                className="rounded-lg border border-slate-800 bg-slate-950/60 p-4 text-xs"
              >
                <div className="flex flex-col gap-3 sm:flex-row sm:items-start sm:justify-between">
                  <div className="space-y-1.5">
                    <div className="flex items-center gap-2">
                      <span
                        className={`rounded px-2 py-0.5 font-mono uppercase ${
                          act.status === "approved"
                            ? "bg-emerald-500/15 text-emerald-300"
                            : act.status === "rejected"
                              ? "bg-rose-500/15 text-rose-300"
                              : "bg-amber-500/15 text-amber-300"
                        }`}
                      >
                        {act.status}
                      </span>
                      <span className="font-mono text-slate-500">
                        Finding #{act.finding_id}
                      </span>
                      {act.decided_by && (
                        <span className="text-slate-400">
                          • Revisado por {act.decided_by}
                        </span>
                      )}
                    </div>
                    <pre className="overflow-x-auto rounded bg-slate-900 px-3 py-2 font-mono text-sky-300">
                      $ {act.command}
                    </pre>
                    {act.rationale && (
                      <p className="text-slate-400">{act.rationale}</p>
                    )}
                  </div>

                  <div className="flex flex-wrap gap-1.5">
                    <button
                      type="button"
                      onClick={() => copyCommand(act.id, act.command)}
                      className="flex items-center gap-1 rounded border border-slate-700 px-2.5 py-1 text-slate-300 hover:bg-slate-800"
                    >
                      <Copy className="h-3.5 w-3.5" />
                      {copiedId === act.id ? "Copiado" : "Copiar"}
                    </button>
                    {act.status !== "approved" && (
                      <button
                        type="button"
                        onClick={() =>
                          reviewMutation.mutate({ id: act.id, status: "approved" })
                        }
                        className="flex items-center gap-1 rounded border border-emerald-700/60 bg-emerald-500/10 px-2.5 py-1 text-emerald-300 hover:bg-emerald-500/20"
                      >
                        <Check className="h-3.5 w-3.5" />
                        Aprobar
                      </button>
                    )}
                    {act.status !== "rejected" && (
                      <button
                        type="button"
                        onClick={() =>
                          reviewMutation.mutate({ id: act.id, status: "rejected" })
                        }
                        className="flex items-center gap-1 rounded border border-rose-700/60 bg-rose-500/10 px-2.5 py-1 text-rose-300 hover:bg-rose-500/20"
                      >
                        <X className="h-3.5 w-3.5" />
                        Rechazar
                      </button>
                    )}
                  </div>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>

      <div className="rounded-xl border border-slate-800 bg-slate-900/70 p-5">
        <div className="mb-4 flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
          <div className="flex items-center gap-2">
            <BookOpen className="h-4 w-4 text-sky-400" />
            <div>
              <h2 className="text-base font-semibold text-slate-100">
                RAG offline sobre la Arch Wiki (US-27)
              </h2>
              <p className="text-xs text-slate-400">
                Consulta documentación local indexada con citas verificables de wiki.archlinux.org
              </p>
            </div>
          </div>

          <form
            onSubmit={(e) => {
              e.preventDefault();
              if (wikiQuery.trim()) setSubmittedWikiQuery(wikiQuery.trim());
            }}
            className="flex items-center gap-2 text-xs"
          >
            <input
              type="text"
              value={wikiQuery}
              onChange={(e) => setWikiQuery(e.target.value)}
              placeholder="Buscar en la Arch Wiki local..."
              className="w-60 rounded-lg border border-slate-700 bg-slate-950 px-3 py-1.5 text-slate-100 placeholder-slate-500 focus:border-sky-500 focus:outline-none"
            />
            <button
              type="submit"
              className="flex items-center gap-1 rounded-lg bg-sky-600 px-3 py-1.5 font-medium text-white hover:bg-sky-500"
            >
              <Search className="h-3.5 w-3.5" />
              Buscar
            </button>
          </form>
        </div>

        {wikiSearchQuery.isLoading ? (
          <p className="text-xs text-slate-400">Buscando en índice local...</p>
        ) : (wikiSearchQuery.data?.items.length ?? 0) === 0 ? (
          <p className="text-xs text-slate-500">Sin coincidencias para esa consulta.</p>
        ) : (
          <div className="space-y-3 text-xs">
            {wikiSearchQuery.data?.items.map((src, idx) => (
              <div
                key={`${src.url}-${idx}`}
                className="rounded-lg border border-slate-800 bg-slate-950/60 p-3.5"
              >
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <a
                    href={src.url}
                    target="_blank"
                    rel="noreferrer"
                    className="font-semibold text-sky-300 underline hover:text-sky-200"
                  >
                    {src.title} — {src.section}
                  </a>
                  <span className="font-mono text-[11px] text-slate-500">
                    score {src.score.toFixed(2)}
                  </span>
                </div>
                <p className="mt-1.5 text-slate-300">{src.snippet}</p>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}
