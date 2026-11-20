import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { fetchEntityTimeline, fetchTimelineEntities } from "../api/client";
import { Clock, Search } from "lucide-react";

function KindBadge({ kind }: { kind: string }) {
  const styles: Record<string, string> = {
    finding: "bg-rose-500/20 text-rose-300",
    event: "bg-sky-500/20 text-sky-300",
    listener: "bg-amber-500/20 text-amber-300",
    flow: "bg-emerald-500/20 text-emerald-300",
    dns: "bg-violet-500/20 text-violet-300",
  };
  return (
    <span
      className={`rounded px-2 py-0.5 font-mono text-[11px] uppercase ${
        styles[kind] ?? "bg-slate-700 text-slate-300"
      }`}
    >
      {kind}
    </span>
  );
}

export function TimelinePanel() {
  const [entityType, setEntityType] = useState("package");
  const [entityId, setEntityId] = useState("");
  const [activeTarget, setActiveTarget] = useState<{
    entityType: string;
    entityId: string;
  } | null>(null);

  const entitiesQuery = useQuery({
    queryKey: ["timeline-entities"],
    queryFn: fetchTimelineEntities,
  });

  const timelineQuery = useQuery({
    queryKey: ["entity-timeline", activeTarget?.entityType, activeTarget?.entityId],
    queryFn: () =>
      fetchEntityTimeline(activeTarget!.entityType, activeTarget!.entityId),
    enabled: Boolean(activeTarget?.entityType && activeTarget?.entityId),
  });

  return (
    <div className="space-y-6">
      <div className="rounded-xl border border-slate-800 bg-slate-900/70 p-5">
        <div className="mb-4 flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
          <div className="flex items-center gap-2">
            <Clock className="h-4 w-4 text-sky-400" />
            <div>
              <h2 className="text-base font-semibold text-slate-100">
                Línea de tiempo por entidad (US-24)
              </h2>
              <p className="text-xs text-slate-400">
                Correlaciona eventos, hallazgos, puertos, conexiones y DNS de un paquete, servicio o proceso
              </p>
            </div>
          </div>

          <form
            onSubmit={(e) => {
              e.preventDefault();
              if (entityId.trim()) {
                setActiveTarget({
                  entityType: entityType.trim(),
                  entityId: entityId.trim(),
                });
              }
            }}
            className="flex flex-wrap items-center gap-2 text-xs"
          >
            <select
              value={entityType}
              onChange={(e) => setEntityType(e.target.value)}
              className="rounded-lg border border-slate-700 bg-slate-950 px-2.5 py-1.5 text-slate-200"
            >
              <option value="package">package</option>
              <option value="process">process</option>
              <option value="service">service</option>
              <option value="listener">listener</option>
              <option value="persistence">persistence</option>
              <option value="system">system</option>
            </select>
            <input
              type="text"
              value={entityId}
              onChange={(e) => setEntityId(e.target.value)}
              placeholder="Nombre o ID de entidad..."
              className="rounded-lg border border-slate-700 bg-slate-950 px-3 py-1.5 text-slate-100 placeholder-slate-500 focus:border-sky-500 focus:outline-none"
            />
            <button
              type="submit"
              className="flex items-center gap-1 rounded-lg bg-sky-600 px-3 py-1.5 font-medium text-white hover:bg-sky-500"
            >
              <Search className="h-3.5 w-3.5" />
              Correlacionar
            </button>
          </form>
        </div>

        {(entitiesQuery.data?.entities.length ?? 0) > 0 && (
          <div className="mb-4 flex flex-wrap gap-1.5">
            {entitiesQuery.data?.entities.slice(0, 18).map((ent) => (
              <button
                key={`${ent.entity_type}:${ent.entity_id}`}
                type="button"
                onClick={() => {
                  setEntityType(ent.entity_type);
                  setEntityId(ent.entity_id);
                  setActiveTarget({
                    entityType: ent.entity_type,
                    entityId: ent.entity_id,
                  });
                }}
                className="rounded-md border border-slate-700 bg-slate-950/70 px-2 py-1 font-mono text-[11px] text-slate-300 hover:border-sky-500 hover:text-sky-300"
              >
                {ent.entity_type}:{ent.entity_id}
              </button>
            ))}
          </div>
        )}

        {!activeTarget ? (
          <div className="py-10 text-center text-xs text-slate-500">
            Selecciona una entidad arriba o escribe su identificador para reconstruir la cronología.
          </div>
        ) : timelineQuery.isLoading ? (
          <div className="py-10 text-center text-xs text-slate-400">
            Reconstruyendo línea de tiempo...
          </div>
        ) : (timelineQuery.data?.entries.length ?? 0) === 0 ? (
          <div className="py-10 text-center text-xs text-slate-500">
            Sin registros correlacionados para {activeTarget.entityType}:{activeTarget.entityId}.
          </div>
        ) : (
          <div className="relative space-y-3 border-l border-slate-800 pl-5">
            {timelineQuery.data?.entries.map((item, idx) => (
              <div
                key={`${item.ts}-${item.kind}-${idx}`}
                className="rounded-lg border border-slate-800 bg-slate-950/60 p-3 text-xs"
              >
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <div className="flex items-center gap-2">
                    <KindBadge kind={item.kind} />
                    <span className="font-semibold text-slate-100">{item.title}</span>
                  </div>
                  <span className="font-mono text-[11px] text-slate-400">
                    {new Date(item.ts).toLocaleString()}
                  </span>
                </div>
                <p className="mt-1 text-slate-400">{item.summary}</p>
                <p className="mt-1 font-mono text-[11px] text-slate-500">
                  Origen: {item.source} • Severidad: {item.severity}
                </p>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}
