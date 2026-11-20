import { useEffect, useRef } from "react";
import uPlot from "uplot";
import type { TimeSeriesPoint } from "../api/client";

interface EventsTimeSeriesProps {
  points: TimeSeriesPoint[];
}

export function EventsTimeSeries({ points }: EventsTimeSeriesProps) {
  const containerRef = useRef<HTMLDivElement | null>(null);
  const plotRef = useRef<uPlot | null>(null);

  useEffect(() => {
    const el = containerRef.current;
    if (!el || points.length === 0) {
      if (plotRef.current) {
        plotRef.current.destroy();
        plotRef.current = null;
      }
      return;
    }

    const xs = points.map((p) => p.ts_sec);
    const eventsSeries = points.map((p) => p.events_count);
    const findingsSeries = points.map((p) => p.findings_count);

    const data: uPlot.AlignedData = [xs, eventsSeries, findingsSeries];
    const width = Math.max(el.clientWidth, 320);

    const opts: uPlot.Options = {
      width,
      height: 240,
      scales: {
        x: { time: true },
        y: { auto: true },
      },
      axes: [
        {
          stroke: "#94a3b8",
          grid: { stroke: "#1e293b" },
        },
        {
          stroke: "#94a3b8",
          grid: { stroke: "#1e293b" },
        },
      ],
      series: [
        {},
        {
          label: "Eventos / min",
          stroke: "#38bdf8",
          fill: "rgba(56, 189, 248, 0.14)",
          width: 2,
        },
        {
          label: "Hallazgos / min",
          stroke: "#f59e0b",
          width: 2,
        },
      ],
    };

    if (plotRef.current) {
      plotRef.current.destroy();
    }
    const plot = new uPlot(opts, data, el);
    plotRef.current = plot;

    const ro = new ResizeObserver((entries) => {
      for (const entry of entries) {
        const nextWidth = Math.floor(entry.contentRect.width);
        if (nextWidth > 0 && plotRef.current) {
          plotRef.current.setSize({ width: nextWidth, height: 240 });
        }
      }
    });
    ro.observe(el);

    return () => {
      ro.disconnect();
      plot.destroy();
      plotRef.current = null;
    };
  }, [points]);

  return (
    <div className="rounded-xl border border-slate-800 bg-slate-900/70 p-5">
      <div className="mb-3 flex items-center justify-between">
        <div>
          <h2 className="text-sm font-semibold text-slate-100">
            Serie temporal de actividad (uPlot)
          </h2>
          <p className="text-xs text-slate-400">
            Eventos y hallazgos agregados por minuto (últimas 24 h)
          </p>
        </div>
        <span className="rounded bg-slate-800 px-2 py-0.5 text-xs text-slate-300">
          {points.length} puntos
        </span>
      </div>

      {points.length === 0 ? (
        <div className="flex h-[240px] items-center justify-center rounded-lg border border-dashed border-slate-800 text-sm text-slate-500">
          Sin puntos de serie temporal todavía. Ejecuta el colector para generar eventos.
        </div>
      ) : (
        <div ref={containerRef} className="w-full overflow-hidden" />
      )}
    </div>
  );
}
