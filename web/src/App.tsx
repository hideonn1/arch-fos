import { useEffect, useState } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import {
  ApiError,
  fetchAuthMe,
  fetchCollectorHealth,
  fetchSummary,
  loginWithToken,
  logout,
  type Finding,
} from "./api/client";
import { LoginScreen } from "./components/LoginScreen";
import { SummaryCards } from "./components/SummaryCards";
import { EventsTimeSeries } from "./components/EventsTimeSeries";
import { PackagesPanel } from "./components/PackagesPanel";
import { OverviewTables } from "./components/OverviewTables";
import { FindingsPanel } from "./components/FindingsPanel";
import { ServicesListenersPanel } from "./components/ServicesListenersPanel";
import { NetworkPanel } from "./components/NetworkPanel";
import { TimelinePanel } from "./components/TimelinePanel";
import { RulesPanel } from "./components/RulesPanel";
import { BellRing, HeartPulse, LogOut, Radio, RefreshCw, Shield, X } from "lucide-react";

type Tab = "overview" | "findings" | "timeline" | "network" | "packages" | "runtime" | "rules";
type SseStatus = "connecting" | "live" | "reconnecting";

export function App() {
  const queryClient = useQueryClient();
  const [tab, setTab] = useState<Tab>("overview");
  const [loginError, setLoginError] = useState<string | null>(null);
  const [loginLoading, setLoginLoading] = useState(false);
  const [sseStatus, setSseStatus] = useState<SseStatus>("connecting");
  const [liveAlert, setLiveAlert] = useState<Finding | null>(null);

  const authQuery = useQuery({
    queryKey: ["auth-me"],
    queryFn: fetchAuthMe,
    retry: false,
  });

  const isAuthenticated = authQuery.data?.authenticated === true;

  // US-21: Real-time SSE subscription with automatic EventSource reconnection
  useEffect(() => {
    if (!isAuthenticated) {
      setSseStatus("connecting");
      return;
    }

    setSseStatus("connecting");
    const source = new EventSource("/api/v1/stream", { withCredentials: true });
    source.onopen = () => setSseStatus("live");
    source.onerror = () => setSseStatus("reconnecting");

    source.addEventListener("finding", (event) => {
      try {
        const finding = JSON.parse((event as MessageEvent<string>).data) as Finding;
        setLiveAlert(finding);
        void queryClient.invalidateQueries({ queryKey: ["findings"] });
        void queryClient.invalidateQueries({ queryKey: ["summary"] });
        void queryClient.invalidateQueries({ queryKey: ["recent-findings"] });
      } catch {
        // ignore malformed SSE frame
      }
    });

    return () => {
      source.close();
      setSseStatus("connecting");
    };
  }, [isAuthenticated, queryClient]);

  const summaryQuery = useQuery({
    queryKey: ["summary"],
    queryFn: fetchSummary,
    enabled: isAuthenticated,
    refetchInterval: 30_000,
  });

  const collectorHealthQuery = useQuery({
    queryKey: ["collector-health"],
    queryFn: fetchCollectorHealth,
    enabled: isAuthenticated,
    refetchInterval: 30_000,
  });

  async function handleLogin(token: string) {
    setLoginError(null);
    setLoginLoading(true);
    try {
      await loginWithToken(token);
      await queryClient.invalidateQueries();
    } catch (err) {
      if (err instanceof ApiError) {
        setLoginError(err.message);
      } else {
        setLoginError("Error de conexión con la API local");
      }
    } finally {
      setLoginLoading(false);
    }
  }

  async function handleLogout() {
    await logout();
    queryClient.clear();
    await authQuery.refetch();
  }

  if (authQuery.isLoading) {
    return (
      <div className="flex min-h-screen items-center justify-center bg-slate-950 text-sm text-slate-400">
        Conectando con arch-fos-api...
      </div>
    );
  }

  if (!isAuthenticated) {
    return (
      <LoginScreen
        onLogin={handleLogin}
        error={loginError}
        loading={loginLoading}
      />
    );
  }

  const colHealth = collectorHealthQuery.data;

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100">
      <header className="border-b border-slate-800 bg-slate-900/80 backdrop-blur">
        <div className="mx-auto flex max-w-7xl flex-wrap items-center justify-between gap-3 px-4 py-3 sm:px-6">
          <div className="flex items-center gap-3">
            <Shield className="h-6 w-6 text-sky-400" />
            <div>
              <h1 className="text-sm font-semibold tracking-tight text-slate-100">
                Arch Forward Observations System
              </h1>
              <div className="flex flex-wrap items-center gap-2 text-[11px] text-slate-400">
                <span>Hito 4 · Persistencia, Integridad, Timeline y Sigma</span>
                <span
                  className={`inline-flex items-center gap-1 rounded px-1.5 py-0.5 ${
                    sseStatus === "live"
                      ? "bg-sky-500/15 text-sky-300"
                      : sseStatus === "connecting"
                        ? "bg-slate-700/60 text-slate-300"
                        : "bg-amber-500/15 text-amber-300"
                  }`}
                >
                  <Radio className="h-3 w-3" />
                  {sseStatus === "live"
                    ? "SSE en vivo"
                    : sseStatus === "connecting"
                      ? "SSE conectando..."
                      : "SSE reconectando"}
                </span>
                {colHealth && colHealth.last_heartbeat_at > 0 && (
                  <span className="inline-flex items-center gap-1 rounded bg-emerald-500/10 px-1.5 py-0.5 text-emerald-300">
                    <HeartPulse className="h-3 w-3" />
                    Colector: {colHealth.status} • DB{" "}
                    {(colHealth.db_size_bytes / 1024).toFixed(0)} KiB • RSS{" "}
                    {(colHealth.rss_bytes / (1024 * 1024)).toFixed(1)} MiB
                  </span>
                )}
              </div>
            </div>
          </div>

          <nav className="flex flex-wrap items-center gap-2">
            {(
              [
                ["overview", "Resumen"],
                ["findings", "Hallazgos"],
                ["timeline", "Línea de tiempo"],
                ["network", "Red y Amenazas"],
                ["packages", "Paquetes"],
                ["runtime", "Servicios y Puertos"],
                ["rules", "Reglas YAML"],
              ] as const
            ).map(([key, label]) => (
              <button
                key={key}
                type="button"
                onClick={() => setTab(key)}
                className={`rounded-lg px-3 py-1.5 text-xs font-medium transition ${
                  tab === key
                    ? "bg-sky-500/20 text-sky-300"
                    : "text-slate-400 hover:bg-slate-800 hover:text-slate-200"
                }`}
              >
                {label}
              </button>
            ))}
            <button
              type="button"
              onClick={() => queryClient.invalidateQueries()}
              title="Actualizar"
              className="rounded-lg border border-slate-700 p-1.5 text-slate-300 hover:bg-slate-800"
            >
              <RefreshCw className="h-4 w-4" />
            </button>
            <button
              type="button"
              onClick={handleLogout}
              title="Cerrar sesión"
              className="flex items-center gap-1.5 rounded-lg border border-slate-700 px-2.5 py-1.5 text-xs text-slate-300 hover:bg-slate-800"
            >
              <LogOut className="h-3.5 w-3.5" />
              Salir
            </button>
          </nav>
        </div>
      </header>

      <main className="mx-auto max-w-7xl space-y-6 px-4 py-6 sm:px-6">
        {liveAlert && (
          <div className="flex items-center justify-between gap-3 rounded-xl border border-amber-700/60 bg-amber-950/40 px-4 py-3 text-xs text-amber-200">
            <div className="flex items-center gap-2">
              <BellRing className="h-4 w-4 text-amber-400" />
              <span>
                <strong>Nuevo hallazgo en tiempo real:</strong> [{liveAlert.severity}]{" "}
                {liveAlert.title}
              </span>
            </div>
            <button
              type="button"
              onClick={() => setLiveAlert(null)}
              className="rounded p-1 hover:bg-amber-900/50"
            >
              <X className="h-3.5 w-3.5" />
            </button>
          </div>
        )}

        {tab === "overview" && (
          <>
            {summaryQuery.isLoading ? (
              <div className="py-12 text-center text-sm text-slate-400">
                Cargando resumen del sistema...
              </div>
            ) : summaryQuery.isError ? (
              <div className="rounded-xl border border-rose-800/70 bg-rose-950/40 p-4 text-sm text-rose-300">
                Error cargando resumen: {summaryQuery.error.message}
              </div>
            ) : (
              summaryQuery.data && (
                <>
                  <SummaryCards summary={summaryQuery.data} />
                  <EventsTimeSeries points={summaryQuery.data.time_series} />
                  <OverviewTables summary={summaryQuery.data} />
                </>
              )
            )}
          </>
        )}

        {tab === "findings" && <FindingsPanel />}
        {tab === "timeline" && <TimelinePanel />}
        {tab === "network" && <NetworkPanel />}
        {tab === "packages" && <PackagesPanel />}
        {tab === "runtime" && <ServicesListenersPanel />}
        {tab === "rules" && <RulesPanel />}
      </main>
    </div>
  );
}

export default App;
