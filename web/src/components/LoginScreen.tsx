import { useState, type FormEvent } from "react";
import { ShieldAlert, KeyRound } from "lucide-react";

interface LoginScreenProps {
  onLogin: (token: string) => Promise<void>;
  error: string | null;
  loading: boolean;
}

export function LoginScreen({ onLogin, error, loading }: LoginScreenProps) {
  const [token, setToken] = useState("");

  async function handleSubmit(e: FormEvent) {
    e.preventDefault();
    if (!token.trim()) return;
    await onLogin(token.trim());
  }

  return (
    <div className="flex min-h-screen items-center justify-center bg-slate-950 px-4">
      <div className="w-full max-w-md rounded-xl border border-slate-800 bg-slate-900/90 p-8 shadow-2xl">
        <div className="mb-6 flex items-center gap-3">
          <div className="flex h-11 w-11 items-center justify-center rounded-lg bg-sky-500/15 text-sky-400">
            <ShieldAlert className="h-6 w-6" />
          </div>
          <div>
            <h1 className="text-lg font-semibold text-slate-100">
              Arch Forward Observations System
            </h1>
            <p className="text-xs text-slate-400">
              Acceso local autenticado (127.0.0.1)
            </p>
          </div>
        </div>

        <form onSubmit={handleSubmit} className="space-y-4">
          <div>
            <label
              htmlFor="local-token"
              className="mb-1.5 block text-sm font-medium text-slate-300"
            >
              Token local de sesión
            </label>
            <div className="relative">
              <KeyRound className="pointer-events-none absolute top-3 left-3 h-4 w-4 text-slate-500" />
              <input
                id="local-token"
                type="password"
                value={token}
                onChange={(e) => setToken(e.target.value)}
                placeholder="Pega el token de /run/arch-fos-api/api.token"
                className="w-full rounded-lg border border-slate-700 bg-slate-950 py-2.5 pr-3 pl-9 text-sm text-slate-100 placeholder-slate-500 focus:border-sky-500 focus:outline-none"
                autoComplete="off"
                autoFocus
              />
            </div>
          </div>

          {error && (
            <div className="rounded-lg border border-rose-800/70 bg-rose-950/50 px-3 py-2 text-xs text-rose-300">
              {error}
            </div>
          )}

          <button
            type="submit"
            disabled={loading || !token.trim()}
            className="w-full rounded-lg bg-sky-600 px-4 py-2.5 text-sm font-medium text-white transition hover:bg-sky-500 disabled:cursor-not-allowed disabled:opacity-50"
          >
            {loading ? "Verificando..." : "Iniciar sesión"}
          </button>
        </form>

        <p className="mt-5 text-xs leading-relaxed text-slate-500">
          La cookie de sesión usa <code className="text-slate-300">HttpOnly</code> y{" "}
          <code className="text-slate-300">SameSite=Strict</code> con protección CSRF.
        </p>
      </div>
    </div>
  );
}
