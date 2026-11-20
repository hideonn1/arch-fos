# Arch Forward Observations System (`arch-fos`)

Plataforma local y *full-stack* de observabilidad y auditoría de seguridad para **Arch Linux**, diseñada con separación estricta de privilegios, base de datos SQLite en modo WAL y dashboard web embebido.

---

## Características principales

### Seguridad y arquitectura de privilegios mínimos
- **Colector privilegiado (`arch-fos-collector`):** único escritor de SQLite; corre con usuario dedicado y *capabilities* mínimas (`CAP_BPF`, `CAP_NET_RAW`, `CAP_PERFMON`).
- **API sin privilegios (`arch-fos-api`):** corre con `DynamicUser=yes` y cero *capabilities*, abre SQLite estrictamente en **solo lectura** (`mode=ro`) y reenvía mutaciones auditadas al colector mediante un socket Unix de control.
- **Acceso estrictamente local:** bind exclusivo a `127.0.0.1`, `::1` o Unix socket, autenticación con token local (`0600`), sesión con cookie `HttpOnly` + `SameSite=Strict`, protección CSRF y cabeceras `CSP`, `X-Frame-Options: DENY` y `Referrer-Policy: no-referrer`.

### Auditoría de paquetes Pacman y AUR
- **Inventario ALPM (`libalpm`):** snapshot periódico y *diff* que detecta `package_installed`, `package_removed` y `package_upgraded`, clasificando paquetes oficiales vs. foráneos/AUR.
- **Vulnerabilidades (CVEs):** sincronización con *Arch Security Tracker* (`If-None-Match`) y comparación exacta de versiones con `alpm::vercmp`.
- **Reputación AUR:** consultas por lotes con *rate-limit* y caché a AUR RPC v5 para detectar cambios de mantenedor, adopción tras estado huérfano, pocos votos, envíos recientes y paquetes `OutOfDate` prolongados.
- **Análisis estático de `PKGBUILD` y `.install` (`arch-fos-analyzer`):** parser AST basado en `tree-sitter-bash` que detecta patrones de riesgo (`curl|sh`, `wget|bash`, `base64 -d`, `eval`, checksums `SKIP`, fuentes fuera de allowlist, escritura fuera de `$pkgdir`, `systemctl enable` y comandos de red en `.install`).
- **Diff de versiones AUR y hook de Pacman (`arch-fos` CLI):** comparación vía `git` entre versiones de un `PKGBUILD` y hook `PreTransaction` (`/usr/share/libalpm/hooks/arch-fos-pre-transaction.hook`) con modos `warn` / `block` y *bypass* explícito auditado.
- **Integridad de archivos:** verificación contra archivos `mtree` locales (equivalente a `pacman -Qkk`), excluyendo archivos de configuración declarados en `backup`.

### Telemetría de red, sistema y reglas
- **Flujos de red atribuidos a procesos:** programa eBPF (`aya`) sobre `tracepoint/sock/inet_sock_set_state` y `cgroup/sendmsg4` con agregación por minuto en `flows_1m` (sin capturas completas de paquetes) y caída automática a modo degradado con `NETLINK_SOCK_DIAG` + `/proc` cuando no hay `CAP_BPF`.
- **Puertos en escucha:** lectura vía `NETLINK_SOCK_DIAG` con atribución a PID y paquete dueño de Pacman.
- **Análisis DNS e inteligencia de amenazas:** heurísticas de entropía de Shannon, longitud, tasa `NXDOMAIN` y explosión de subdominios; cruce con feeds locales cacheados de **URLhaus** y **Feodo Tracker** (`abuse.ch`).
- **Baseline de red (14 días):** aprendizaje por proceso con detección de primer tráfico saliente, puertos de destino nuevos y *beaconing* periódico.
- **Servicios y persistencia:** inventario de units `systemd` y consumo cgroup vía D-Bus (`zbus`), detección de cambios en units/timers, crontabs, `autostart`, shell RC, `ld.so.preload`, módulos del kernel y binarios SUID/SGID.
- **Reglas declarativas:** reglas YAML estilo Sigma en `rules/` con recarga en caliente y mapeo opcional a **MITRE ATT&CK**.

### API OpenAPI y Dashboard
- **Contrato tipado:** API REST en Axum documentada con OpenAPI 3.1 (`utoipa`) y tipos TypeScript autogenerados (`openapi-typescript`).
- **Dashboard SPA embebido (`rust-embed`):** construido con React, TypeScript, Tailwind CSS, TanStack Query y `uPlot`, con actualizaciones en tiempo real por **SSE** (`/api/v1/stream`), gestión de hallazgos/supresiones con auditoría y línea de tiempo correlacionada por entidad.

---

## Arquitectura

```text
┌──────────────────────────────┐        ┌──────────────────────────────┐
│  arch-fos-collector (Rust)   │        │  arch-fos-api (Rust / Axum)  │
│  - eBPF (aya) / sock_diag    │ escribe│  - SQLite solo lectura (ro)  │
│  - alpm / mtree / zbus       ├───────►│  - OpenAPI 3.1 + SSE         │
│  - YAML Sigma / Threat Intel │ SQLite │  - SPA embebida (rust-embed) │
│  - Socket Unix de control    │ (WAL)  │  - 127.0.0.1 + Cookie/CSRF   │
└──────────────▲───────────────┘        └──────────────┬───────────────┘
               │ IPC (mutaciones auditadas)            │ HTTP local
               └───────────────────────────────────────┘
                                                       │
┌──────────────────────────────┐        ┌──────────────▼───────────────┐
│  arch-fos CLI / Hook ALPM    │        │  Dashboard Web (React + TS)  │
│  - scan-pkgbuild / diff      │        │  - Resumen, uPlot, Hallazgos │
│  - PreTransaction hook       │        │  - Timeline, Red, Paquetes   │
└──────────────────────────────┘        └──────────────────────────────┘
```

---

## Estructura del repositorio

```text
arch-fos/
├── crates/
│   ├── common/      # Modelos de dominio, contratos API e IPC (sin I/O)
│   ├── analyzer/    # Análisis estático PKGBUILD/.install (tree-sitter-bash) y diff git
│   ├── collector/   # Daemon colector, eBPF C/aya, reglas YAML, retención y DB writer
│   ├── api/         # Servidor HTTP local, auth/CSRF/CSP, OpenAPI, SSE y SPA embebida
│   └── cli/         # Binario CLI `arch-fos` y hook PreTransaction de pacman
├── migrations/      # Migraciones SQLite versionadas (sqlx)
├── packaging/       # Units systemd, sysusers, tmpfiles, hook ALPM y PKGBUILD
├── rules/           # Reglas de detección YAML estilo Sigma (MITRE ATT&CK)
├── web/             # Frontend React + TypeScript + Tailwind + Vite + uPlot
└── Makefile         # Tareas de verificación, OpenAPI y compilación
```

---

## Requisitos y desarrollo local

### Dependencias en Arch Linux
- Toolchain de Rust (`rustc`, `cargo`)
- `clang` (compilación del objeto eBPF `--target=bpf`)
- `pacman` / `libalpm` y `sqlite`
- `nodejs` y `npm`

### Verificación y compilación

```bash
# Instalar dependencias del frontend
npm --prefix web install

# Regenerar contrato OpenAPI y tipos TypeScript
make openapi

# Compilar frontend (embebido luego en arch-fos-api via rust-embed)
make web-build

# Ejecutar fmt, clippy (-D warnings), tests de Rust y typecheck de TypeScript
make check

# Compilar todo el workspace en modo release
make build
```

### Ejecución rápida en desarrollo

1. Generar una base de datos local con el colector (usa `--offline` si no quieres consultar feeds externos en pruebas):
   ```bash
   cargo run -p arch-fos-collector -- --db-path ./arch-fos.db --once --offline
   ```
2. Iniciar la API web sirviendo el frontend e imprimiendo el token de acceso local:
   ```bash
   cargo run -p arch-fos-api -- --db-path ./arch-fos.db --token-file ./api.token --static-dir ./web/dist --print-token
   ```
3. Abrir `http://127.0.0.1:8420` e iniciar sesión con el token impreso en consola.

### Uso del CLI `arch-fos`

```bash
# Analizar estáticamente un PKGBUILD o script .install
cargo run -p arch-fos-cli -- scan-pkgbuild ./ruta/al/PKGBUILD ./ruta/al/pkg.install

# Comparar dos revisiones de un repositorio AUR local
cargo run -p arch-fos-cli -- diff-pkgbuild ./ruta/al/repo-aur --from HEAD~1 --to HEAD
```

---

## Instalación en Arch Linux (`PKGBUILD`)

El directorio [`packaging/`](packaging/) incluye los archivos necesarios para construir e instalar el paquete del sistema con `makepkg`:

```bash
cd packaging
makepkg -si
```

Luego en el host:
```bash
sudo systemctl enable --now arch-fos-collector.service arch-fos-api.service
systemd-analyze security arch-fos-collector.service arch-fos-api.service
```

---

## Roadmap

- **Hitos 1–4 (implementados):** Esqueleto + SQLite WAL + inventario ALPM, servicios/puertos/CVEs/AUR/análisis PKGBUILD/gestión de hallazgos, red eBPF/DNS/Threat Intel/baseline/SSE, persistencia/integridad `mtree`/línea de tiempo/binario único/reglas YAML Sigma.
- **Próxima etapa (IA local y aislamiento):** explicación de hallazgos con LLM local (Ollama) protegido contra inyección de prompts, RAG offline sobre la Arch Wiki, aprobación manual de acciones sugeridas y compilación aislada de paquetes en sandbox (`systemd-nspawn` / `bwrap`).

---

## Licencia

Distribuido bajo licencia [MIT](LICENSE).
