use std::path::PathBuf;

use arch_fos_api::auth::{AuthState, load_or_create_token};
use arch_fos_api::build_router;
use arch_fos_api::config::{ApiConfig, validate_loopback_addr};
use arch_fos_api::db::open_readonly_pool;
use arch_fos_api::openapi::openapi_json_pretty;
use arch_fos_api::routes::AppState;
use clap::Parser;
use tokio::net::{TcpListener, UnixListener};
use tokio::signal;
use tracing::info;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cfg = ApiConfig::parse();

    if cfg.dump_openapi {
        let json = openapi_json_pretty()?;
        println!("{json}");
        return Ok(());
    }

    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let token = load_or_create_token(&cfg.token_file)?;
    if cfg.print_token {
        info!(
            token_file = %cfg.token_file.display(),
            token = %token,
            "local authentication token ready"
        );
    } else {
        info!(
            token_file = %cfg.token_file.display(),
            "local authentication token loaded"
        );
    }

    let pool = open_readonly_pool(&cfg.db_path).await?;
    info!(db_path = %cfg.db_path.display(), "opened SQLite database in read-only mode");

    let state = AppState {
        pool,
        auth: AuthState::new(token),
        collector_socket: cfg.collector_socket,
    };
    let app = build_router(state, cfg.static_dir.as_deref());

    if let Some(socket_path) = cfg.unix_socket {
        serve_unix_socket(app, socket_path).await?;
    } else {
        let addr = validate_loopback_addr(&cfg.listen)?;
        let listener = TcpListener::bind(addr).await?;
        info!(listen = %addr, "arch-fos-api listening on loopback TCP");
        axum::serve(listener, app)
            .with_graceful_shutdown(shutdown_signal())
            .await?;
    }

    Ok(())
}

async fn serve_unix_socket(
    app: axum::Router,
    socket_path: PathBuf,
) -> Result<(), Box<dyn std::error::Error>> {
    if let Some(parent) = socket_path.parent()
        && !parent.as_os_str().is_empty()
    {
        std::fs::create_dir_all(parent)?;
    }
    if socket_path.exists() {
        std::fs::remove_file(&socket_path)?;
    }

    let listener = UnixListener::bind(&socket_path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&socket_path, std::fs::Permissions::from_mode(0o600))?;
    }
    info!(socket = %socket_path.display(), "arch-fos-api listening on unix socket");
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await?;
    Ok(())
}

async fn shutdown_signal() {
    let ctrl_c = async {
        let _ = signal::ctrl_c().await;
    };

    #[cfg(unix)]
    let terminate = async {
        if let Ok(mut sigterm) = signal::unix::signal(signal::unix::SignalKind::terminate()) {
            sigterm.recv().await;
        }
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        () = ctrl_c => {}
        () = terminate => {}
    }
}
