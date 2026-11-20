use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;

use clap::Parser;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("invalid listen address '{0}': {1}")]
    InvalidAddr(String, std::net::AddrParseError),
    #[error("refusing to bind non-loopback address '{0}': only 127.0.0.1 or ::1 is permitted")]
    NonLoopbackAddr(IpAddr),
}

/// Unprivileged API server for Arch Forward Observations System.
#[derive(Debug, Clone, Parser)]
#[command(name = "arch-fos-api", version, about)]
pub struct ApiConfig {
    /// Path to the SQLite database file (opened in read-only mode).
    #[arg(
        long,
        env = "ARCH_FOS_DB_PATH",
        default_value = "/var/lib/arch-fos/arch-fos.db"
    )]
    pub db_path: PathBuf,

    /// Loopback TCP address to bind (must be 127.0.0.1 or ::1).
    #[arg(long, env = "ARCH_FOS_LISTEN", default_value = "127.0.0.1:8420")]
    pub listen: String,

    /// Optional Unix domain socket path instead of TCP (if set, overrides --listen).
    #[arg(long, env = "ARCH_FOS_UNIX_SOCKET")]
    pub unix_socket: Option<PathBuf>,

    /// Path to the local authentication token file (auto-generated with 0600 permissions if missing).
    #[arg(
        long,
        env = "ARCH_FOS_TOKEN_FILE",
        default_value = "/run/arch-fos-api/api.token"
    )]
    pub token_file: PathBuf,

    /// Optional directory containing built frontend static assets (`web/dist`).
    #[arg(long, env = "ARCH_FOS_STATIC_DIR")]
    pub static_dir: Option<PathBuf>,

    /// Path to the collector control Unix socket for finding/suppression mutations.
    #[arg(
        long,
        env = "ARCH_FOS_COLLECTOR_SOCK",
        default_value = "/run/arch-fos/collector.sock"
    )]
    pub collector_socket: PathBuf,

    /// Print the OpenAPI 3.1 JSON specification to stdout and exit.
    #[arg(long, default_value_t = false)]
    pub dump_openapi: bool,

    /// Print the active local login token path/value on startup (for local dev convenience).
    #[arg(long, default_value_t = false)]
    pub print_token: bool,
}

/// Validates that the configured TCP socket address is strictly loopback.
pub fn validate_loopback_addr(listen: &str) -> Result<SocketAddr, ConfigError> {
    let addr: SocketAddr = listen
        .parse()
        .map_err(|err| ConfigError::InvalidAddr(listen.to_string(), err))?;
    if !addr.ip().is_loopback() {
        return Err(ConfigError::NonLoopbackAddr(addr.ip()));
    }
    Ok(addr)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_loopback_addresses() {
        assert!(validate_loopback_addr("127.0.0.1:8420").is_ok());
        assert!(validate_loopback_addr("[::1]:8420").is_ok());
    }

    #[test]
    fn rejects_non_loopback_addresses() {
        assert!(matches!(
            validate_loopback_addr("0.0.0.0:8420"),
            Err(ConfigError::NonLoopbackAddr(_))
        ));
        assert!(matches!(
            validate_loopback_addr("192.168.1.10:8420"),
            Err(ConfigError::NonLoopbackAddr(_))
        ));
        assert!(matches!(
            validate_loopback_addr("[::]:8420"),
            Err(ConfigError::NonLoopbackAddr(_))
        ));
    }
}
