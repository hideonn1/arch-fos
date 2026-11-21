use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use arch_fos_common::{CollectorCommand, CollectorResponse};
use sqlx::SqlitePool;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};
use tracing::{debug, warn};

use crate::db::apply_collector_command;

/// Maximum permitted byte length of a single IPC JSON command line (64 KiB) to prevent memory DoS.
const MAX_IPC_LINE_BYTES: usize = 64 * 1024;

/// Binds the collector control Unix socket (`0660`) and processes mutation commands.
pub async fn spawn_control_socket(
    pool: SqlitePool,
    socket_path: &Path,
) -> Result<tokio::task::JoinHandle<()>, std::io::Error> {
    if let Some(parent) = socket_path.parent()
        && !parent.as_os_str().is_empty()
    {
        std::fs::create_dir_all(parent)?;
    }
    if socket_path.exists() {
        std::fs::remove_file(socket_path)?;
    }

    let listener = UnixListener::bind(socket_path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(socket_path, std::fs::Permissions::from_mode(0o660))?;
    }

    let handle = tokio::spawn(async move {
        loop {
            match listener.accept().await {
                Ok((stream, _)) => {
                    let pool_clone = pool.clone();
                    tokio::spawn(async move {
                        if let Err(err) = handle_client(pool_clone, stream).await {
                            debug!(error = %err, "collector control client ended with error");
                        }
                    });
                }
                Err(err) => {
                    warn!(error = %err, "collector control socket accept error");
                    break;
                }
            }
        }
    });

    Ok(handle)
}

async fn handle_client(pool: SqlitePool, stream: UnixStream) -> Result<(), std::io::Error> {
    let (reader, mut writer) = stream.into_split();
    let mut reader = BufReader::new(reader);
    let mut buf = Vec::with_capacity(1024);

    loop {
        buf.clear();
        let bytes_read = (&mut reader)
            .take((MAX_IPC_LINE_BYTES + 1) as u64)
            .read_until(b'\n', &mut buf)
            .await?;
        if bytes_read == 0 {
            break;
        }
        if buf.len() > MAX_IPC_LINE_BYTES {
            let err_resp = CollectorResponse::Error {
                message: format!("IPC command exceeds {MAX_IPC_LINE_BYTES} byte limit"),
            };
            let encoded = serde_json::to_string(&err_resp).unwrap_or_default();
            writer.write_all(encoded.as_bytes()).await?;
            writer.write_all(b"\n").await?;
            writer.flush().await?;
            break;
        }

        let line = String::from_utf8_lossy(&buf);
        if line.trim().is_empty() {
            continue;
        }
        let response = match serde_json::from_str::<CollectorCommand>(line.trim()) {
            Ok(cmd) => {
                let now_ms = current_unix_ms();
                match apply_collector_command(&pool, cmd, now_ms).await {
                    Ok(resp) => resp,
                    Err(err) => CollectorResponse::Error {
                        message: err.to_string(),
                    },
                }
            }
            Err(err) => CollectorResponse::Error {
                message: format!("invalid command payload: {err}"),
            },
        };

        let encoded = serde_json::to_string(&response).unwrap_or_else(|_| {
            r#"{"result":"error","message":"failed to encode response"}"#.to_string()
        });
        writer.write_all(encoded.as_bytes()).await?;
        writer.write_all(b"\n").await?;
        writer.flush().await?;
    }
    Ok(())
}

fn current_unix_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| i64::try_from(d.as_millis()).unwrap_or(i64::MAX))
        .unwrap_or(0)
}
