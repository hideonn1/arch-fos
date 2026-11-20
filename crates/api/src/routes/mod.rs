pub mod auth;
pub mod dns;
pub mod events;
pub mod findings;
pub mod flows;
pub mod health;
pub mod listeners;
pub mod packages;
pub mod rules;
pub mod services;
pub mod stream;
pub mod summary;
pub mod suppressions;
pub mod threat_intel;
pub mod timeline;

use std::path::{Path, PathBuf};

use arch_fos_common::{ApiErrorBody, CollectorCommand, CollectorResponse};
use axum::Json;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use sqlx::SqlitePool;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;

use crate::auth::AuthState;

#[derive(Debug, Clone)]
pub struct AppState {
    pub pool: SqlitePool,
    pub auth: AuthState,
    pub collector_socket: PathBuf,
}

#[derive(Debug)]
pub struct ApiError {
    pub status: StatusCode,
    pub code: &'static str,
    pub message: String,
}

impl ApiError {
    #[must_use]
    pub fn bad_request(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::BAD_REQUEST,
            code: "bad_request",
            message: message.into(),
        }
    }

    #[must_use]
    pub fn unauthorized(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::UNAUTHORIZED,
            code: "unauthorized",
            message: message.into(),
        }
    }

    #[must_use]
    pub fn not_found(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::NOT_FOUND,
            code: "not_found",
            message: message.into(),
        }
    }

    #[must_use]
    pub fn service_unavailable(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::SERVICE_UNAVAILABLE,
            code: "collector_unavailable",
            message: message.into(),
        }
    }
}

impl From<sqlx::Error> for ApiError {
    fn from(err: sqlx::Error) -> Self {
        Self {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            code: "database_error",
            message: err.to_string(),
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (
            self.status,
            Json(ApiErrorBody {
                error: self.code.to_string(),
                message: self.message,
            }),
        )
            .into_response()
    }
}

/// Normalizes pagination limits between 1 and 200 (default 50).
#[must_use]
pub fn normalize_limit(limit: Option<u32>) -> i64 {
    i64::from(limit.unwrap_or(50).clamp(1, 200))
}

/// Parses an integer keyset cursor (`id < cursor`).
pub fn parse_i64_cursor(cursor: Option<&str>) -> Result<Option<i64>, ApiError> {
    match cursor {
        None | Some("") => Ok(None),
        Some(raw) => raw
            .parse::<i64>()
            .map(Some)
            .map_err(|_| ApiError::bad_request("invalid numeric cursor")),
    }
}

/// Sends a mutation command to the sole-writer collector over its Unix domain socket.
pub async fn send_collector_command(
    socket_path: &Path,
    cmd: CollectorCommand,
) -> Result<Option<i64>, ApiError> {
    let stream = UnixStream::connect(socket_path).await.map_err(|err| {
        ApiError::service_unavailable(format!(
            "cannot reach collector control socket {}: {err}",
            socket_path.display()
        ))
    })?;

    let (reader, mut writer) = stream.into_split();
    let payload = serde_json::to_string(&cmd)
        .map_err(|err| ApiError::bad_request(format!("failed to encode command: {err}")))?;
    writer
        .write_all(payload.as_bytes())
        .await
        .map_err(|err| ApiError::service_unavailable(err.to_string()))?;
    writer
        .write_all(b"\n")
        .await
        .map_err(|err| ApiError::service_unavailable(err.to_string()))?;
    writer
        .flush()
        .await
        .map_err(|err| ApiError::service_unavailable(err.to_string()))?;

    let mut lines = BufReader::new(reader).lines();
    let Some(line) = lines
        .next_line()
        .await
        .map_err(|err| ApiError::service_unavailable(err.to_string()))?
    else {
        return Err(ApiError::service_unavailable(
            "collector closed control connection without response",
        ));
    };

    let resp: CollectorResponse = serde_json::from_str(&line).map_err(|err| {
        ApiError::service_unavailable(format!("invalid collector response: {err}"))
    })?;

    match resp {
        CollectorResponse::Ok { id } => Ok(id),
        CollectorResponse::NotFound { message } => Err(ApiError::not_found(message)),
        CollectorResponse::Error { message } => Err(ApiError {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            code: "collector_error",
            message,
        }),
    }
}
