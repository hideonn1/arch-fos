use std::collections::HashMap;
use std::fs::OpenOptions;
use std::io::Write;
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};

use arch_fos_common::ApiErrorBody;
use axum::Json;
use axum::extract::{Request, State};
use axum::http::header::{
    CACHE_CONTROL, COOKIE, ORIGIN, REFERER, SET_COOKIE, X_CONTENT_TYPE_OPTIONS, X_FRAME_OPTIONS,
};
use axum::http::{HeaderName, HeaderValue, Method, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use rand::RngCore;
use tokio::sync::RwLock;

pub const SESSION_COOKIE_NAME: &str = "arch_fos_session";
pub const CSRF_HEADER_NAME: &str = "x-csrf-token";
const SESSION_TTL: Duration = Duration::from_secs(24 * 60 * 60);

const CSP_HEADER_VALUE: &str = "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; object-src 'none'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'";

#[derive(Debug, Clone)]
pub struct SessionRecord {
    pub csrf_token: String,
    pub expires_at: Instant,
}

#[derive(Debug, Clone)]
pub struct AuthState {
    api_token: String,
    sessions: Arc<RwLock<HashMap<String, SessionRecord>>>,
}

impl AuthState {
    /// Creates a new authentication manager from the active local API token.
    #[must_use]
    pub fn new(api_token: String) -> Self {
        Self {
            api_token,
            sessions: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Validates the presented login token in constant time.
    #[must_use]
    pub fn verify_api_token(&self, candidate: &str) -> bool {
        constant_time_eq(self.api_token.as_bytes(), candidate.trim().as_bytes())
    }

    /// Creates a fresh authenticated session and returns `(session_id, csrf_token)`.
    pub async fn create_session(&self) -> (String, String) {
        let session_id = generate_random_hex(32);
        let csrf_token = generate_random_hex(32);
        let record = SessionRecord {
            csrf_token: csrf_token.clone(),
            expires_at: Instant::now() + SESSION_TTL,
        };

        let mut guard = self.sessions.write().await;
        // Prune expired sessions opportunistically to bound memory.
        let now = Instant::now();
        guard.retain(|_, v| v.expires_at > now);
        guard.insert(session_id.clone(), record);

        (session_id, csrf_token)
    }

    /// Returns the session record if the session ID is valid and unexpired.
    pub async fn get_session(&self, session_id: &str) -> Option<SessionRecord> {
        let guard = self.sessions.read().await;
        let record = guard.get(session_id)?;
        if record.expires_at <= Instant::now() {
            return None;
        }
        Some(record.clone())
    }

    /// Removes a session on logout.
    pub async fn delete_session(&self, session_id: &str) {
        let mut guard = self.sessions.write().await;
        guard.remove(session_id);
    }
}

/// Loads an existing local API token or generates a new 256-bit hex token with mode `0600`.
pub fn load_or_create_token(path: &Path) -> Result<String, std::io::Error> {
    if path.exists() {
        let content = std::fs::read_to_string(path)?;
        let trimmed = content.trim().to_string();
        if !trimmed.is_empty() {
            return Ok(trimmed);
        }
    }

    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        std::fs::create_dir_all(parent)?;
    }

    let token = generate_random_hex(32);

    let mut options = OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }

    let mut file = options.open(path)?;
    writeln!(file, "{token}")?;
    Ok(token)
}

/// Generates `byte_len` cryptographic random bytes encoded as lowercase hex.
#[must_use]
pub fn generate_random_hex(byte_len: usize) -> String {
    let mut bytes = vec![0u8; byte_len];
    rand::rng().fill_bytes(&mut bytes);
    hex::encode(bytes)
}

/// Constant-time byte slice equality check.
#[must_use]
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// Extracts the session cookie value from the HTTP `Cookie` header.
#[must_use]
pub fn extract_session_cookie(req: &Request) -> Option<String> {
    let header = req.headers().get(COOKIE)?.to_str().ok()?;
    for pair in header.split(';') {
        let trimmed = pair.trim();
        if let Some((name, value)) = trimmed.split_once('=')
            && name.trim() == SESSION_COOKIE_NAME
            && !value.is_empty()
        {
            return Some(value.trim().to_string());
        }
    }
    None
}

/// Builds the `Set-Cookie` header value for an active `HttpOnly` + `SameSite=Strict` session.
#[must_use]
pub fn build_session_cookie(session_id: &str) -> String {
    format!(
        "{SESSION_COOKIE_NAME}={session_id}; HttpOnly; SameSite=Strict; Path=/; Max-Age={}",
        SESSION_TTL.as_secs()
    )
}

/// Builds the `Set-Cookie` header value that clears the session cookie.
#[must_use]
pub fn clear_session_cookie() -> String {
    format!("{SESSION_COOKIE_NAME}=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0")
}

/// Middleware enforcing session cookie authentication and CSRF checks on state-changing requests.
pub async fn require_auth(
    State(auth): State<AuthState>,
    req: Request,
    next: Next,
) -> Result<Response, Response> {
    let Some(session_id) = extract_session_cookie(&req) else {
        return Err(error_response(
            StatusCode::UNAUTHORIZED,
            "unauthorized",
            "missing session cookie",
        ));
    };

    let Some(session) = auth.get_session(&session_id).await else {
        return Err(error_response(
            StatusCode::UNAUTHORIZED,
            "unauthorized",
            "invalid or expired session",
        ));
    };

    if is_state_changing(req.method()) {
        if !is_allowed_origin(&req) {
            return Err(error_response(
                StatusCode::FORBIDDEN,
                "csrf_origin_rejected",
                "cross-origin state-changing request rejected",
            ));
        }

        let header_csrf = req
            .headers()
            .get(CSRF_HEADER_NAME)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");

        if !constant_time_eq(session.csrf_token.as_bytes(), header_csrf.as_bytes()) {
            return Err(error_response(
                StatusCode::FORBIDDEN,
                "csrf_invalid",
                "missing or invalid X-CSRF-Token header",
            ));
        }
    }

    Ok(next.run(req).await)
}

/// Verifies `Origin` or `Referer` (when present) belongs to loopback localhost.
#[must_use]
pub fn is_allowed_origin(req: &Request) -> bool {
    if let Some(origin) = req.headers().get(ORIGIN).and_then(|v| v.to_str().ok()) {
        return is_loopback_origin_url(origin);
    }
    if let Some(referer) = req.headers().get(REFERER).and_then(|v| v.to_str().ok()) {
        return is_loopback_origin_url(referer);
    }
    true
}

fn is_loopback_origin_url(url: &str) -> bool {
    let rest = url
        .strip_prefix("http://")
        .or_else(|| url.strip_prefix("https://"))
        .unwrap_or("");
    let host_port = rest.split('/').next().unwrap_or("");
    let host = if host_port.starts_with('[') {
        host_port
            .split(']')
            .next()
            .map(|s| s.trim_start_matches('['))
            .unwrap_or("")
    } else {
        host_port.split(':').next().unwrap_or("")
    };
    matches!(host, "127.0.0.1" | "localhost" | "::1")
}

fn is_state_changing(method: &Method) -> bool {
    matches!(
        *method,
        Method::POST | Method::PUT | Method::PATCH | Method::DELETE
    )
}

/// Middleware attaching strict security headers (`CSP`, `X-Frame-Options`, `Referrer-Policy`) to every response.
pub async fn security_headers(req: Request, next: Next) -> Response {
    let is_api = req.uri().path().starts_with("/api/");
    let mut response = next.run(req).await;
    let headers = response.headers_mut();

    headers.insert(
        HeaderName::from_static("content-security-policy"),
        HeaderValue::from_static(CSP_HEADER_VALUE),
    );
    headers.insert(X_FRAME_OPTIONS, HeaderValue::from_static("DENY"));
    headers.insert(
        HeaderName::from_static("referrer-policy"),
        HeaderValue::from_static("no-referrer"),
    );
    headers.insert(X_CONTENT_TYPE_OPTIONS, HeaderValue::from_static("nosniff"));

    if is_api {
        headers.insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
    }

    // Ensure Set-Cookie is preserved cleanly by Axum
    let _ = SET_COOKIE;
    response
}

fn error_response(status: StatusCode, code: &str, message: &str) -> Response {
    (
        status,
        Json(ApiErrorBody {
            error: code.to_string(),
            message: message.to_string(),
        }),
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn constant_time_eq_works() {
        assert!(constant_time_eq(b"secret123", b"secret123"));
        assert!(!constant_time_eq(b"secret123", b"secret124"));
        assert!(!constant_time_eq(b"short", b"longer"));
    }

    #[test]
    fn loopback_origin_validation() {
        assert!(is_loopback_origin_url("http://127.0.0.1:8420"));
        assert!(is_loopback_origin_url("http://localhost:5173/dashboard"));
        assert!(is_loopback_origin_url("http://[::1]:8420"));
        assert!(!is_loopback_origin_url("https://evil.example.com"));
        assert!(!is_loopback_origin_url("http://192.168.1.50:8420"));
    }
}
