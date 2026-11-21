use arch_fos_common::{ApiErrorBody, AuthStatus, LoginRequest};
use axum::Json;
use axum::extract::{Request, State};
use axum::http::header::SET_COOKIE;
use axum::http::{HeaderMap, HeaderValue, StatusCode};

use crate::auth::{
    build_session_cookie, clear_session_cookie, extract_session_cookie, is_allowed_origin,
};
use crate::routes::{ApiError, AppState};

/// Returns whether the current browser session is authenticated and provides the active CSRF token.
#[utoipa::path(
    get,
    path = "/api/v1/auth/me",
    tag = "auth",
    responses(
        (status = 200, description = "Session state", body = AuthStatus),
    )
)]
pub async fn auth_me(State(state): State<AppState>, req: Request) -> Json<AuthStatus> {
    if let Some(session_id) = extract_session_cookie(&req)
        && let Some(session) = state.auth.get_session(&session_id).await
    {
        return Json(AuthStatus {
            authenticated: true,
            csrf_token: Some(session.csrf_token),
        });
    }

    Json(AuthStatus {
        authenticated: false,
        csrf_token: None,
    })
}

/// Exchanges the local API token for an `HttpOnly`, `SameSite=Strict` session cookie.
#[utoipa::path(
    post,
    path = "/api/v1/auth/login",
    tag = "auth",
    request_body = LoginRequest,
    responses(
        (status = 200, description = "Authenticated session created", body = AuthStatus),
        (status = 401, description = "Invalid local token", body = ApiErrorBody),
        (status = 403, description = "Cross-origin login rejected", body = ApiErrorBody),
    )
)]
pub async fn auth_login(
    State(state): State<AppState>,
    req: Request,
) -> Result<(HeaderMap, Json<AuthStatus>), ApiError> {
    if !is_allowed_origin(&req) {
        return Err(ApiError {
            status: StatusCode::FORBIDDEN,
            code: "csrf_origin_rejected",
            message: "cross-origin login request rejected".to_string(),
        });
    }

    let body_bytes = axum::body::to_bytes(req.into_body(), 16 * 1024)
        .await
        .map_err(|_| ApiError::bad_request("invalid request body"))?;
    let payload: LoginRequest = serde_json::from_slice(&body_bytes)
        .map_err(|_| ApiError::bad_request("invalid JSON login payload"))?;

    if !state.auth.verify_api_token(&payload.token) {
        // Throttle failed authentication attempts to mitigate local brute-force loops.
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        return Err(ApiError::unauthorized("invalid local authentication token"));
    }

    let (session_id, csrf_token) = state.auth.create_session().await;
    let cookie = build_session_cookie(&session_id);
    let mut headers = HeaderMap::new();
    headers.insert(
        SET_COOKIE,
        HeaderValue::from_str(&cookie)
            .map_err(|_| ApiError::bad_request("failed to format session cookie"))?,
    );

    Ok((
        headers,
        Json(AuthStatus {
            authenticated: true,
            csrf_token: Some(csrf_token),
        }),
    ))
}

/// Invalidates the current session and clears the session cookie (requires CSRF header).
#[utoipa::path(
    post,
    path = "/api/v1/auth/logout",
    tag = "auth",
    responses(
        (status = 200, description = "Logged out", body = AuthStatus),
        (status = 401, description = "Unauthorized", body = ApiErrorBody),
        (status = 403, description = "CSRF validation failed", body = ApiErrorBody),
    )
)]
pub async fn auth_logout(
    State(state): State<AppState>,
    req: Request,
) -> Result<(HeaderMap, Json<AuthStatus>), ApiError> {
    if let Some(session_id) = extract_session_cookie(&req) {
        state.auth.delete_session(&session_id).await;
    }

    let mut headers = HeaderMap::new();
    headers.insert(
        SET_COOKIE,
        HeaderValue::from_str(&clear_session_cookie())
            .map_err(|_| ApiError::bad_request("failed to clear session cookie"))?,
    );

    Ok((
        headers,
        Json(AuthStatus {
            authenticated: false,
            csrf_token: None,
        }),
    ))
}
