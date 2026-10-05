//! Routes: token issue, ABAC-protected records, audit tail.

use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::Deserialize;
use serde_json::{Value, json};

use crate::AppState;
use crate::audit::AuditRecord;
use crate::auth;
use crate::policy::{Action, Decision, Resource, ResourceKind, Subject, decide};

pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/health", get(health))
        .route("/auth/token", post(issue_token))
        .route("/api/v1/records/{record_id}", get(read_record))
        .route(
            "/api/v1/records/{record_id}",
            axum::routing::put(write_record).patch(approve_record),
        )
        .route("/api/v1/audit", get(audit_tail))
        .with_state(state)
}

pub async fn health() -> Json<Value> {
    Json(json!({ "status": "ok", "version": env!("CARGO_PKG_VERSION") }))
}

#[derive(Debug, Deserialize)]
pub struct TokenRequest {
    pub user: String,
    pub role: String,
    pub department: String,
}

pub async fn issue_token(
    State(state): State<AppState>,
    Json(request): Json<TokenRequest>,
) -> Response {
    // Zero-trust: the issuer is a demo IdP; in production this is where an
    // upstream identity check happens (the point of the demo is what
    // happens AFTER the token exists).
    match auth::issue(
        &request.user,
        &request.role,
        &request.department,
        &state.secret,
    ) {
        Ok(token) => (
            StatusCode::OK,
            Json(json!({ "token": token, "expires_in": 3600 })),
        )
            .into_response(),
        Err(err) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": err.to_string() })),
        )
            .into_response(),
    }
}

fn bearer(headers: &HeaderMap) -> Option<&str> {
    headers
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
}

async fn authorize(
    state: &AppState,
    headers: &HeaderMap,
    action: Action,
    resource_kind: ResourceKind,
    resource_department: &str,
    resource_name: &str,
) -> Result<Subject, Box<Response>> {
    // 1. Authenticate.
    let token = bearer(headers).ok_or_else(|| {
        Box::new(
            (
                StatusCode::UNAUTHORIZED,
                Json(json!({ "error": "missing bearer token" })),
            )
                .into_response(),
        )
    })?;
    let claims = auth::verify(token, &state.secret).map_err(|_| {
        Box::new(
            (
                StatusCode::UNAUTHORIZED,
                Json(json!({ "error": "invalid or expired token" })),
            )
                .into_response(),
        )
    })?;

    // 2. Rate limit per subject.
    let rate_limited = !state.limiter.allow(&claims.sub);

    // 3. Authorize (ABAC).
    let subject = Subject {
        user: claims.sub.clone(),
        role: claims.role.clone(),
        department: claims.department.clone(),
    };
    let decision = decide(
        &subject,
        &action,
        &Resource {
            kind: resource_kind,
            department: resource_department.to_string(),
        },
    );

    // 4. Audit everything.
    state.audit.append(&AuditRecord {
        at: chrono::Utc::now(),
        subject: subject.user.clone(),
        role: subject.role.clone(),
        action: format!("{action:?}"),
        resource: resource_name.to_string(),
        decision: if rate_limited {
            "deny".into()
        } else {
            format!("{decision:?}").to_lowercase()
        },
        rate_limited,
        request_id: uuid::Uuid::new_v4().to_string(),
    });

    if rate_limited {
        return Err(Box::new(
            (
                StatusCode::TOO_MANY_REQUESTS,
                Json(json!({ "error": "rate limit exceeded" })),
            )
                .into_response(),
        ));
    }
    match decision {
        Decision::Allow => Ok(subject),
        Decision::Deny => Err(Box::new(
            (
                StatusCode::FORBIDDEN,
                Json(json!({ "error": "policy denied this request" })),
            )
                .into_response(),
        )),
    }
}

pub async fn read_record(
    State(state): State<AppState>,
    Path(record_id): Path<String>,
    headers: HeaderMap,
) -> Response {
    let Some(department) = AppState::record_department(&record_id) else {
        return (
            StatusCode::NOT_FOUND,
            Json(json!({ "error": format!("unknown record: {record_id}") })),
        )
            .into_response();
    };
    match authorize(
        &state,
        &headers,
        Action::Read,
        ResourceKind::PatientRecord,
        department,
        &record_id,
    )
    .await
    {
        Ok(_) => {
            let records = state.records.read().expect("records lock");
            (
                StatusCode::OK,
                Json(json!({
                    "record_id": record_id,
                    "department": department,
                    "content": records.get(&record_id),
                })),
            )
                .into_response()
        }
        Err(response) => *response,
    }
}

#[derive(Debug, Deserialize)]
pub struct WriteRequest {
    pub content: String,
}

pub async fn write_record(
    State(state): State<AppState>,
    Path(record_id): Path<String>,
    headers: HeaderMap,
    Json(request): Json<WriteRequest>,
) -> Response {
    let Some(department) = AppState::record_department(&record_id) else {
        return (
            StatusCode::NOT_FOUND,
            Json(json!({ "error": format!("unknown record: {record_id}") })),
        )
            .into_response();
    };
    match authorize(
        &state,
        &headers,
        Action::Write,
        ResourceKind::PatientRecord,
        department,
        &record_id,
    )
    .await
    {
        Ok(subject) => {
            state
                .records
                .write()
                .expect("records lock")
                .insert(record_id.clone(), request.content);
            (
                StatusCode::OK,
                Json(json!({
                    "record_id": record_id,
                    "written_by": subject.user,
                })),
            )
                .into_response()
        }
        Err(response) => *response,
    }
}

pub async fn approve_record(
    State(state): State<AppState>,
    Path(record_id): Path<String>,
    headers: HeaderMap,
) -> Response {
    let Some(department) = AppState::record_department(&record_id) else {
        return (
            StatusCode::NOT_FOUND,
            Json(json!({ "error": format!("unknown record: {record_id}") })),
        )
            .into_response();
    };
    match authorize(
        &state,
        &headers,
        Action::Approve,
        ResourceKind::PatientRecord,
        department,
        &record_id,
    )
    .await
    {
        Ok(subject) => (
            StatusCode::OK,
            Json(json!({ "record_id": record_id, "approved_by": subject.user })),
        )
            .into_response(),
        Err(response) => *response,
    }
}

pub async fn audit_tail(State(state): State<AppState>, headers: HeaderMap) -> Response {
    match authorize(
        &state,
        &headers,
        Action::Read,
        ResourceKind::AuditLog,
        "security",
        "audit-log",
    )
    .await
    {
        Ok(_) => (
            StatusCode::OK,
            Json(json!({
                "note": "audit records stream to the configured sink (file in prod, tracing in demo)",
                "policy": "auditors may read; nobody may write",
            })),
        )
            .into_response(),
        Err(response) => *response,
    }
}
