//! End-to-end authz flows: issue token → ABAC-protected access → rate
//! limits → audit-gated endpoints.

use axum::body::Body;
use axum::http::{Request, StatusCode};
use serde_json::Value;
use tower::ServiceExt;

use zero_trust_auth_demo::AppState;
use zero_trust_auth_demo::routes;

async fn token(app: &axum::Router, user: &str, role: &str, department: &str) -> String {
    let response = app
        .clone()
        .oneshot(
            Request::post("/auth/token")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({ "user": user, "role": role, "department": department })
                        .to_string(),
                ))
                .expect("builds"),
        )
        .await
        .expect("request");
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("body");
    let body: Value = serde_json::from_slice(&bytes).expect("json");
    body["token"].as_str().expect("token").to_string()
}

async fn call(
    app: &axum::Router,
    method: &str,
    path: &str,
    token: Option<&str>,
    body: Option<String>,
) -> (StatusCode, Value) {
    let mut builder = Request::builder().method(method).uri(path);
    if let Some(token) = token {
        builder = builder.header("authorization", format!("Bearer {token}"));
    }
    if body.is_some() {
        builder = builder.header("content-type", "application/json");
    }
    let response = app
        .clone()
        .oneshot(
            builder
                .body(Body::from(body.unwrap_or_default()))
                .expect("builds"),
        )
        .await
        .expect("request");
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("body");
    (status, serde_json::from_slice(&bytes).expect("json"))
}

#[tokio::test]
async fn health_ok() {
    let app = routes::router(AppState::demo());
    let (status, body) = call(&app, "GET", "/health", None, None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["status"], "ok");
}

#[tokio::test]
async fn same_department_physician_reads_and_writes() {
    let app = routes::router(AppState::demo());
    let token = token(&app, "ada", "physician", "cardiology").await;
    let (status, body) = call(
        &app,
        "GET",
        "/api/v1/records/cardio-patient-1",
        Some(&token),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["department"], "cardiology");

    let (status, body) = call(
        &app,
        "PUT",
        "/api/v1/records/cardio-patient-1",
        Some(&token),
        Some(r#"{"content":"updated note"}"#.into()),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["written_by"], "ada");
}

#[tokio::test]
async fn cross_department_denied() {
    let app = routes::router(AppState::demo());
    let token = token(&app, "bob", "physician", "oncology").await;
    let (status, body) = call(
        &app,
        "GET",
        "/api/v1/records/cardio-patient-1",
        Some(&token),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert!(body["error"].as_str().unwrap().contains("policy"));
}

#[tokio::test]
async fn nurse_reads_but_cannot_write() {
    let app = routes::router(AppState::demo());
    let token = token(&app, "grace", "nurse", "cardiology").await;
    let (status, _) = call(
        &app,
        "GET",
        "/api/v1/records/cardio-patient-1",
        Some(&token),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let (status, _) = call(
        &app,
        "PUT",
        "/api/v1/records/cardio-patient-1",
        Some(&token),
        Some(r#"{"content":"x"}"#.into()),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn no_token_is_unauthorized() {
    let app = routes::router(AppState::demo());
    let (status, _) = call(&app, "GET", "/api/v1/records/cardio-patient-1", None, None).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn garbage_token_is_unauthorized() {
    let app = routes::router(AppState::demo());
    let (status, _) = call(
        &app,
        "GET",
        "/api/v1/records/cardio-patient-1",
        Some("garbage.token.here"),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn rate_limit_kicks_in() {
    // Tight limiter: 2 capacity, zero refill for the test instance.
    let app = routes::router(AppState {
        secret: b"zero-trust-demo-secret".to_vec(),
        limiter: zero_trust_auth_demo::rate_limit::RateLimiter::new(2, 0.0),
        audit: zero_trust_auth_demo::audit::AuditLog::in_memory(),
        records: std::sync::Arc::new(std::sync::RwLock::new(
            [("cardio-patient-1".to_string(), "x".to_string())]
                .into_iter()
                .collect(),
        )),
    });
    let token = token(&app, "ada", "physician", "cardiology").await;
    let first = call(
        &app,
        "GET",
        "/api/v1/records/cardio-patient-1",
        Some(&token),
        None,
    )
    .await;
    let second = call(
        &app,
        "GET",
        "/api/v1/records/cardio-patient-1",
        Some(&token),
        None,
    )
    .await;
    let third = call(
        &app,
        "GET",
        "/api/v1/records/cardio-patient-1",
        Some(&token),
        None,
    )
    .await;
    assert_eq!(first.0, StatusCode::OK);
    assert_eq!(second.0, StatusCode::OK);
    assert_eq!(third.0, StatusCode::TOO_MANY_REQUESTS);
}

#[tokio::test]
async fn audit_tail_is_auditor_only() {
    let app = routes::router(AppState::demo());
    let physician = token(&app, "ada", "physician", "cardiology").await;
    let (status, _) = call(&app, "GET", "/api/v1/audit", Some(&physician), None).await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    let auditor = token(&app, "zed", "auditor", "security").await;
    let (status, _) = call(&app, "GET", "/api/v1/audit", Some(&auditor), None).await;
    assert_eq!(status, StatusCode::OK);
}
