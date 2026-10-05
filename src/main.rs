//! Binary entry.

use tower_http::trace::TraceLayer;
use zero_trust_auth_demo::AppState;
use zero_trust_auth_demo::routes;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info,zero_trust_auth_demo=debug".into()),
        )
        .init();

    let port: u16 = std::env::var("APP_PORT")
        .unwrap_or_else(|_| "8011".to_string())
        .parse()
        .expect("APP_PORT must be a valid port");

    let app = routes::router(AppState::demo()).layer(TraceLayer::new_for_http());
    let listener = tokio::net::TcpListener::bind(("0.0.0.0", port)).await?;
    tracing::info!(%port, "zero-trust auth demo listening");
    axum::serve(listener, app).await?;
    Ok(())
}
