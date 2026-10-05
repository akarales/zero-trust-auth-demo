//! zero-trust-auth-demo — JWT + ABAC + rate limiting + audit logging.
//!
//! Zero-trust posture in miniature: every request is authenticated
//! (JWT), authorized (attribute-based policy — never just "logged in"),
//! rate-limited per client, and written to an append-only audit log.
//! Pure policy logic lives in `policy.rs` (tested); the demo data store
//! is in-memory (Postgres/Redis are Phase 1).

pub mod audit;
pub mod auth;
pub mod policy;
pub mod rate_limit;
pub mod routes;
pub mod state;

pub use state::AppState;
