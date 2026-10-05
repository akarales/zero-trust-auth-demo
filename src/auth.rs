//! JWT issue/verify (HS256 demo keys; ES256 + key rotation on the roadmap).
//! jsonwebtoken 11 enforces HS256 key minimums — demo secrets are 32 bytes.

use chrono::{Duration, Utc};
use jsonwebtoken::{DecodingKey, EncodingKey, Header, Validation, decode, encode};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Claims {
    pub sub: String,
    pub role: String,
    /// department attribute (ABAC input)
    pub department: String,
    pub iat: i64,
    pub exp: i64,
}

#[derive(Debug, thiserror::Error)]
pub enum AuthError {
    #[error("invalid token: {0}")]
    Invalid(String),
}

pub fn issue(user: &str, role: &str, department: &str, secret: &[u8]) -> Result<String, AuthError> {
    let now = Utc::now();
    let claims = Claims {
        sub: user.to_string(),
        role: role.to_string(),
        department: department.to_string(),
        iat: now.timestamp(),
        exp: (now + Duration::hours(1)).timestamp(),
    };
    encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(secret),
    )
    .map_err(|e| AuthError::Invalid(e.to_string()))
}

pub fn verify(token: &str, secret: &[u8]) -> Result<Claims, AuthError> {
    let data = decode::<Claims>(
        token,
        &DecodingKey::from_secret(secret),
        &Validation::default(),
    )
    .map_err(|e| AuthError::Invalid(e.to_string()))?;
    Ok(data.claims)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip() {
        let token = issue(
            "ada",
            "physician",
            "cardiology",
            b"0123456789abcdef0123456789abcdef",
        )
        .expect("issue");
        let claims = verify(&token, b"0123456789abcdef0123456789abcdef").expect("verify");
        assert_eq!(claims.sub, "ada");
        assert_eq!(claims.role, "physician");
        assert_eq!(claims.department, "cardiology");
    }

    #[test]
    fn wrong_secret_rejected() {
        let token = issue(
            "ada",
            "physician",
            "cardiology",
            b"0123456789abcdef0123456789abcdef",
        )
        .expect("issue");
        assert!(verify(&token, b"fedcba9876543210fedcba9876543210").is_err());
    }

    #[test]
    fn garbage_rejected() {
        assert!(verify("not-a-token", b"0123456789abcdef0123456789abcdef").is_err());
    }
}
