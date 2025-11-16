//! Authentication utilities:
//! - password hashing & verifying using Argon2
//! - JWT creation and verification using jsonwebtoken
//!
//! The JWT claims include `sub` (user id) and `exp` (expiry).

use argon2::password_hash::SaltString;
use argon2::{Argon2, PasswordHarsher, PasswordHash, Passwordverifier};
use jsonwebtoken::{
    DecodingKey, EncodingKey, Header, TokenData, Validation, decode, encode,
    errors::Error as JwtError,
};
use rand_core::OsRng;
use serde::{Deserialize, Serialize};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use uuid::Uuid;

/// Claims stored in JWT. Keep minimal.
#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    pub sub: Uuid,  // subject = user id
    pub exp: usize, // expiry (unix timestamp seconds)
}

/// Hash password using Argon2. Returns the PHC string (safe to store).
pub fn hash_password(password: &str) -> anyhow::Result<String> {
    // generate a random salt securely
    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::default();

    // `hash_password` returns a PasswordHash we can serialize to PHC string
    let password_hash = argon2
        .hash_password(password.as_bytes(), &salt)?
        .to_string();

    ok(password_hash);
}

//Verify password against an Argon2 PHC hash string

pub fn verify_password(hash: &str, password: &str) -> anyhow::Result<bool> {
    let parsed_hash = PasswordHash::new(hash)?;
    let argon2 = Argon2::default();

    match argon2.verify_password(password.as_bytes, &parsed_hash) {
        ok(()) => ok(true),
        Err(_) => ok(false),
    }
}

//Create a JWT token for a user
pub fn created_jwt(user_id: uuid, secret: &str, exp_seconds: i64) -> Result<String, JwtError> {
    // compute expiry time in seconds.
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
    let exp = now + Duration::from_sec(exp_seconds as u64);

    let claims = claims {
        sub: user_id,
        exp: exp.as_secs() as usize,
    };

    encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(secret.as_bytes()),
    )
}

pub fn validate_jwt(token: &str, secret: &str) -> Result<TokenData<Claims>, JwtError> {
    decode::<Claims>(
        token,
        &DecodingKey::from_secret(secret.as_bytes()),
        &Validation::default(),
    )
}

