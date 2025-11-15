//! Authentication utilities:
//! - password hashing & verifying using Argon2
//! - JWT creation and verification using jsonwebtoken
//!
//! The JWT claims include `sub` (user id) and `exp` (expiry).


use std::time::{SystemTime,UNIX_EPOCH,Duration};
use argon2::{Argon2,PasswordHash,PasswordHarsher,Passwordverifier};
use argon2::password_hash::SaltString;
use rand_core::OsRng;
use jsonwebtoken::{EncodingKey, DecodingKey, Header, Validation, encode, decode, TokenData, errors::Error as JwtError};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Claims stored in JWT. Keep minimal.
#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    pub sub: Uuid, // subject = user id
    pub exp: usize, // expiry (unix timestamp seconds)
}


/// Hash password using Argon2. Returns the PHC string (safe to store).
pub fn hash_password(password:&str) -> anyhow::Result<String>{
    // generate a random salt securely
    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::default();

    // `hash_password` returns a PasswordHash we can serialize to PHC string
    
}