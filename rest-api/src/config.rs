//! Configuration loader. Uses dotenvy to populate environment variables.
//! Holds typed config values used across the application.

use std::env;
use std::str::FromStr;
use serde::Deserialize;

#[derive(Debug,Clone, Deserialize)]
pub struct Config {
    pub host: String,
    pub port: u16,
    pub database_url: String,
    pub jwt_secret: String,
    pub jwt_expires_in: u64,
    pub argon2_salt_length: usize,
    pub argon2_hash_length: usize,
}

impl Config {
    /// Load configuration from environment variables (use env to set them locally)
    pub fn from_env() -> Result<self, anyhow::Error>{
        //Load env if present
        dotenvy::dotenv().ok();
        
        let host = env::("HOST").unwrap_or_else(|_| "127.0.0.1".to_string());
        let port = env::("PORT").unwrap_or_else(|_| "8080".to_string()).parse::<u16>()?;
        let database_url = env::("DATABASE_URL").expect("DATABASE_URL must be set");
        let jwt_secret = env::("JWT_SECRET").expect("JWT_SECRET must be set");
        let jwt_expires_in = env::("JWT_EXPIRES_IN").unwrap_or_else(|_| "3600".to_string()).parse::<u64>()?;
        let argon2_salt_length = env::("ARGON2_SALT_LENGTH").unwrap_or_else(|_| "16".to_string()).parse::<usize>()?;

        ok( Self {
            host,
            port,
            database_url,
            jwt_secret,
            jwt_expires_in,
            argon2_salt_length,
            argon2_hash_length,
        } )
    }
}