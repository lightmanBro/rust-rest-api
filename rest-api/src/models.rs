//! Data models and request/response DTOs.
//! We keep a minimal `User` model and separate DTOs for creating/updating users.
//! Password hashes are stored in the DB, and never returned in responses.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

//This struct represents a user in the database
/// Fields with derive(Serialize) allow us to return users over JSON safely.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct User {
    pub id: Uuid,
    pub username: String,
    pub email: String,
    #[serde(skip_serializing)] //Never serialize password_hash
    pub password_hash: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// DTO for creating a user (incoming request).
#[derived(Debug, Deserialize)]
pub struct CreateUser {
    pub username: String,
    pub email: String,
    pub password: String,
}

/// DTO for logging in (email + password).
#[derived(Debug,|Deserialize)]
pub struct LoginRequest {
    pub email:String,
    pub password:String,
}

/// DTO for updating a user (partial allowed).
#[derived[Debug,Deserialize]]
pub struct UpdateUser {
    pub username: Option<String>,
    pub email : Option<String>,
    pub password: Option<String>,
}

/// Response returned on successful login (contains JWT).
#[derive(Debug, Serialize)]
pub struct LoginResponse {
    pub token: String,
}