//! Request handlers: implement register, login and the CRUD for users.
//!
//! Each handler is `async` and uses the shared `sqlx::Pool<Postgres>` stored
//! as state on the axum router. We show how to:
//!  - create a user with hashed password
//!  - login user (verify password) and return JWT
//!  - protect endpoints (validate JWT from Authorization header)
//!  - basic CRUD operations using sqlx

use axum::{
    extract::{State, Json, Path, TypedHeader},
    http::HeaderMap,
    headers::{authorization::Bearer, Authorization},
};
use serde_json::json;
use sqlx::PgPool;
use uuid::Uuid;
use chrono::Utc;

use crate::models::{CreateUser, LoginRequest, User, UpdateUser, LoginResponse};
use crate::auth::{hash_password, verify_password, create_jwt, validate_jwt, Claims};
use crate::config::Config;
use crate::errors::AppError;

/// Helper: extract bearer token from headers
fn extract_bearer_token(headers: &HeaderMap) -> Option<String> {
    // axum also offers TypedHeader extraction; here we opt manual extraction to illustrate.
    headers.get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| {
            if s.to_lowercase().starts_with("bearer ") {
                Some(s[7..].to_string())
            } else {
                None
            }
        })
}

/// Handler: Register a new user (public)
pub async fn register_handler(
    State(pool): State<PgPool>,
    Json(payload): Json<CreateUser>,
) -> Result<Json<User>, AppError> {
    // Simple validation
    if payload.username.trim().is_empty() || payload.password.len() < 6 {
        return Err(AppError::BadRequest("Invalid username or password (min 6)".into()));
    }

    // Hash password (argon2)
    let password_hash = hash_password(&payload.password).map_err(|e| AppError::Internal(e.to_string()))?;

    // Insert into DB
    // We return the created user's id, username, email, created_at
    let rec = sqlx::query!(
        r#"
        INSERT INTO users (username, email, password_hash)
        VALUES ($1, $2, $3)
        RETURNING id, username, email, created_at
        "#,
        payload.username,
        payload.email,
        password_hash
    )
    .fetch_one(&pool)
    .await
    .map_err(|e| {
        // map unique constraint errors to bad request for nicer UX
        let msg = e.to_string();
        if msg.contains("unique") {
            AppError::BadRequest("username or email already exists".into())
        } else {
            AppError::DbError(msg)
        }
    })?;

    let user = User {
        id: rec.id,
        username: rec.username,
        email: rec.email,
        created_at: rec.created_at.into(),
    };

    Ok(Json(user))
}

/// Handler: Login — verify credentials and return JWT
pub async fn login_handler(
    State(pool): State<PgPool>,
    Json(payload): Json<LoginRequest>,
) -> Result<Json<LoginResponse>, AppError> {
    // Fetch user by email
    let row = sqlx::query!(
        r#"SELECT id, password_hash FROM users WHERE email = $1"#,
        payload.email
    )
    .fetch_optional(&pool)
    .await
    .map_err(|e| AppError::DbError(e.to_string()))?;

    let row = match row {
        Some(r) => r,
        None => return Err(AppError::Unauthorized("Invalid credentials".into())),
    };

    // Verify password
    let verified = verify_password(&row.password_hash, &payload.password).map_err(|e| AppError::Internal(e.to_string()))?;
    if !verified {
        return Err(AppError::Unauthorized("Invalid credentials".into()));
    }

    // Create JWT (we need secret & expiry)
    let jwt_secret = std::env::var("JWT_SECRET").expect("JWT_SECRET must be set");
    let exp_seconds = std::env::var("JWT_EXP_SECONDS")
        .ok()
        .and_then(|s| s.parse::<i64>().ok())
        .unwrap_or(3600);

    let token = create_jwt(row.id, &jwt_secret, exp_seconds).map_err(|e| AppError::Internal(e.to_string()))?;

    Ok(Json(LoginResponse { token }))
}

/// Middleware-like helper: validate Authorization header, return user id
async fn authenticate(headers: &HeaderMap) -> Result<Uuid, AppError> {
    let token = extract_bearer_token(headers).ok_or_else(|| AppError::Unauthorized("Missing Authorization Bearer token".into()))?;
    let jwt_secret = std::env::var("JWT_SECRET").map_err(|_| AppError::Internal("JWT_SECRET not set".into()))?;
    let token_data = validate_jwt(&token, &jwt_secret).map_err(|_| AppError::Unauthorized("Invalid token".into()))?;
    Ok(token_data.claims.sub)
}

/// Handler: list users (protected)
pub async fn list_users_handler(
    State(pool): State<PgPool>,
    headers: HeaderMap,
) -> Result<Json<Vec<User>>, AppError> {
    // Authenticate first
    let _caller = authenticate(&headers).await?;

    // Query DB for users
    let rows = sqlx::query!(
        r#"SELECT id, username, email, created_at FROM users ORDER BY created_at DESC LIMIT 100"#
    )
    .fetch_all(&pool)
    .await
    .map_err(|e| AppError::DbError(e.to_string()))?;

    let users = rows.into_iter().map(|r| User {
        id: r.id,
        username: r.username,
        email: r.email,
        created_at: r.created_at.into(),
    }).collect();

    Ok(Json(users))
}

/// Handler: get one user by id (protected)
pub async fn get_user_handler(
    State(pool): State<PgPool>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> Result<Json<User>, AppError> {
    let _caller = authenticate(&headers).await?;

    let rec = sqlx::query!(
        r#"SELECT id, username, email, created_at FROM users WHERE id = $1"#,
        id
    )
    .fetch_optional(&pool)
    .await
    .map_err(|e| AppError::DbError(e.to_string()))?;

    match rec {
        Some(r) => Ok(Json(User {
            id: r.id,
            username: r.username,
            email: r.email,
            created_at: r.created_at.into(),
        })),
        None => Err(AppError::NotFound("User not found".into())),
    }
}

/// Handler: update user (protected) — allows updating username/email/password
pub async fn update_user_handler(
    State(pool): State<PgPool>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    Json(payload): Json<UpdateUser>,
) -> Result<Json<User>, AppError> {
    let _caller = authenticate(&headers).await?;

    // If password is present, hash it
    let new_password_hash = if let Some(pw) = payload.password {
        Some(hash_password(&pw).map_err(|e| AppError::Internal(e.to_string()))?)
    } else {
        None
    };

    // Build update query dynamically — example uses COALESCE pattern
    // Note: we must fetch existing row and update fields provided.
    let existing = sqlx::query!(
        r#"SELECT id, username, email, created_at FROM users WHERE id = $1"#,
        id
    )
    .fetch_optional(&pool)
    .await
    .map_err(|e| AppError::DbError(e.to_string()))?;

    let existing = match existing {
        Some(row) => row,
        None => return Err(AppError::NotFound("User not found".into())),
    };

    let new_username = payload.username.unwrap_or(existing.username.clone());
    let new_email = payload.email.unwrap_or(existing.email.clone());

    if let Some(pw_hash) = new_password_hash {
        // update with password
        let rec = sqlx::query!(
            r#"UPDATE users SET username=$1, email=$2, password_hash=$3 WHERE id=$4
               RETURNING id, username, email, created_at"#,
            new_username,
            new_email,
            pw_hash,
            id
        )
        .fetch_one(&pool)
        .await
        .map_err(|e| AppError::DbError(e.to_string()))?;

        return Ok(Json(User {
            id: rec.id,
            username: rec.username,
            email: rec.email,
            created_at: rec.created_at.into(),
        }));
    } else {
        // update without password
        let rec = sqlx::query!(
            r#"UPDATE users SET username=$1, email=$2 WHERE id=$3
               RETURNING id, username, email, created_at"#,
            new_username,
            new_email,
            id
        )
        .fetch_one(&pool)
        .await
        .map_err(|e| AppError::DbError(e.to_string()))?;

        return Ok(Json(User {
            id: rec.id,
            username: rec.username,
            email: rec.email,
            created_at: rec.created_at.into(),
        }));
    }
}

/// Handler: delete user (protected)
pub async fn delete_user_handler(
    State(pool): State<PgPool>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> Result<Json<serde_json::Value>, AppError> {
    let _caller = authenticate(&headers).await?;

    let res = sqlx::query!("DELETE FROM users WHERE id = $1", id)
        .execute(&pool)
        .await
        .map_err(|e| AppError::DbError(e.to_string()))?;

    if res.rows_affected() == 0 {
        return Err(AppError::NotFound("User not found".into()));
    }

    Ok(Json(json!({ "status": "deleted" })))
}
