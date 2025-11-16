//! Centralized error type mapping into axum `IntoResponse` for consistent HTTP responses.

use axum::response::{IntoResponse, Response};
use axum::http::StatusCode;
use serde_json::json;

//Application error type
#[derive(Debug)]
pub enum AppError {
    Unauthorized(String),
    BadRequest(String),
    NotFound(String),
    DbError(String),
    Internal(String),
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        match self {
            AppError::Unauthorized(msg) => {
                let body = json!({ "error": msg });
                (StatusCode::UNAUTHORIZED, axum::Json(body)).into_response()
            }
            AppError::BadRequest(msg) => {
                let body = json!({ "error": msg });
                (StatusCode::BAD_REQUEST, axum::Json(body)).into_response()
            }
            AppError::NotFound(msg) => {
                let body = json!({ "error": msg });
                (StatusCode::NOT_FOUND, axum::Json(body)).into_response()
            }
            AppError::DbError(msg) => {
                let body = json!({ "error": msg });
                (StatusCode::INTERNAL_SERVER_ERROR, axum::Json(body)).into_response()
            }
            AppError::Internal(msg) => {
                let body = json!({ "error": msg });
                (StatusCode::INTERNAL_SERVER_ERROR, axum::Json(body)).into_response()
            }
        }
    }
}