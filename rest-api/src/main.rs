use std::env;
use std::net::SocketAddr;
use std::sync::Arc;

use axum::{
routing::{get,post,put,delete},
Router,
extract::path,
json
};

use tower_http::trace::TraceLayer;
use tower_http::cors::{CorsLayer, Any};
use tracing_subscriber;

fn main() {
    println!("Hello, world!");
}
