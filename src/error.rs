//! Error taxonomy and HTTP response mapping.

use axum::http::StatusCode;
use axum::response::{Html, IntoResponse, Response};
use axum::Json;
use serde_json::json;

/// Errors that map onto the API error matrix (`{"error-message": …}` JSON body).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AppError {
    Unauthenticated,
    Forbidden,
    MissingGroups,
    BadCsrf,
    BadState,
    Upstream,
    Internal,
}

impl AppError {
    /// The HTTP status the error is reported as.
    pub fn status(&self) -> StatusCode {
        match self {
            AppError::Unauthenticated => StatusCode::UNAUTHORIZED,
            AppError::Forbidden => StatusCode::FORBIDDEN,
            AppError::MissingGroups => StatusCode::INTERNAL_SERVER_ERROR,
            AppError::BadCsrf => StatusCode::FORBIDDEN,
            AppError::BadState => StatusCode::UNAUTHORIZED,
            AppError::Upstream => StatusCode::BAD_GATEWAY,
            AppError::Internal => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }

    /// The human-readable error message carried in the response body.
    pub fn error_message(&self) -> &'static str {
        match self {
            AppError::Unauthenticated => "Not Authenticated",
            AppError::Forbidden => "Forbidden",
            AppError::MissingGroups => {
                "Application not configured correctly. Missing groups in claim"
            }
            AppError::BadCsrf => "Invalid CSRF token",
            AppError::BadState => "Invalid state",
            AppError::Upstream => "Upstream error",
            AppError::Internal => "Internal server error",
        }
    }
}

impl From<AppError> for ApiError {
    fn from(error: AppError) -> Self {
        ApiError(error)
    }
}

impl From<AppError> for PageError {
    fn from(error: AppError) -> Self {
        PageError(error)
    }
}

/// API error wrapper: JSON body `{"error-message": …}`, `application/json`.
pub struct ApiError(pub AppError);

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let status = self.0.status();
        let body = json!({ "error-message": self.0.error_message() });

        (status, Json(body)).into_response()
    }
}

/// HTML error wrapper: small error page, `text/html`.
pub struct PageError(pub AppError);

impl IntoResponse for PageError {
    fn into_response(self) -> Response {
        let status = self.0.status();
        let message = self.0.error_message();
        // Errors can be rendered before the app is fully up, so keep a
        // minimal inline page as a fallback if the template cannot render.
        let context = minijinja::context! { message };
        let body = match crate::web::templates::render("error.html", context) {
            Ok(body) => body,
            Err(_) => format!(
                "<html><head><title>VSM Error</title></head><body><h1>{message}</h1></body></html>"
            ),
        };

        (status, Html(body)).into_response()
    }
}
