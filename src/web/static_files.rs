//! Static asset serving: embedded defaults with an on-disk override.

use std::path::{Component, Path};

use axum::extract::Path as PathParam;
use axum::http::{header, StatusCode};
use axum::response::{IntoResponse, Response};
use rust_embed::RustEmbed;

#[derive(RustEmbed)]
#[folder = "static/"]
struct EmbeddedAssets;

/// Returns an asset's bytes, preferring a mounted `static/<path>` file.
fn asset(path: &str) -> Option<Vec<u8>> {
    if let Ok(bytes) = std::fs::read(Path::new("static").join(path)) {
        return Some(bytes);
    }

    EmbeddedAssets::get(path).map(|file| file.data.into_owned())
}

/// Rejects absolute paths and `..` traversal before touching the filesystem.
fn safe_name(path: &str) -> bool {
    !path.is_empty()
        && Path::new(path)
            .components()
            .all(|component| matches!(component, Component::Normal(_)))
}

fn content_type(path: &str) -> &'static str {
    let extension = path
        .rsplit('.')
        .next()
        .unwrap_or_default()
        .to_ascii_lowercase();
    match extension.as_str() {
        "png" => "image/png",
        "svg" => "image/svg+xml",
        "ico" => "image/x-icon",
        "css" => "text/css",
        "js" => "text/javascript",
        _ => "application/octet-stream",
    }
}

/// `GET /static/*path`: serves a mounted asset when present, else the embedded one.
pub async fn file(PathParam(path): PathParam<String>) -> Response {
    if !safe_name(&path) {
        return StatusCode::NOT_FOUND.into_response();
    }

    let Some(bytes) = asset(&path) else {
        return StatusCode::NOT_FOUND.into_response();
    };

    ([(header::CONTENT_TYPE, content_type(&path))], bytes).into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn logo_is_embedded_for_diskless_runtime() {
        let asset = EmbeddedAssets::get("logo.png").expect("logo.png is embedded");
        assert!(!asset.data.is_empty());
        assert!(
            asset.data.starts_with(b"\x89PNG\r\n\x1a\n"),
            "logo.png does not have PNG magic bytes"
        );
        assert!(
            asset.data.len() >= 1024,
            "logo.png is unexpectedly small: {} bytes",
            asset.data.len()
        );
    }

    #[test]
    fn embedded_assets_are_not_lfs_pointers() {
        for path in EmbeddedAssets::iter() {
            let asset = EmbeddedAssets::get(&path).expect("iterated asset is readable");
            assert!(
                !asset.data.starts_with(b"version https://git-lfs"),
                "asset {path} is an un-smudged Git LFS pointer"
            );
        }
    }

    #[test]
    fn traversal_names_are_rejected() {
        assert!(safe_name("logo.png"));
        assert!(!safe_name("../Cargo.toml"));
        assert!(!safe_name("/etc/passwd"));
        assert!(!safe_name("nested/../../secret"));
    }
}
