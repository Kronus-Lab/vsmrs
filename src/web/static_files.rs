//! Static asset serving: embedded defaults with an on-disk override.

use std::path::{Component, Path};

use axum::extract::Path as PathParam;
use axum::http::{header, StatusCode};
use axum::response::{IntoResponse, Response};
use rust_embed::RustEmbed;

#[derive(RustEmbed)]
#[folder = "static/"]
struct EmbeddedAssets;

/// Returns an asset's bytes from `root`, preferring a mounted file over the
/// embedded default.
fn asset_from(path: &str, root: &Path) -> Option<Vec<u8>> {
    if let Ok(bytes) = std::fs::read(root.join(path)) {
        return Some(bytes);
    }

    EmbeddedAssets::get(path).map(|file| file.data.into_owned())
}

/// Returns an asset's bytes, preferring the mounted `static/<path>` file.
fn asset(path: &str) -> Option<Vec<u8>> {
    asset_from(path, Path::new("static"))
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

    /// A uniquely named temp asset root removed on drop, even on panic.
    struct TempAssetRoot(std::path::PathBuf);

    impl TempAssetRoot {
        fn new(name: &str, contents: &[u8]) -> Self {
            let unique = format!(
                "vsm-static-{name}-{}-{}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .expect("system clock is after the unix epoch")
                    .as_nanos()
            );
            let root = std::env::temp_dir().join(unique);
            std::fs::create_dir_all(&root).expect("create static temp root");
            std::fs::write(root.join(name), contents).expect("write asset override");
            Self(root)
        }
    }

    impl Drop for TempAssetRoot {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn mounted_asset_overrides_embedded_bytes() {
        let contents = b"mounted logo.png override bytes";
        let root = TempAssetRoot::new("logo.png", contents);

        let bytes = asset_from("logo.png", &root.0).expect("asset bytes are available");
        assert_eq!(bytes, contents);
        assert_ne!(
            bytes,
            EmbeddedAssets::get("logo.png")
                .expect("logo.png is embedded")
                .data
                .into_owned()
        );
    }

    #[tokio::test]
    async fn unknown_asset_returns_not_found() {
        let name = format!(
            "missing-asset-{}.bin",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("system clock is after the unix epoch")
                .as_nanos()
        );
        let response = file(PathParam(name)).await;
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }
}
