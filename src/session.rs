//! Session state: Redis-backed token records, one-time pending logins, the
//! signed session cookie and read-time expiry.
//!
//! Redis (DB 0) holds the OIDC token set under the bare session UUID, which is
//! also the only value carried by the `session` cookie, and pending login
//! state under the caller's namespaced key (`oidc:<random>`). Keys are written
//! with a TTL, and a record whose `expires_at` has passed is deleted on read,
//! so a replayed cookie cannot outlive the token it points at. Nothing here
//! logs key values, token records or cookie contents.

#[cfg(test)]
use std::collections::HashMap;
#[cfg(test)]
use std::sync::Mutex;
#[cfg(test)]
use std::time::{Duration, Instant};
use std::time::{SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use cookie::{Cookie, SameSite};
use hkdf::Hkdf;
use rand::RngCore;
use redis::AsyncCommands;
use serde::{Deserialize, Serialize};
use sha2::Sha256;

/// Cookie name, kept from the Flask app.
const SESSION_COOKIE_NAME: &str = "session";

/// Signed cookie carrying the random pending-login id back to the browser.
pub const PENDING_COOKIE_NAME: &str = "oidc_pending";

/// Lifetime of a pending login and of the cookie that binds it to a browser.
pub const PENDING_LOGIN_TTL_SECS: u64 = 600;

/// Random bytes behind the session UUID, rendered as 32 lowercase hex chars.
const SESSION_ID_BYTES: usize = 16;

/// `cookie::Key` needs exactly 64 bytes of keying material.
const SIGNING_KEY_BYTES: usize = 64;

/// Domain separation for the HKDF expansion of `FLASK_SECRET`.
const SIGNING_KEY_INFO: &[u8] = b"vsm session cookie signing key v1";

/// The token set stored in Redis under the session UUID.
#[derive(Clone, Serialize, Deserialize)]
pub struct TokenRecord {
    pub access_token: String,
    /// Unix timestamp after which the record is no longer valid.
    pub expires_at: f64,
    pub userinfo: serde_json::Value,
    pub csrf_token: String,
}

/// The one-time state kept between `GET /auth/login` and the callback.
#[derive(Clone, Serialize, Deserialize)]
pub struct PendingLogin {
    pub state: String,
    pub nonce: String,
    pub pkce_verifier: String,
}

/// The session state a web handler needs, shared by the Redis-backed store and
/// the in-memory store used by tests.
#[async_trait]
pub trait SessionStore: Send + Sync {
    /// Returns the token record for `uuid`, or `None` when it is missing,
    /// unreadable, or already past `expires_at` (expired records are removed).
    async fn get(&self, uuid: &str) -> Option<TokenRecord>;

    /// Stores `record` under `uuid` with a `ttl_secs` Redis TTL.
    async fn put(&self, uuid: &str, record: &TokenRecord, ttl_secs: u64) -> anyhow::Result<()>;

    /// Removes `uuid`, if present. Used by logout.
    async fn delete(&self, uuid: &str);

    /// Stores one-time login state under `id`, which is the full key the
    /// caller namespaces as `oidc:<random>`, with a `ttl_secs` TTL.
    async fn put_pending(&self, id: &str, pending: &PendingLogin, ttl_secs: u64);

    /// Removes and returns the pending login stored under `id`; a second call
    /// for the same `id` returns `None`.
    async fn take_pending(&self, id: &str) -> Option<PendingLogin>;
}

/// Session store backed by Redis DB 0.
pub struct RedisStore {
    connection: redis::aio::MultiplexedConnection,
}

impl RedisStore {
    /// Connects to the Redis instance used for session state.
    pub async fn connect(host: &str, port: u16) -> anyhow::Result<Self> {
        let client = redis::Client::open(format!("redis://{host}:{port}/0"))?;
        let connection = client.get_multiplexed_async_connection().await?;

        Ok(Self { connection })
    }
}

#[async_trait]
impl SessionStore for RedisStore {
    async fn get(&self, uuid: &str) -> Option<TokenRecord> {
        let mut connection = self.connection.clone();
        let payload: Option<String> = match connection.get(uuid).await {
            Ok(payload) => payload,
            Err(error) => {
                tracing::warn!(%error, "failed to read session record");
                return None;
            }
        };

        let record = match payload {
            Some(payload) => match serde_json::from_str::<TokenRecord>(&payload) {
                Ok(record) => record,
                Err(error) => {
                    tracing::warn!(%error, "session record is not a valid token record");
                    return None;
                }
            },
            None => return None,
        };

        if is_expired(&record, unix_now()) {
            // The TTL should have removed this already; delete it anyway so a
            // clock skew or an externally written key cannot keep it alive.
            self.delete(uuid).await;
            return None;
        }

        Some(record)
    }

    async fn put(&self, uuid: &str, record: &TokenRecord, ttl_secs: u64) -> anyhow::Result<()> {
        let payload = serde_json::to_string(record)?;
        let mut connection = self.connection.clone();
        // SETEX is Redis' atomic `SET key value EX seconds`; the TTL is the
        // outer bound and `expires_at` remains authoritative at read time.
        connection
            .set_ex::<_, _, ()>(uuid, payload, ttl_secs.max(1))
            .await?;

        Ok(())
    }

    async fn delete(&self, uuid: &str) {
        let mut connection = self.connection.clone();
        if let Err(error) = connection.del::<_, ()>(uuid).await {
            tracing::warn!(%error, "failed to delete session record");
        }
    }

    async fn put_pending(&self, id: &str, pending: &PendingLogin, ttl_secs: u64) {
        let payload = match serde_json::to_string(pending) {
            Ok(payload) => payload,
            Err(error) => {
                tracing::warn!(%error, "failed to encode pending login");
                return;
            }
        };
        let mut connection = self.connection.clone();
        if let Err(error) = connection
            .set_ex::<_, _, ()>(id, payload, ttl_secs.max(1))
            .await
        {
            tracing::warn!(%error, "failed to write pending login");
        }
    }

    async fn take_pending(&self, id: &str) -> Option<PendingLogin> {
        let mut connection = self.connection.clone();
        // GETDEL makes the one-time use atomic, so a replayed callback cannot
        // consume the same pending state twice.
        let payload: Option<String> = match connection.get_del(id).await {
            Ok(payload) => payload,
            Err(error) => {
                tracing::warn!(%error, "failed to read pending login");
                return None;
            }
        };

        let payload = payload?;
        match serde_json::from_str::<PendingLogin>(&payload) {
            Ok(pending) => Some(pending),
            Err(error) => {
                tracing::warn!(%error, "pending login is not a valid record");
                None
            }
        }
    }
}

/// One stored value plus the instant at which it stops being visible.
#[cfg(test)]
struct Entry<T> {
    value: T,
    expires_at: Instant,
}

/// In-memory session store with the same visibility rules as the Redis store.
#[cfg(test)]
#[derive(Default)]
pub struct MemoryStore {
    tokens: Mutex<HashMap<String, Entry<TokenRecord>>>,
    pending: Mutex<HashMap<String, Entry<PendingLogin>>>,
}

#[cfg(test)]
impl MemoryStore {
    pub fn new() -> Self {
        Self::default()
    }
}

#[cfg(test)]
fn memory_insert<T>(map: &Mutex<HashMap<String, Entry<T>>>, key: &str, value: T, ttl_secs: u64) {
    let mut map = map.lock().expect("memory store lock is not poisoned");
    map.insert(
        key.to_owned(),
        Entry {
            value,
            expires_at: Instant::now() + Duration::from_secs(ttl_secs.max(1)),
        },
    );
}

#[cfg(test)]
fn memory_load<T: Clone>(map: &Mutex<HashMap<String, Entry<T>>>, key: &str) -> Option<T> {
    let mut map = map.lock().expect("memory store lock is not poisoned");
    let expired = match map.get(key) {
        Some(entry) => entry.expires_at <= Instant::now(),
        None => return None,
    };

    if expired {
        map.remove(key);
        return None;
    }

    map.get(key).map(|entry| entry.value.clone())
}

#[cfg(test)]
fn memory_remove<T>(map: &Mutex<HashMap<String, Entry<T>>>, key: &str) {
    map.lock()
        .expect("memory store lock is not poisoned")
        .remove(key);
}

#[cfg(test)]
#[async_trait]
impl SessionStore for MemoryStore {
    async fn get(&self, uuid: &str) -> Option<TokenRecord> {
        let record = memory_load(&self.tokens, uuid)?;

        if is_expired(&record, unix_now()) {
            memory_remove(&self.tokens, uuid);
            return None;
        }

        Some(record)
    }

    async fn put(&self, uuid: &str, record: &TokenRecord, ttl_secs: u64) -> anyhow::Result<()> {
        memory_insert(&self.tokens, uuid, record.clone(), ttl_secs);
        Ok(())
    }

    async fn delete(&self, uuid: &str) {
        memory_remove(&self.tokens, uuid);
    }

    async fn put_pending(&self, id: &str, pending: &PendingLogin, ttl_secs: u64) {
        memory_insert(&self.pending, id, pending.clone(), ttl_secs);
    }

    async fn take_pending(&self, id: &str) -> Option<PendingLogin> {
        let pending = memory_load(&self.pending, id)?;
        memory_remove(&self.pending, id);
        Some(pending)
    }
}

/// Generates a session UUID: 32 lowercase hex characters, like `uuid4().hex`.
pub fn new_uuid() -> String {
    let mut bytes = [0u8; SESSION_ID_BYTES];
    rand::rng().fill_bytes(&mut bytes);
    hex::encode(bytes)
}

/// Whether `record` has reached `now`; validity is strict (`expires_at > now`).
pub fn is_expired(record: &TokenRecord, now: f64) -> bool {
    record.expires_at <= now
}

/// Derives the 64-byte `cookie::Key` used by the signed cookie jar from
/// `FLASK_SECRET`, so every replica sharing the secret accepts the same
/// cookies. Changing `SIGNING_KEY_INFO` invalidates existing cookies.
pub fn signing_key(secret: &str) -> cookie::Key {
    let hkdf = Hkdf::<Sha256>::new(None, secret.as_bytes());
    let mut key_material = [0u8; SIGNING_KEY_BYTES];
    hkdf.expand(SIGNING_KEY_INFO, &mut key_material)
        .expect("HKDF-SHA256 expands any length up to 8160 bytes");

    cookie::Key::from(&key_material)
}

/// Builds the session cookie holding only the opaque UUID.
///
/// `HttpOnly`, `SameSite=Strict` and `Path=/` always apply; `Secure` and
/// `Domain=HOSTNAME` are added outside development, where the app is served
/// over HTTPS on the public hostname.
pub fn build_session_cookie(development: bool, hostname: &str, value: &str) -> Cookie<'static> {
    let mut builder = Cookie::build((SESSION_COOKIE_NAME, value.to_owned()))
        .http_only(true)
        .same_site(SameSite::Strict)
        .path("/")
        .secure(!development);

    if !development {
        builder = builder.domain(hostname.to_owned());
    }

    builder.build()
}

/// Builds the short-lived signed cookie that binds a pending OIDC login to the
/// browser that started it. Its `Max-Age` matches the Redis `oidc:<random>`
/// TTL, and all other attributes mirror the session cookie.
pub fn build_pending_cookie(development: bool, hostname: &str, value: &str) -> Cookie<'static> {
    let mut builder = Cookie::build((PENDING_COOKIE_NAME, value.to_owned()))
        .http_only(true)
        .same_site(SameSite::Strict)
        .path("/")
        .secure(!development)
        .max_age(time::Duration::seconds(PENDING_LOGIN_TTL_SECS as i64));

    if !development {
        builder = builder.domain(hostname.to_owned());
    }

    builder.build()
}

/// Current Unix time as fractional seconds, matching the OIDC `expires_at`.
fn unix_now() -> f64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock is before the unix epoch")
        .as_secs_f64()
}

#[cfg(test)]
mod tests {
    use super::*;

    use axum_extra::extract::cookie::SignedCookieJar;
    use cookie::SameSite;

    const HOSTNAME: &str = "vsm.local.kronus.network";
    const EXPIRES_AT: f64 = 1_700_000_000.0;

    fn token_record(expires_at: f64) -> TokenRecord {
        TokenRecord {
            access_token: "access-token-value".to_owned(),
            expires_at,
            userinfo: serde_json::json!({
                "preferred_username": "testuser",
                "groups": ["/example"],
            }),
            csrf_token: "csrf-token-value".to_owned(),
        }
    }

    fn pending_login() -> PendingLogin {
        PendingLogin {
            state: "state-value".to_owned(),
            nonce: "nonce-value".to_owned(),
            pkce_verifier: "verifier-value".to_owned(),
        }
    }

    #[test]
    fn cookie_has_hardened_attributes_in_production() {
        let cookie = build_session_cookie(false, HOSTNAME, "abc");

        assert_eq!(cookie.name(), "session");
        assert_eq!(cookie.value(), "abc");
        assert_eq!(cookie.http_only(), Some(true));
        assert_eq!(cookie.same_site(), Some(SameSite::Strict));
        assert_eq!(cookie.path(), Some("/"));
        assert_eq!(cookie.secure(), Some(true));
        assert_eq!(cookie.domain(), Some(HOSTNAME));
    }

    #[test]
    fn cookie_is_host_only_in_development() {
        let cookie = build_session_cookie(true, HOSTNAME, "abc");

        assert_eq!(cookie.name(), "session");
        assert_eq!(cookie.value(), "abc");
        assert_eq!(cookie.http_only(), Some(true));
        assert_eq!(cookie.same_site(), Some(SameSite::Strict));
        assert_eq!(cookie.path(), Some("/"));
        assert_eq!(cookie.secure(), Some(false));
        assert_eq!(cookie.domain(), None);
    }

    #[test]
    fn pending_cookie_is_hardened_and_short_lived() {
        let cookie = build_pending_cookie(false, HOSTNAME, "state-value");

        assert_eq!(cookie.name(), PENDING_COOKIE_NAME);
        assert_eq!(cookie.value(), "state-value");
        assert_eq!(cookie.http_only(), Some(true));
        assert_eq!(cookie.same_site(), Some(SameSite::Strict));
        assert_eq!(cookie.path(), Some("/"));
        assert_eq!(cookie.secure(), Some(true));
        assert_eq!(cookie.domain(), Some(HOSTNAME));
        assert_eq!(
            cookie.max_age(),
            Some(time::Duration::seconds(PENDING_LOGIN_TTL_SECS as i64))
        );

        let development_cookie = build_pending_cookie(true, HOSTNAME, "state-value");
        assert_eq!(development_cookie.secure(), Some(false));
        assert_eq!(development_cookie.domain(), None);
    }

    #[test]
    fn pending_cookie_is_accepted_by_signed_cookie_jar() {
        let jar = SignedCookieJar::new(signing_key("itsasecret"));
        let jar = jar.add(build_pending_cookie(true, HOSTNAME, "state-value"));

        assert_eq!(
            jar.get(PENDING_COOKIE_NAME)
                .map(|cookie| cookie.value().to_owned()),
            Some("state-value".to_owned())
        );
    }

    #[test]
    fn expiry_is_strict() {
        let record = token_record(EXPIRES_AT);

        assert!(!is_expired(&record, EXPIRES_AT - 0.01));
        assert!(is_expired(&record, EXPIRES_AT));
        assert!(is_expired(&record, EXPIRES_AT + 0.01));
    }

    /// Guards the contract the router depends on: the derived key must be the
    /// same `cookie` version `axum-extra`'s signed jar signs with.
    #[test]
    fn signing_key_is_accepted_by_signed_cookie_jar() {
        let jar = SignedCookieJar::new(signing_key("itsasecret"));
        let jar = jar.add(build_session_cookie(true, HOSTNAME, "abc"));

        assert_eq!(
            jar.get(SESSION_COOKIE_NAME)
                .map(|cookie| cookie.value().to_owned()),
            Some("abc".to_owned())
        );
    }

    #[test]
    fn new_uuid_is_32_lowercase_hex() {
        let uuid = new_uuid();

        assert_eq!(uuid.len(), 32);
        assert!(
            uuid.chars()
                .all(|c| c.is_ascii_digit() || ('a'..='f').contains(&c)),
            "not lowercase hex: {uuid}"
        );
        assert_ne!(new_uuid(), uuid);
    }

    #[tokio::test]
    async fn memory_store_roundtrip_and_pending_is_one_shot() {
        let store = MemoryStore::new();
        assert!(store.get("missing").await.is_none());

        let record = token_record(unix_now() + 3600.0);
        store
            .put("uuid", &record, 60)
            .await
            .expect("memory store write succeeds");

        let loaded = store.get("uuid").await.expect("record is stored");
        assert_eq!(loaded.access_token, record.access_token);
        assert_eq!(loaded.expires_at, record.expires_at);
        assert_eq!(loaded.userinfo, record.userinfo);
        assert_eq!(loaded.csrf_token, record.csrf_token);

        store.delete("uuid").await;
        assert!(store.get("uuid").await.is_none());

        let pending = pending_login();
        store.put_pending("oidc:login", &pending, 600).await;

        let taken = store
            .take_pending("oidc:login")
            .await
            .expect("pending login is stored");
        assert_eq!(taken.state, pending.state);
        assert_eq!(taken.nonce, pending.nonce);
        assert_eq!(taken.pkce_verifier, pending.pkce_verifier);
        assert!(store.take_pending("oidc:login").await.is_none());
    }

    #[tokio::test]
    async fn memory_store_hides_and_drops_expired_token() {
        let store = MemoryStore::new();
        store
            .put("expired", &token_record(unix_now() - 1.0), 60)
            .await
            .expect("memory store write succeeds");

        assert!(store.get("expired").await.is_none());
        assert!(
            store
                .tokens
                .lock()
                .expect("token map is not poisoned")
                .is_empty(),
            "an expired record must be deleted from the store"
        );
    }
}
