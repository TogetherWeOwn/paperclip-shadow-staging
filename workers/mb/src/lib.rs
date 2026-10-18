//! NNTune v2 MusicBrainz mirror read API.
//!
//! Routes (all JSON, all read-only):
//! - `GET /v1/mb/artist/:mbid` — artist lookup by MBID.
//! - `GET /v1/mb/release/:mbid` — release lookup by MBID.
//! - `GET /v1/mb/recording/:mbid` — recording lookup by MBID.
//! - `GET /v1/mb/search?q=&type=artist|release|recording` — trigram search.
//!
//! Data comes from PlanetScale Postgres (`nntunev2-mb`) via the Hyperdrive
//! binding `MB_DB`; successful responses are cached in KV (`MB_CACHE`) and
//! at the edge via the Cache API / `Cache-Control`. Failures (400/404/500)
//! are `no-store` and are never written to either cache. Interactive reads
//! never call musicbrainz.org. Cover art bytes live in the `nntunev2-art`
//! R2 bucket; this worker serves cacheable URLs, never secrets. See
//! `README.md` and `migrations/0001_mb_mirror.sql`.
//!
//! Structure: [`handle_lookup`] / [`handle_search`] are the testable core
//! over the [`MbRepo`] and [`SuccessCache`] traits. The HTTP layer at the bottom wires them to a per-request
//! `tokio-postgres` client over the Hyperdrive socket and to the KV binding.

use serde::Serialize;

/// Cache TTLs: lookups are immutable-ish (long TTL), search is short TTL.
/// They apply to successful responses only; failures serve `no-store`.
const LOOKUP_CACHE_TTL_S: u32 = 86_400;
const SEARCH_CACHE_TTL_S: u32 = 300;

/// Search returns at most this many hits (SQL `LIMIT` and a defensive
/// truncation in [`handle_search`]).
const SEARCH_LIMIT: usize = 25;

/// Upper bound on `q` length, in chars. Bounds trigram work and KV keys.
const MAX_QUERY_CHARS: usize = 100;

/// Hyperdrive / KV binding names: must match `wrangler.toml.example`.
const MB_DB_BINDING: &str = "MB_DB";
const MB_CACHE_BINDING: &str = "MB_CACHE";

/// Entity selector. The only route into SQL: each variant maps to a
/// static, parameterized statement (see [`lookup_sql`]/[`search_sql`]), so
/// no user input ever reaches a table or column name.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kind {
    Artist,
    Release,
    Recording,
}

impl Kind {
    fn parse(raw: Option<String>) -> Option<Kind> {
        match raw.as_deref() {
            Some("artist") => Some(Kind::Artist),
            Some("release") => Some(Kind::Release),
            Some("recording") => Some(Kind::Recording),
            _ => None,
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            Kind::Artist => "artist",
            Kind::Release => "release",
            Kind::Recording => "recording",
        }
    }
}

/// Lookup statement per kind. `$1` is the validated MBID, cast in SQL so
/// the driver only ever binds a string. The parameter is typed `text`
/// (`$1::text::uuid`): a bare `$1::uuid` would make Postgres infer the
/// parameter as `uuid`, which tokio-postgres cannot bind from `&str`
/// ("error serializing parameter 0", every lookup 500s). Casting through
/// `text` keeps the `&str` binding working while the final `::uuid` cast
/// still hits the primary-key index. Selected ids are cast to `text`
/// to keep row decoding free of uuid/timestamp types.
fn lookup_sql(kind: Kind) -> &'static str {
    match kind {
        Kind::Artist => {
            "SELECT mbid::text AS mbid, name, sort_name, type, country::text AS country \
             FROM mb_artist WHERE mbid = $1::text::uuid"
        }
        Kind::Release => {
            "SELECT mbid::text AS mbid, artist_mbid::text AS artist_mbid, title, \
             release_type, year, caa_url \
             FROM mb_release WHERE mbid = $1::text::uuid"
        }
        Kind::Recording => {
            "SELECT mbid::text AS mbid, release_mbid::text AS release_mbid, title, \
             track_no, duration_ms \
             FROM mb_recording WHERE mbid = $1::text::uuid"
        }
    }
}

/// Trigram search statement per kind. `$1` is the normalized query; `%` is
/// the `pg_trgm` similarity predicate (GIN index in migration 0001),
/// ordered by score with a deterministic tiebreak and a hard limit.
fn search_sql(kind: Kind) -> &'static str {
    match kind {
        Kind::Artist => {
            "SELECT mbid::text AS mbid, name AS label, similarity(name, $1) AS score \
             FROM mb_artist WHERE name % $1 \
             ORDER BY score DESC, label ASC, mbid ASC LIMIT 25"
        }
        Kind::Release => {
            "SELECT mbid::text AS mbid, title AS label, similarity(title, $1) AS score \
             FROM mb_release WHERE title % $1 \
             ORDER BY score DESC, label ASC, mbid ASC LIMIT 25"
        }
        Kind::Recording => {
            "SELECT mbid::text AS mbid, title AS label, similarity(title, $1) AS score \
             FROM mb_recording WHERE title % $1 \
             ORDER BY score DESC, label ASC, mbid ASC LIMIT 25"
        }
    }
}

/// Validate an MBID string (UUID shape `8-4-4-4-12` hex). Keeps malformed
/// `:mbid` values out of Hyperdrive SQL and out of cache keys.
fn is_valid_mbid(raw: &str) -> bool {
    let bytes = raw.as_bytes();
    if bytes.len() != 36 {
        return false;
    }
    for (i, &byte) in bytes.iter().enumerate() {
        match i {
            8 | 13 | 18 | 23 => {
                if byte != b'-' {
                    return false;
                }
            }
            _ => {
                if !byte.is_ascii_hexdigit() {
                    return false;
                }
            }
        }
    }
    true
}

/// Normalize a search query for SQL and cache keys: trimmed, lowercased,
/// interior whitespace collapsed. Case/whitespace variants of a query
/// therefore share one SQL shape and one cache entry.
fn normalize_query(raw: &str) -> String {
    raw.split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .to_lowercase()
}

/// Stable KV key for a lookup success: `mb:lookup:<kind>:<mbid>`.
fn lookup_cache_key(kind: Kind, mbid: &str) -> String {
    format!("mb:lookup:{}:{}", kind.as_str(), mbid.to_lowercase())
}

/// Stable KV key for a search success: `mb:search:<kind>:<normalized q>`.
fn search_cache_key(kind: Kind, raw_q: &str) -> String {
    format!("mb:search:{}:{}", kind.as_str(), normalize_query(raw_q))
}

/// Success-path `Cache-Control` value for the given TTL.
fn cache_control(ttl_s: u32) -> String {
    format!("public, max-age={ttl_s}")
}

// --- JSON entities --------------------------------------------------------

#[derive(Debug, Clone, Serialize)]
struct Artist {
    mbid: String,
    name: String,
    sort_name: String,
    #[serde(rename = "type")]
    artist_type: Option<String>,
    country: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
struct Release {
    mbid: String,
    artist_mbid: Option<String>,
    title: String,
    release_type: Option<String>,
    year: Option<i16>,
    caa_url: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
struct Recording {
    mbid: String,
    release_mbid: Option<String>,
    title: String,
    track_no: Option<i16>,
    duration_ms: Option<i32>,
}

/// One lookup row, tagged by [`Kind`] again at serialization time so the
/// JSON carries `"kind"` alongside the flat entity fields.
#[derive(Debug, Clone)]
enum Entity {
    Artist(Artist),
    Release(Release),
    Recording(Recording),
}

impl Entity {
    fn to_json(&self, kind: Kind) -> serde_json::Value {
        let mut value = match self {
            Entity::Artist(a) => serde_json::to_value(a),
            Entity::Release(r) => serde_json::to_value(r),
            Entity::Recording(r) => serde_json::to_value(r),
        }
        .unwrap_or(serde_json::Value::Null);
        if let serde_json::Value::Object(map) = &mut value {
            map.insert(
                "kind".to_string(),
                serde_json::Value::String(kind.as_str().to_string()),
            );
        }
        value
    }
}

#[derive(Debug, Clone)]
struct SearchHit {
    mbid: String,
    label: String,
    score: f32,
}

impl SearchHit {
    fn to_json(&self, kind: Kind) -> serde_json::Value {
        // Artists answer `name`, releases/recordings answer `title`,
        // matching the lookup field names for the same row.
        let label_key = match kind {
            Kind::Artist => "name",
            Kind::Release | Kind::Recording => "title",
        };
        serde_json::json!({
            "mbid": self.mbid,
            label_key: self.label,
            "score": self.score,
        })
    }
}

// --- Core handler traits and logic ----------------------------------------

/// Opaque repository failure. Carries no detail on purpose: handler
/// responses must never leak DB/driver internals to clients.
#[derive(Debug)]
struct RepoError;

/// Read-only mirror repository over the `MB_DB` Hyperdrive binding.
trait MbRepo {
    async fn lookup(&self, kind: Kind, mbid: &str) -> Result<Option<Entity>, RepoError>;
    async fn search(&self, kind: Kind, normalized_q: &str) -> Result<Vec<SearchHit>, RepoError>;
}

/// Success-only response cache (KV in production). Deliberately
/// infallible: a failed `get` is a miss and a failed `put` is dropped,
/// so cache problems degrade to plain DB reads instead of errors.
trait SuccessCache {
    async fn get(&self, key: &str) -> Option<String>;
    async fn put(&self, key: &str, body: &str, ttl_s: u32);
}

/// Transport-neutral handler result. `cache_ttl` is `Some` exactly for
/// cacheable successes (status 200); the HTTP layer renders `Some(ttl)`
/// as `Cache-Control: public, max-age=<ttl>` and `None` as `no-store`.
#[derive(Debug, PartialEq, Eq)]
struct ApiResponse {
    status: u16,
    body: String,
    cache_ttl: Option<u32>,
}

fn error_response(message: &str, status: u16) -> ApiResponse {
    let body = serde_json::json!({ "error": message }).to_string();
    ApiResponse {
        status,
        body,
        cache_ttl: None,
    }
}

fn success_response(body: String, ttl_s: u32) -> ApiResponse {
    ApiResponse {
        status: 200,
        body,
        cache_ttl: Some(ttl_s),
    }
}

/// Lookup core: validate → KV → DB. Only a found row is written to the
/// cache; missing rows (404) and read failures (500) never are.
async fn handle_lookup<R: MbRepo, C: SuccessCache>(
    repo: &R,
    cache: &C,
    kind: Kind,
    mbid: &str,
) -> ApiResponse {
    if !is_valid_mbid(mbid) {
        return error_response("invalid mbid (must be UUID)", 400);
    }
    let key = lookup_cache_key(kind, mbid);
    if let Some(body) = cache.get(&key).await {
        return success_response(body, LOOKUP_CACHE_TTL_S);
    }
    match repo.lookup(kind, &mbid.to_lowercase()).await {
        Ok(Some(entity)) => {
            let body = entity.to_json(kind).to_string();
            cache.put(&key, &body, LOOKUP_CACHE_TTL_S).await;
            success_response(body, LOOKUP_CACHE_TTL_S)
        }
        Ok(None) => error_response("not found", 404),
        Err(_) => error_response("internal error", 500),
    }
}

/// Search core: validate → KV → DB. A successful query (including an
/// empty result list) is cached for [`SEARCH_CACHE_TTL_S`]; a read
/// failure is a 500, never an empty success, and is never cached.
async fn handle_search<R: MbRepo, C: SuccessCache>(
    repo: &R,
    cache: &C,
    raw_kind: Option<String>,
    raw_q: &str,
) -> ApiResponse {
    let q = raw_q.trim();
    let q_chars = q.chars().count();
    if q_chars < 2 {
        return error_response("query too short (min 2 chars)", 400);
    }
    if q_chars > MAX_QUERY_CHARS {
        return error_response("query too long (max 100 chars)", 400);
    }
    if q.chars().any(char::is_control) {
        return error_response("query contains control characters", 400);
    }
    let kind = match Kind::parse(raw_kind) {
        Some(kind) => kind,
        None => return error_response("type must be one of artist|release|recording", 400),
    };
    let key = search_cache_key(kind, q);
    if let Some(body) = cache.get(&key).await {
        return success_response(body, SEARCH_CACHE_TTL_S);
    }
    // The body echoes the normalized query, not the raw one: case and
    // whitespace variants share this cache entry, so the first writer's
    // raw casing must not leak into later variants' responses.
    let normalized_q = normalize_query(q);
    match repo.search(kind, &normalized_q).await {
        Ok(mut hits) => {
            hits.truncate(SEARCH_LIMIT);
            let results: Vec<serde_json::Value> =
                hits.iter().map(|hit| hit.to_json(kind)).collect();
            let body = serde_json::json!({
                "q": normalized_q,
                "type": kind.as_str(),
                "results": results,
            })
            .to_string();
            cache.put(&key, &body, SEARCH_CACHE_TTL_S).await;
            success_response(body, SEARCH_CACHE_TTL_S)
        }
        Err(_) => error_response("internal error", 500),
    }
}

// --- HTTP layer -------------------------------------------------------------

mod http_layer {
    use super::*;
    use worker::kv::KvStore;
    use worker::{
        console_log, Cache, Env, Headers, Request, Response, ResponseBody, Result as WorkerResult,
        RouteContext,
    };

    /// KV-backed [`SuccessCache`]; degrades to no-op when the binding is
    /// absent so a misconfigured cache never blocks DB reads.
    enum EdgeCache {
        Kv(KvStore),
        Noop,
    }

    impl EdgeCache {
        fn from_env(env: &Env) -> Self {
            match env.kv(MB_CACHE_BINDING) {
                Ok(kv) => EdgeCache::Kv(kv),
                Err(_) => EdgeCache::Noop,
            }
        }
    }

    impl SuccessCache for EdgeCache {
        async fn get(&self, key: &str) -> Option<String> {
            match self {
                EdgeCache::Kv(kv) => kv.get(key).text().await.ok().flatten(),
                EdgeCache::Noop => None,
            }
        }

        async fn put(&self, key: &str, body: &str, ttl_s: u32) {
            if let EdgeCache::Kv(kv) = self {
                // KV expiration_ttl minimum is 60s; both TTLs exceed it.
                let _ = match kv.put(key, body) {
                    Ok(builder) => builder.expiration_ttl(u64::from(ttl_s)).execute().await,
                    Err(_) => return,
                };
            }
        }
    }

    /// [`MbRepo`] over Hyperdrive. Lazy: the Postgres connection is opened
    /// per query (Hyperdrive pools underneath), so a KV/edge cache hit
    /// never connects.
    struct PgRepo {
        env: Env,
    }

    impl PgRepo {
        async fn connect(&self) -> Result<tokio_postgres::Client, RepoError> {
            let hyperdrive = self.env.hyperdrive(MB_DB_BINDING).map_err(|_| RepoError)?;
            let socket = worker::Socket::builder()
                .secure_transport(worker::SecureTransport::StartTls)
                .connect(hyperdrive.host(), hyperdrive.port())
                .map_err(|_| RepoError)?;
            let config: tokio_postgres::Config = hyperdrive
                .connection_string()
                .parse()
                .map_err(|_| RepoError)?;
            let (client, connection) = config
                .connect_raw(socket, worker::postgres_tls::PassthroughTls)
                .await
                .map_err(|_| RepoError)?;
            wasm_bindgen_futures::spawn_local(async move {
                // Detail stays out of logs: driver errors can carry
                // host/role strings that are not needed to triage.
                if connection.await.is_err() {
                    console_log!("mb db connection error");
                }
            });
            Ok(client)
        }
    }

    impl MbRepo for PgRepo {
        async fn lookup(&self, kind: Kind, mbid: &str) -> Result<Option<Entity>, RepoError> {
            let client = self.connect().await?;
            let row = client
                .query_opt(lookup_sql(kind), &[&mbid])
                .await
                .map_err(|_| RepoError)?;
            row.map(|row| entity_from_row(kind, &row)).transpose()
        }

        async fn search(
            &self,
            kind: Kind,
            normalized_q: &str,
        ) -> Result<Vec<SearchHit>, RepoError> {
            let client = self.connect().await?;
            let rows = client
                .query(search_sql(kind), &[&normalized_q])
                .await
                .map_err(|_| RepoError)?;
            rows.iter().map(hit_from_row).collect()
        }
    }

    fn entity_from_row(kind: Kind, row: &tokio_postgres::Row) -> Result<Entity, RepoError> {
        // Column names/types are fixed by `lookup_sql`; a mismatch is a
        // server-side schema bug, reported as an opaque read failure.
        let entity = match kind {
            Kind::Artist => Entity::Artist(Artist {
                mbid: row.try_get("mbid").map_err(|_| RepoError)?,
                name: row.try_get("name").map_err(|_| RepoError)?,
                sort_name: row.try_get("sort_name").map_err(|_| RepoError)?,
                artist_type: row.try_get("type").map_err(|_| RepoError)?,
                country: row.try_get("country").map_err(|_| RepoError)?,
            }),
            Kind::Release => Entity::Release(Release {
                mbid: row.try_get("mbid").map_err(|_| RepoError)?,
                artist_mbid: row.try_get("artist_mbid").map_err(|_| RepoError)?,
                title: row.try_get("title").map_err(|_| RepoError)?,
                release_type: row.try_get("release_type").map_err(|_| RepoError)?,
                year: row.try_get("year").map_err(|_| RepoError)?,
                caa_url: row.try_get("caa_url").map_err(|_| RepoError)?,
            }),
            Kind::Recording => Entity::Recording(Recording {
                mbid: row.try_get("mbid").map_err(|_| RepoError)?,
                release_mbid: row.try_get("release_mbid").map_err(|_| RepoError)?,
                title: row.try_get("title").map_err(|_| RepoError)?,
                track_no: row.try_get("track_no").map_err(|_| RepoError)?,
                duration_ms: row.try_get("duration_ms").map_err(|_| RepoError)?,
            }),
        };
        Ok(entity)
    }

    fn hit_from_row(row: &tokio_postgres::Row) -> Result<SearchHit, RepoError> {
        Ok(SearchHit {
            mbid: row.try_get("mbid").map_err(|_| RepoError)?,
            label: row.try_get("label").map_err(|_| RepoError)?,
            score: row.try_get("score").map_err(|_| RepoError)?,
        })
    }

    fn json_headers(cache_ttl: Option<u32>) -> WorkerResult<Headers> {
        let mut headers = Headers::new();
        headers.append("content-type", "application/json; charset=utf-8")?;
        match cache_ttl {
            Some(ttl) => headers.append("cache-control", &cache_control(ttl))?,
            None => headers.append("cache-control", "no-store")?,
        }
        Ok(headers)
    }

    fn render(api: &ApiResponse) -> WorkerResult<Response> {
        Ok(
            Response::from_body(ResponseBody::Body(api.body.clone().into_bytes()))?
                .with_status(api.status)
                .with_headers(json_headers(api.cache_ttl)?),
        )
    }

    /// Render a core result and, for successes only, store a copy in
    /// the edge Cache API keyed by the request URL.
    async fn serve(req_url: String, api: ApiResponse) -> WorkerResult<Response> {
        let response = render(&api)?;
        if api.cache_ttl.is_some() {
            let edge_copy = render(&api)?;
            // Best-effort: an edge-cache failure must not fail the read.
            let _ = Cache::default().put(req_url, edge_copy).await;
        }
        Ok(response)
    }

    async fn edge_hit(req: &Request) -> Option<Response> {
        let url = req.url().ok()?.to_string();
        Cache::default().get(url, false).await.ok().flatten()
    }

    pub async fn lookup_route(
        kind: Kind,
        req: &Request,
        ctx: &RouteContext<()>,
    ) -> WorkerResult<Response> {
        if let Some(hit) = edge_hit(req).await {
            return Ok(hit);
        }
        let mbid = ctx.param("mbid").map(String::as_str).unwrap_or("");
        let repo = PgRepo {
            env: ctx.env.clone(),
        };
        let cache = EdgeCache::from_env(&ctx.env);
        let api = handle_lookup(&repo, &cache, kind, mbid).await;
        serve(req.url()?.to_string(), api).await
    }

    pub async fn search_route(req: &Request, ctx: &RouteContext<()>) -> WorkerResult<Response> {
        if let Some(hit) = edge_hit(req).await {
            return Ok(hit);
        }
        let url = req.url()?;
        let query: std::collections::HashMap<String, String> =
            url.query_pairs().into_owned().collect();
        let repo = PgRepo {
            env: ctx.env.clone(),
        };
        let cache = EdgeCache::from_env(&ctx.env);
        let api = handle_search(
            &repo,
            &cache,
            query.get("type").cloned(),
            query.get("q").map(String::as_str).unwrap_or(""),
        )
        .await;
        serve(url.to_string(), api).await
    }

    pub async fn not_found() -> WorkerResult<Response> {
        render(&error_response("not found", 404))
    }
}

#[worker::event(fetch)]
pub async fn main(
    req: worker::Request,
    env: worker::Env,
    _ctx: worker::Context,
) -> worker::Result<worker::Response> {
    worker::Router::new()
        .get_async("/v1/mb/artist/:mbid", |req, ctx| async move {
            http_layer::lookup_route(Kind::Artist, &req, &ctx).await
        })
        .get_async("/v1/mb/release/:mbid", |req, ctx| async move {
            http_layer::lookup_route(Kind::Release, &req, &ctx).await
        })
        .get_async("/v1/mb/recording/:mbid", |req, ctx| async move {
            http_layer::lookup_route(Kind::Recording, &req, &ctx).await
        })
        .get_async("/v1/mb/search", |req, ctx| async move {
            http_layer::search_route(&req, &ctx).await
        })
        .or_else_any_method_async("/*catchall", |_, _| async { http_layer::not_found().await })
        .run(req, env)
        .await
}
#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::future::Future;
    use std::task::{Context, Poll, Waker};

    /// Minimal executor: the fakes below complete on first poll.
    fn block_on<F: Future>(future: F) -> F::Output {
        let waker = Waker::noop();
        let mut cx = Context::from_waker(waker);
        let mut future = Box::pin(future);
        for _ in 0..100 {
            if let Poll::Ready(value) = future.as_mut().poll(&mut cx) {
                return value;
            }
        }
        panic!("test future did not complete");
    }

    const MBID: &str = "123e4567-e89b-12d3-a456-426614174000";

    #[derive(Default)]
    struct FakeRepo {
        lookup_calls: RefCell<u32>,
        search_calls: RefCell<u32>,
        last_search_q: RefCell<String>,
        entity: Option<Entity>,
        hits: Vec<SearchHit>,
        fail: bool,
    }

    impl MbRepo for FakeRepo {
        async fn lookup(&self, _kind: Kind, _mbid: &str) -> Result<Option<Entity>, RepoError> {
            *self.lookup_calls.borrow_mut() += 1;
            if self.fail {
                return Err(RepoError);
            }
            Ok(self.entity.clone())
        }

        async fn search(&self, _kind: Kind, q: &str) -> Result<Vec<SearchHit>, RepoError> {
            *self.search_calls.borrow_mut() += 1;
            *self.last_search_q.borrow_mut() = q.to_string();
            if self.fail {
                return Err(RepoError);
            }
            Ok(self.hits.clone())
        }
    }

    #[derive(Default)]
    struct FakeCache {
        stored: RefCell<std::collections::HashMap<String, String>>,
        puts: RefCell<Vec<(String, u32)>>,
        gets: RefCell<u32>,
    }

    impl SuccessCache for FakeCache {
        async fn get(&self, key: &str) -> Option<String> {
            *self.gets.borrow_mut() += 1;
            self.stored.borrow().get(key).cloned()
        }

        async fn put(&self, key: &str, body: &str, ttl_s: u32) {
            self.puts.borrow_mut().push((key.to_string(), ttl_s));
            self.stored
                .borrow_mut()
                .insert(key.to_string(), body.to_string());
        }
    }

    fn artist() -> Entity {
        Entity::Artist(Artist {
            mbid: MBID.to_string(),
            name: "Test Artist".to_string(),
            sort_name: "Artist, Test".to_string(),
            artist_type: Some("Group".to_string()),
            country: Some("US".to_string()),
        })
    }

    fn hit(n: u32) -> SearchHit {
        SearchHit {
            mbid: format!("123e4567-e89b-12d3-a456-42661417{n:04}"),
            label: format!("Hit {n}"),
            score: 1.0 - (n as f32 / 100.0),
        }
    }

    #[test]
    fn lookup_sql_is_parameterized_per_kind() {
        for (kind, table) in [
            (Kind::Artist, "mb_artist"),
            (Kind::Release, "mb_release"),
            (Kind::Recording, "mb_recording"),
        ] {
            let sql = lookup_sql(kind);
            assert!(sql.contains(table), "{sql}");
            // `$1` must stay `text`-typed so the `&str` bind works
            // (bare `$1::uuid` makes Postgres infer a uuid parameter,
            // which tokio-postgres refuses from `&str`: every lookup 500s).
            assert!(sql.contains("mbid = $1::text::uuid"), "{sql}");
            assert!(!sql.contains("= $1::uuid"), "{sql}");
            assert!(sql.contains("mbid::text AS mbid"), "{sql}");
        }
    }

    #[test]
    fn search_sql_is_trigram_bounded_and_ordered() {
        for kind in [Kind::Artist, Kind::Release, Kind::Recording] {
            let sql = search_sql(kind);
            assert!(sql.contains("% $1"), "{sql}");
            assert!(sql.contains("similarity("), "{sql}");
            assert!(sql.contains("ORDER BY score DESC"), "{sql}");
            assert!(sql.contains("LIMIT 25"), "{sql}");
        }
        assert_eq!(SEARCH_LIMIT, 25);
    }

    #[test]
    fn cache_keys_are_stable_and_normalized() {
        assert_eq!(
            lookup_cache_key(Kind::Artist, "123E4567-E89B-12D3-A456-426614174000"),
            format!("mb:lookup:artist:{MBID}")
        );
        assert_eq!(
            search_cache_key(Kind::Release, "  Blue   Monday "),
            "mb:search:release:blue monday"
        );
        assert_eq!(normalize_query("  Blue   Monday "), "blue monday");
    }

    #[test]
    fn lookup_cache_hit_skips_repo() {
        let cache = FakeCache::default();
        cache.stored.borrow_mut().insert(
            lookup_cache_key(Kind::Artist, MBID),
            r#"{"kind":"artist","cached":true}"#.to_string(),
        );
        let repo = FakeRepo::default();
        let resp = block_on(handle_lookup(&repo, &cache, Kind::Artist, MBID));
        assert_eq!(resp.status, 200);
        assert_eq!(resp.cache_ttl, Some(LOOKUP_CACHE_TTL_S));
        assert!(resp.body.contains("cached"));
        assert_eq!(*repo.lookup_calls.borrow(), 0);
    }

    #[test]
    fn lookup_found_returns_entity_and_caches_success() {
        let repo = FakeRepo {
            entity: Some(artist()),
            ..Default::default()
        };
        let cache = FakeCache::default();
        let resp = block_on(handle_lookup(&repo, &cache, Kind::Artist, MBID));
        assert_eq!(resp.status, 200);
        assert_eq!(resp.cache_ttl, Some(86_400));
        let body: serde_json::Value = serde_json::from_str(&resp.body).unwrap();
        assert_eq!(body["kind"], "artist");
        assert_eq!(body["mbid"], MBID);
        assert_eq!(body["name"], "Test Artist");
        assert_eq!(body["sort_name"], "Artist, Test");
        let puts = cache.puts.borrow();
        assert_eq!(puts.len(), 1);
        assert_eq!(puts[0].1, 86_400);
    }

    #[test]
    fn lookup_release_json_carries_caa_url() {
        let repo = FakeRepo {
            entity: Some(Entity::Release(Release {
                mbid: MBID.to_string(),
                artist_mbid: None,
                title: "Blue Monday".to_string(),
                release_type: Some("Single".to_string()),
                year: Some(1983),
                caa_url: None,
            })),
            ..Default::default()
        };
        let cache = FakeCache::default();
        let resp = block_on(handle_lookup(&repo, &cache, Kind::Release, MBID));
        assert_eq!(resp.status, 200);
        let body: serde_json::Value = serde_json::from_str(&resp.body).unwrap();
        assert_eq!(body["title"], "Blue Monday");
        assert_eq!(body["year"], 1983);
        assert!(body["caa_url"].is_null());
        assert!(body["artist_mbid"].is_null());
    }

    #[test]
    fn lookup_missing_is_404_and_not_cached() {
        let repo = FakeRepo::default();
        let cache = FakeCache::default();
        let resp = block_on(handle_lookup(&repo, &cache, Kind::Recording, MBID));
        assert_eq!(resp.status, 404);
        assert_eq!(resp.cache_ttl, None);
        assert!(cache.puts.borrow().is_empty());
    }

    #[test]
    fn lookup_repo_error_is_generic_500_and_not_cached() {
        let repo = FakeRepo {
            fail: true,
            ..Default::default()
        };
        let cache = FakeCache::default();
        let resp = block_on(handle_lookup(&repo, &cache, Kind::Artist, MBID));
        assert_eq!(resp.status, 500);
        assert_eq!(resp.body, r#"{"error":"internal error"}"#);
        assert_eq!(resp.cache_ttl, None);
        assert!(cache.puts.borrow().is_empty());
    }

    #[test]
    fn lookup_invalid_mbid_is_400_before_cache_or_repo() {
        let repo = FakeRepo::default();
        let cache = FakeCache::default();
        let resp = block_on(handle_lookup(&repo, &cache, Kind::Artist, "nope"));
        assert_eq!(resp.status, 400);
        assert_eq!(*repo.lookup_calls.borrow(), 0);
        assert_eq!(*cache.gets.borrow(), 0);
    }

    #[test]
    fn search_returns_ordered_hits_capped_at_limit_and_caches() {
        let repo = FakeRepo {
            hits: (0..30).map(hit).collect(),
            ..Default::default()
        };
        let cache = FakeCache::default();
        let resp = block_on(handle_search(
            &repo,
            &cache,
            Some("artist".to_string()),
            "  Test  ",
        ));
        assert_eq!(resp.status, 200);
        assert_eq!(resp.cache_ttl, Some(300));
        let body: serde_json::Value = serde_json::from_str(&resp.body).unwrap();
        assert_eq!(body["type"], "artist");
        assert_eq!(body["q"], "test");
        let results = body["results"].as_array().unwrap();
        assert_eq!(results.len(), 25);
        assert_eq!(results[0]["name"], "Hit 0");
        assert_eq!(cache.puts.borrow().len(), 1);
        assert_eq!(cache.puts.borrow()[0].1, 300);
        // SQL param is the normalized query, matching the cache key.
        assert_eq!(repo.last_search_q.borrow().as_str(), "test");
    }

    #[test]
    fn search_empty_success_is_200_and_cacheable() {
        let repo = FakeRepo::default();
        let cache = FakeCache::default();
        let resp = block_on(handle_search(
            &repo,
            &cache,
            Some("release".to_string()),
            "nothing matches",
        ));
        assert_eq!(resp.status, 200);
        let body: serde_json::Value = serde_json::from_str(&resp.body).unwrap();
        assert_eq!(body["results"].as_array().unwrap().len(), 0);
        assert_eq!(resp.cache_ttl, Some(300));
    }

    #[test]
    fn search_repo_error_is_not_an_empty_success() {
        let repo = FakeRepo {
            fail: true,
            ..Default::default()
        };
        let cache = FakeCache::default();
        let resp = block_on(handle_search(
            &repo,
            &cache,
            Some("recording".to_string()),
            "anything",
        ));
        assert_eq!(resp.status, 500);
        assert!(!resp.body.contains("results"));
        assert_eq!(resp.cache_ttl, None);
        assert!(cache.puts.borrow().is_empty());
    }

    #[test]
    fn search_cache_hit_skips_repo() {
        let cache = FakeCache::default();
        cache.stored.borrow_mut().insert(
            search_cache_key(Kind::Artist, "test"),
            r#"{"q":"test","cached":true}"#.to_string(),
        );
        let repo = FakeRepo::default();
        let resp = block_on(handle_search(
            &repo,
            &cache,
            Some("artist".to_string()),
            " Test ",
        ));
        assert_eq!(resp.status, 200);
        assert!(resp.body.contains("cached"));
        assert_eq!(*repo.search_calls.borrow(), 0);
    }

    #[test]
    fn search_rejects_bad_input_before_repo() {
        let repo = FakeRepo::default();
        let cache = FakeCache::default();
        for (kind, q) in [
            (Some("artist".to_string()), "a"),
            (Some("track".to_string()), "valid query"),
            (None, "valid query"),
            (Some("artist".to_string()), "x"),
        ] {
            let resp = block_on(handle_search(&repo, &cache, kind, q));
            assert_eq!(resp.status, 400, "q={q}");
            assert_eq!(resp.cache_ttl, None);
        }
        let too_long = "a".repeat(MAX_QUERY_CHARS + 1);
        let resp = block_on(handle_search(
            &repo,
            &cache,
            Some("artist".to_string()),
            &too_long,
        ));
        assert_eq!(resp.status, 400);
        assert_eq!(*repo.search_calls.borrow(), 0);
        assert!(cache.puts.borrow().is_empty());
    }

    #[test]
    fn search_rejects_control_characters_before_cache_or_repo() {
        let repo = FakeRepo::default();
        let cache = FakeCache::default();
        let resp = block_on(handle_search(
            &repo,
            &cache,
            Some("artist".to_string()),
            "\0ab",
        ));

        assert_eq!(resp.status, 400);
        assert_eq!(resp.cache_ttl, None);
        assert_eq!(*repo.search_calls.borrow(), 0);
        assert_eq!(*cache.gets.borrow(), 0);
        assert!(cache.puts.borrow().is_empty());
    }

    #[test]
    fn search_kind_accepts_known_types() {
        assert_eq!(Kind::parse(Some("artist".to_string())), Some(Kind::Artist));
        assert_eq!(
            Kind::parse(Some("release".to_string())),
            Some(Kind::Release)
        );
        assert_eq!(
            Kind::parse(Some("recording".to_string())),
            Some(Kind::Recording)
        );
    }

    #[test]
    fn search_kind_rejects_unknown_types() {
        assert_eq!(Kind::parse(None), None);
        assert_eq!(Kind::parse(Some("track".to_string())), None);
        assert_eq!(Kind::parse(Some(String::new())), None);
    }

    #[test]
    fn cache_control_formats_ttl() {
        assert_eq!(cache_control(300), "public, max-age=300");
        assert_eq!(cache_control(LOOKUP_CACHE_TTL_S), "public, max-age=86400");
    }

    #[test]
    fn mbid_validation_accepts_uuid_shape() {
        assert!(is_valid_mbid("123e4567-e89b-12d3-a456-426614174000"));
        assert!(is_valid_mbid("123E4567-E89B-12D3-A456-426614174000"));
    }

    #[test]
    fn mbid_validation_rejects_malformed_values() {
        assert!(!is_valid_mbid("not-a-uuid"));
        assert!(!is_valid_mbid(""));
        assert!(!is_valid_mbid("123e4567-e89b-12d3-a456-42661417400"));
        assert!(!is_valid_mbid("123e4567-e89b-12d3-a456-4266141740000"));
        assert!(!is_valid_mbid("123e4567_e89b_12d3_a456_426614174000"));
        assert!(!is_valid_mbid("gggggggg-hhhh-iiii-jjjj-kkkkkkkkkkkk"));
    }
}
