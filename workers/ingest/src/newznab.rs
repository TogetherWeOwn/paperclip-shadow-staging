//! Newznab search for BYO indexers.
//!
//! Security contract (see the vault card: raw provider/indexer keys live in
//! the BYOP vault, never in repo, logs, or API bodies):
//!
//! - [`build_search_url`] builds the query URL **without** the key.
//! - [`inject_api_key`] adds `&apikey=` server-side from the vault binding,
//!   at request time only.
//! - [`redact_api_key`] scrubs the key for logs. Log the redacted URL only.
//! - `http://` indexer URLs are refused: the key would travel in cleartext.

/// Newznab search caps for one request.
pub const MAX_LIMIT: u32 = 100;
/// Music-only search (`t=music`); the pipeline ingests audio releases.
pub const SEARCH_TYPE: &str = "music";
/// Upper bound on requested categories per search: every category becomes a
/// `&cat=` parameter on the outbound URL, so an unbounded list is an
/// unbounded URL. Routes reject larger lists with 400 before anything is
/// built or enqueued.
pub const MAX_CATEGORIES: usize = 16;
/// Upper bound on the requested page (0-based). With [`MAX_LIMIT`] this caps
/// the offset at 10_000 rows; routes reject larger pages with 400.
pub const MAX_PAGE: u32 = 100;
/// Largest offset [`build_search_url`] accepts (`MAX_PAGE * MAX_LIMIT`).
pub const MAX_OFFSET: u32 = MAX_PAGE * MAX_LIMIT;

/// Query parameters for one Newznab search.
pub struct SearchParams<'a> {
    pub base_url: &'a str,
    pub query: &'a str,
    pub categories: &'a [u32],
    pub limit: u32,
    pub offset: u32,
}

/// Percent-encode a query value (RFC 3986 unreserved set stays bare).
pub fn percent_encode(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len());
    for b in raw.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'~') {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

/// Reject non-https URLs, embedded credentials, and URLs that already carry
/// a query or fragment.
///
/// A base URL pasted with its own `?apikey=…` would compose into a URL that
/// already holds a key before [`inject_api_key`] runs (malforming `/api` into
/// a query value and leaking the real key past [`redact_api_key`); a `#`
/// would swallow the whole search query into the fragment so it is never
/// sent. Bare origin + optional path only.
fn check_base_url(base_url: &str) -> Result<String, &'static str> {
    if !base_url.starts_with("https://") {
        return Err("indexer base url must be https");
    }
    let rest = &base_url["https://".len()..];
    if rest.is_empty() || rest.starts_with('/') {
        return Err("indexer base url must include a host");
    }
    if rest.contains('@') {
        return Err("indexer base url must not embed credentials");
    }
    if rest.contains('?') || rest.contains('#') {
        return Err("indexer base url must not contain '?' or '#'");
    }
    if rest.chars().any(|c| c.is_whitespace()) {
        return Err("indexer base url must not contain whitespace");
    }
    Ok(base_url.trim_end_matches('/').to_string())
}

/// Build `https://{indexer}/api?apikey=…` query URL **without** the key.
///
/// Returns an error for empty queries, out-of-range limits, http URLs,
/// and credential-embedding hosts.
pub fn build_search_url(params: &SearchParams<'_>) -> Result<String, &'static str> {
    let base = check_base_url(params.base_url)?;
    let q = params.query.trim();
    if q.is_empty() || q.len() > 200 {
        return Err("query must be 1..=200 chars");
    }
    if params.limit == 0 || params.limit > MAX_LIMIT {
        return Err("limit must be 1..=100");
    }
    if params.offset > MAX_OFFSET {
        return Err("offset exceeds the paged search window");
    }
    if params.categories.len() > MAX_CATEGORIES {
        return Err("too many categories (max 16)");
    }
    let mut url = format!(
        "{base}/api?t={SEARCH_TYPE}&o=json&q={}&limit={}&offset={}",
        percent_encode(q),
        params.limit,
        params.offset
    );
    for cat in params.categories {
        url.push_str(&format!("&cat={cat}"));
    }
    Ok(url)
}

/// Append the vault-resolved key at request time. Never log the result.
pub fn inject_api_key(url_without_key: &str, api_key: &str) -> Result<String, &'static str> {
    if api_key.is_empty() || api_key.len() > 256 {
        return Err("api key must be 1..=256 chars");
    }
    Ok(format!(
        "{url_without_key}&apikey={}",
        percent_encode(api_key)
    ))
}

/// Scrub every `apikey=` value for logs and error messages.
///
/// Case-insensitive (`apikey=`, `APIKEY=`, …) and global: a composed URL can
/// hold more than one key parameter, and leaving any of them scrubs nothing.
/// The parameter names keep their original case; only the values become `***`.
pub fn redact_api_key(url_with_key: &str) -> String {
    // `apikey=` is ASCII, so byte offsets in the lowercased copy line up with
    // the original.
    let lower = url_with_key.to_ascii_lowercase();
    if !lower.contains("apikey=") {
        return url_with_key.to_string();
    }
    let mut out = String::with_capacity(url_with_key.len());
    let mut last = 0;
    let mut from = 0;
    while let Some(rel) = lower[from..].find("apikey=") {
        let name_at = from + rel;
        let value_at = name_at + "apikey=".len();
        out.push_str(&url_with_key[last..value_at]);
        out.push_str("***");
        let value_end = url_with_key[value_at..]
            .find('&')
            .map(|e| value_at + e)
            .unwrap_or(url_with_key.len());
        last = value_end;
        from = value_end;
    }
    out.push_str(&url_with_key[last..]);
    out
}

/// Offset for `page` (0-based) with a row `limit`, saturating on overflow.
pub fn page_offset(page: u32, limit: u32) -> u32 {
    page.saturating_mul(limit)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn params<'a>(base: &'a str, q: &'a str) -> SearchParams<'a> {
        SearchParams {
            base_url: base,
            query: q,
            categories: &[],
            limit: 25,
            offset: 0,
        }
    }

    #[test]
    fn builds_music_search_url() {
        let url = build_search_url(&params("https://indexer.example/", "dark side moon")).unwrap();
        assert!(url.starts_with("https://indexer.example/api?"));
        assert!(url.contains("t=music&o=json"));
        assert!(url.contains("q=dark%20side%20moon"));
        assert!(url.contains("limit=25&offset=0"));
        assert!(!url.contains("apikey"));
    }

    #[test]
    fn categories_append_as_cat_params() {
        let cats = [3000, 3040];
        let p = SearchParams {
            base_url: "https://indexer.example",
            query: "kind",
            categories: &cats,
            limit: 10,
            offset: 20,
        };
        let url = build_search_url(&p).unwrap();
        assert!(url.contains("&cat=3000&cat=3040"));
    }

    #[test]
    fn refuses_http_credential_hosts_and_bad_queries() {
        assert!(build_search_url(&params("http://indexer.example", "x")).is_err());
        assert!(build_search_url(&params("https://user:pass@indexer.example", "x")).is_err());
        assert!(build_search_url(&params("https://", "x")).is_err());
        assert!(build_search_url(&params("https://indexer.example", "")).is_err());
        assert!(build_search_url(&params("https://indexer.example", &"x".repeat(201))).is_err());
        let mut p = params("https://indexer.example", "x");
        p.limit = 0;
        assert!(build_search_url(&p).is_err());
        p.limit = MAX_LIMIT + 1;
        assert!(build_search_url(&p).is_err());
    }

    #[test]
    fn key_injection_and_redaction_roundtrip() {
        let bare = build_search_url(&params("https://indexer.example", "x")).unwrap();
        let full = inject_api_key(&bare, "test-api-key-1").unwrap();
        assert!(full.contains("apikey=test-api-key-1"));
        let redacted = redact_api_key(&full);
        assert!(!redacted.contains("test-api-key-1"));
        assert!(redacted.contains("apikey=***"));
        assert!(inject_api_key(&bare, "").is_err());
    }

    #[test]
    fn redact_leaves_keyless_urls_alone() {
        let bare = build_search_url(&params("https://indexer.example", "x")).unwrap();
        assert_eq!(redact_api_key(&bare), bare);
    }

    #[test]
    fn base_url_rejects_query_fragment_and_whitespace() {
        // A pasted URL carrying its own query would smuggle a key past the
        // vault flow and malform /api; a fragment would swallow the query.
        assert!(build_search_url(&params("https://indexer.example?apikey=x", "x")).is_err());
        assert!(build_search_url(&params("https://indexer.example/api?t=music", "x")).is_err());
        assert!(build_search_url(&params("https://indexer.example#frag", "x")).is_err());
        assert!(build_search_url(&params("https://indexer.example/a b", "x")).is_err());
        assert!(build_search_url(&params("https://indexer.example/path/", "x")).is_ok());
    }

    #[test]
    fn redact_scrubs_every_key_case_insensitively() {
        let url = "https://i.example/api?t=music&apikey=FIRST&q=x&APIKEY=SECOND&other=1";
        let redacted = redact_api_key(url);
        assert!(!redacted.contains("FIRST"));
        assert!(!redacted.contains("SECOND"));
        assert!(redacted.contains("q=x"));
        assert!(redacted.contains("other=1"));
        assert_eq!(redacted.matches("***").count(), 2);
    }

    #[test]
    fn search_caps_categories_and_offset() {
        let cats: Vec<u32> = (0..(MAX_CATEGORIES as u32 + 1)).collect();
        let mut p = SearchParams {
            base_url: "https://indexer.example",
            query: "x",
            categories: &cats,
            limit: 10,
            offset: 0,
        };
        assert!(build_search_url(&p).is_err());
        p.categories = &cats[..MAX_CATEGORIES];
        assert!(build_search_url(&p).is_ok());
        p.offset = MAX_OFFSET + 1;
        assert!(build_search_url(&p).is_err());
        p.offset = MAX_OFFSET;
        assert!(build_search_url(&p).is_ok());
    }

    #[test]
    fn page_offset_saturates() {
        assert_eq!(page_offset(2, 25), 50);
        assert_eq!(page_offset(0, 25), 0);
        assert_eq!(page_offset(u32::MAX, u32::MAX), u32::MAX);
    }
}
