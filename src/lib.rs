//! Signed URL middleware for [Axum](axum), using extractors.
//!
//! ## Usage
//!
//! ```rust
//! use axum::{routing::get, Router};
//! use axum_signed_urls::{SignedUrl, build};
//!
//! // This route will only be accessible if the URL is signed
//! async fn handler(_: SignedUrl) -> String {
//!     // This is how you create a signed URL
//!     build("/path", vec![("foo", "bar")].into_iter().collect()).unwrap()
//! }
//! ```
//!
//! ## A common issue with Axum extractors
//!
//! The most often issue with this extractor is using it after one consuming body e.g.
//! [`axum::extract::Json`].
//! To fix this rearrange extractors in your handler definition moving body consumption to the
//! end, see [details][extractors-order].
//!
//! [axum]: https://docs.rs/axum/latest/axum/
//! [extractors-order]: https://docs.rs/axum/latest/axum/extract/index.html#the-order-of-extractors

#![warn(clippy::all, missing_docs, nonstandard_style, future_incompatible)]

use std::collections::HashMap;

use anyhow::{Context, Result};
use axum::{
    async_trait,
    extract::FromRequestParts,
    http::{request::Parts, StatusCode},
};
use hmac::{Hmac, Mac};
use qstring::QString;
use sha2::Sha256;
use std::env;

/// Extractor for signed URLs, acts as a middleware.
#[derive(Debug)]
pub struct SignedUrl;

#[async_trait]
impl<S> FromRequestParts<S> for SignedUrl {
    type Rejection = (StatusCode, &'static str);

    async fn from_request_parts(parts: &mut Parts, _: &S) -> Result<Self, Self::Rejection> {
        let url = parts.uri.path_and_query().unwrap();

        let (signature_parts, other_parts): (Vec<_>, Vec<_>) = QString::from(url.query().unwrap())
            .into_pairs()
            .into_iter()
            .partition(|(k, _)| k == "signature");

        let signature = signature_parts
            .first()
            .map(|(_, s)| s.to_string())
            .ok_or((StatusCode::UNAUTHORIZED, "Missing signature"))?;

        let query = QString::new(other_parts);
        let unsigned_url = format!("{}{}", url.path(), stringify_query(&query));

        if signature != hmac_sha256(&unsigned_url).unwrap() {
            return Err((StatusCode::UNAUTHORIZED, "Invalid signature"));
        }

        Ok(SignedUrl)
    }
}

/// Builder for signed URLs.
///
/// # Example
///
/// ```rust
/// use axum_signed_urls::build;
/// use std::collections::HashMap;
///
/// // Make sure to set AXUM_SECRET to a secret value, e.g. in your .env file
/// # std::env::set_var("AXUM_SECRET", "hunter2");
///
/// let mut query = HashMap::new();
/// query.insert("foo", "bar");
/// query.insert("baz", "qux");
///
/// let url = build("/path", query).unwrap();
/// assert_eq!(url, "/path?baz=qux&foo=bar&signature=25a3d00acee5bf7c1e71f0ce8addab046710221dbc12d0d1ce0a931a6c5f5add");
/// ```
///
/// # Errors
///
/// Returns `Err` if there is an error while signing the URL.
pub fn build(path: &str, query: HashMap<&str, &str>) -> Result<String> {
    let mut query: Vec<(&str, &str)> = query.into_iter().collect();
    query.sort_by(|(k1, _), (k2, _)| k1.cmp(k2));

    let mut query = QString::new(query);

    let signature = hmac_sha256(&format!("{path}{}", stringify_query(&query)))?;
    query.add_pair(("signature", &signature));

    Ok(format!("{path}{}", stringify_query(&query)))
}

fn stringify_query(query: &QString) -> String {
    if query.is_empty() {
        String::new()
    } else {
        format!("?{query}")
    }
}

type HmacSha256 = Hmac<Sha256>;

fn hmac_sha256<T: AsRef<[u8]>>(data: &T) -> Result<String> {
    let app_key = env::var("AXUM_SECRET").context("AXUM_SECRET not found")?;

    Ok(hex::encode(
        HmacSha256::new_from_slice(app_key.as_bytes())?
            .chain_update(data)
            .finalize()
            .into_bytes(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::env;

    use axum::extract::FromRequest;
    use http::Request;
    use map_macro::map;

    #[test]
    fn hmac_sha256_matches_snapshot() {
        env::set_var("AXUM_SECRET", "hunter2");

        assert_eq!(
            hmac_sha256(&"test").unwrap(),
            "4e99265a03bc2001089f7196919be9bbf5b81a557fbb7ea9907a18a461437a04"
        );
    }

    #[ignore = "pollutes environment"]
    #[test]
    fn fails_when_axum_secret_not_set() {
        env::remove_var("AXUM_SECRET");
        let err = hmac_sha256(&"test").unwrap_err();

        assert_eq!(err.to_string(), "AXUM_SECRET not found");
    }

    #[tokio::test]
    async fn validates_signed_url() {
        env::set_var("AXUM_SECRET", "hunter2");

        let req = Request::builder()
            .uri(format!(
                "https://example.com{}",
                build("/hi", map! {"email" => "miguel@example.com"}).unwrap()
            ))
            .body(())
            .unwrap();

        SignedUrl::from_request(req, &()).await.unwrap();
    }

    #[tokio::test]
    async fn throws_unauthorized_error_on_invalid_signature() {
        env::set_var("AXUM_SECRET", "hunter2");

        let req = Request::builder()
            .uri(format!(
                "https://example.com{}",
                build("/login", map! {"email" => "miguel@example.com"})
                    .unwrap()
                    .replace("miguel@", "admin@")
            ))
            .body(())
            .unwrap();

        let err = SignedUrl::from_request(req, &()).await.unwrap_err();

        assert_eq!(err, (StatusCode::UNAUTHORIZED, "Missing signature"));
    }

    #[tokio::test]
    async fn throws_unauthorized_error_on_missing_signature() {
        env::set_var("AXUM_SECRET", "hunter2");

        let req = Request::builder()
            .uri("https://example.com/hello?email=admin@example.com")
            .body(())
            .unwrap();

        let err = SignedUrl::from_request(req, &()).await.unwrap_err();

        assert_eq!(err, (StatusCode::UNAUTHORIZED, "Missing signature"));
    }

    #[tokio::test]
    async fn works_without_extra_query_params() {
        env::set_var("AXUM_SECRET", "hunter2");

        let req = Request::builder()
            .uri(format!(
                "https://example.com{}",
                build("/test", map! {}).unwrap()
            ))
            .body(())
            .unwrap();

        SignedUrl::from_request(req, &()).await.unwrap();
    }
}
