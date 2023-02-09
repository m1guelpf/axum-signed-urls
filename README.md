[![License](https://img.shields.io/crates/l/axum-signed-urls.svg)](https://choosealicense.com/licenses/mit/)
[![Crates.io](https://img.shields.io/crates/v/axum-signed-urls.svg)](https://crates.io/crates/axum-signed-urls)
[![Docs.rs](https://docs.rs/axum-signed-urls/badge.svg)](https://docs.rs/axum-signed-urls)

# `axum-signed-urls`

<!-- cargo-sync-readme start -->

Signed URL middleware for [Axum](axum), using extractors.

## Usage

```rust,no_run,ignore
use axum::{routing::get, Router};
use axum_signed_urls::{SignedUrl, build};

// This route will only be accessible if the URL is signed
async fn handler(_: SignedUrl) -> String {
    // This is how you create a signed URL
    build("/path", vec![("foo", "bar")].into_iter().collect()).unwrap();
}
```

## A common issue with Axum extractors

The most often issue with this extractor is using it after one consuming body e.g.
[`axum::extract::Json`].
To fix this rearrange extractors in your handler definition moving body consumption to the
end, see [details][extractors-order].

[axum]: https://docs.rs/axum/latest/axum/
[extractors-order]: https://docs.rs/axum/latest/axum/extract/index.html#the-order-of-extractors

<!-- cargo-sync-readme end -->

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
