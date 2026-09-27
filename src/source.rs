use std::net::IpAddr;
use std::str::FromStr;

use actix_web::HttpRequest;
use actix_web::http::header::HeaderName;

use crate::error::AppError;

/// Where a request comes from. Behind a reverse proxy the TCP peer is the proxy
/// itself, so the operator may name one header that the edge proxy always
/// overwrites (for example `CF-Connecting-IP` or `X-Real-IP`). Only its last
/// value is trusted: that is the one the nearest proxy wrote. Without the
/// setting, forwarding headers are ignored because any caller could forge them.
#[derive(Debug, Clone, Default)]
pub struct SourceResolver {
    header: Option<HeaderName>,
}

impl SourceResolver {
    pub const HEADER_ENV: &'static str = "ASYSTANT_CLIENT_IP_HEADER";

    pub fn new(header: Option<&str>) -> Result<Self, AppError> {
        let header = header
            .map(str::trim)
            .filter(|name| !name.is_empty())
            .map(|name| HeaderName::from_str(name).map_err(|_| AppError::Invalid))
            .transpose()?;
        Ok(Self { header })
    }

    pub fn resolve(&self, request: &HttpRequest) -> Option<IpAddr> {
        match &self.header {
            Some(header) => request
                .headers()
                .get(header)
                .and_then(|value| value.to_str().ok())
                .and_then(|value| value.rsplit(',').next())
                .and_then(|value| IpAddr::from_str(value.trim()).ok()),
            None => request.peer_addr().map(|peer| peer.ip()),
        }
    }

    /// Text for audit and last-use records.
    pub fn describe(&self, request: &HttpRequest) -> String {
        self.resolve(request)
            .map_or_else(|| "unknown".to_string(), |address| address.to_string())
    }
}
