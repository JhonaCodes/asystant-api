use std::{
    collections::HashMap,
    net::IpAddr,
    sync::Mutex,
    time::{Duration, Instant},
};
use actix_web::{
    Error,
    body::MessageBody,
    dev::{ServiceRequest, ServiceResponse},
    middleware::Next,
    web,
};
use crate::error::AppError;

/// Process-local admission guard. A trusted ingress must also enforce shared
/// limits. Callers are client backends acting for all their users, often from
/// a single address, so the per-peer window is wide.
pub struct Admission {
    limit: u32,
    windows: Mutex<HashMap<IpAddr, Window>>,
}
struct Window {
    start: Instant,
    count: u32,
}
impl Default for Admission {
    fn default() -> Self {
        Self::with_limit(Self::DEFAULT_LIMIT)
    }
}
impl Admission {
    pub const DEFAULT_LIMIT: u32 = 3000;

    pub fn with_limit(limit: u32) -> Self {
        Self {
            limit,
            windows: Mutex::new(HashMap::new()),
        }
    }
    pub fn check(&self, peer: IpAddr) -> Result<(), AppError> {
        let now = Instant::now();
        let mut windows = self.windows.lock().map_err(|_| AppError::Internal)?;
        windows.retain(|_, window| now.duration_since(window.start) < Duration::from_secs(60));
        if !windows.contains_key(&peer) && windows.len() >= 10_000 {
            return Err(AppError::Limited);
        }
        let window = windows.entry(peer).or_insert(Window {
            start: now,
            count: 0,
        });
        if window.count >= self.limit {
            return Err(AppError::Limited);
        }
        window.count += 1;
        Ok(())
    }
}

pub async fn enforce(
    request: ServiceRequest,
    next: Next<impl MessageBody>,
) -> Result<ServiceResponse<impl MessageBody>, Error> {
    if request.path().starts_with("/v1/") {
        // Never trust caller-supplied Forwarded/X-Forwarded-For headers.
        let peer = request.peer_addr().ok_or(AppError::Invalid)?.ip();
        let admission = request
            .app_data::<web::Data<Admission>>()
            .ok_or(AppError::Internal)?;
        admission.check(peer)?;
    }
    next.call(request).await
}
