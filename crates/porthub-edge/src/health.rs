//! Sample the edge process's descriptor budget through the real HTTP health
//! route. A separate TCP-connect probe can succeed while accept queues stall.
use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
};

#[cfg(any(target_os = "linux", test))]
#[derive(Debug)]
struct Descriptors {
    used: u64,
    limit: Option<u64>,
}
#[cfg(any(target_os = "linux", test))]
impl Descriptors {
    fn pressured(&self) -> bool {
        self.limit
            .is_some_and(|limit| self.used >= limit.saturating_mul(9) / 10)
    }
}
#[cfg(target_os = "linux")]
fn descriptors() -> std::io::Result<Descriptors> {
    let limits = std::fs::read_to_string("/proc/self/limits")?;
    let limit = limits
        .lines()
        .find_map(|line| {
            line.strip_prefix("Max open files")
                .and_then(|rest| rest.split_whitespace().next())
        })
        .ok_or_else(|| std::io::Error::other("descriptor limit missing"))?;
    let limit = if limit == "unlimited" {
        None
    } else {
        Some(
            limit
                .parse()
                .map_err(|_| std::io::Error::other("invalid descriptor limit"))?,
        )
    };
    let used = std::fs::read_dir("/proc/self/fd")?
        .try_fold(0u64, |count, entry| entry.map(|_| count + 1))?;
    // Exclude the descriptor used to enumerate this directory.
    Ok(Descriptors {
        used: used.saturating_sub(1),
        limit,
    })
}

pub(crate) async fn check() -> Response {
    #[cfg(target_os = "linux")]
    {
        let sample = tokio::task::spawn_blocking(descriptors).await;
        match sample {
            Ok(Ok(sample)) => {
                let status = if sample.pressured() {
                    tracing::warn!(
                        used = sample.used,
                        limit = sample.limit,
                        "edge descriptor budget under pressure"
                    );
                    StatusCode::SERVICE_UNAVAILABLE
                } else {
                    StatusCode::OK
                };
                (
                    status,
                    [
                        ("x-porthub-fd-used", sample.used.to_string()),
                        (
                            "x-porthub-fd-limit",
                            sample
                                .limit
                                .map_or_else(|| "unlimited".into(), |n| n.to_string()),
                        ),
                    ],
                    if status.is_success() {
                        "ok"
                    } else {
                        "descriptor pressure"
                    },
                )
                    .into_response()
            }
            _ => {
                tracing::warn!("edge descriptor budget could not be sampled");
                (
                    StatusCode::SERVICE_UNAVAILABLE,
                    "descriptor check unavailable",
                )
                    .into_response()
            }
        }
    }
    #[cfg(not(target_os = "linux"))]
    (StatusCode::OK, "ok").into_response()
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn pressure_is_relative_to_the_current_soft_limit() {
        assert!(!Descriptors {
            used: 800,
            limit: Some(1024)
        }
        .pressured());
        assert!(Descriptors {
            used: 1000,
            limit: Some(1024)
        }
        .pressured());
        assert!(!Descriptors {
            used: 1000,
            limit: Some(65536)
        }
        .pressured());
        assert!(!Descriptors {
            used: 100000,
            limit: None
        }
        .pressured());
    }
    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn health_reports_the_descriptor_budget_and_an_http_response() {
        let response = check().await;
        assert_eq!(response.status(), StatusCode::OK);
        assert!(
            response.headers()["x-porthub-fd-used"]
                .to_str()
                .unwrap()
                .parse::<u64>()
                .unwrap()
                > 0
        );
        assert!(response.headers().contains_key("x-porthub-fd-limit"));
    }
}
