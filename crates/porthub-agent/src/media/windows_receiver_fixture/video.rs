//! Test-only APP header metadata. Never retains image/entropy/identifier bytes.
use super::{Config, ENV};
use anyhow::{ensure, Result};
use porthub_components::{media::Kind, media_forward::Plan};
use serde::Serialize;
use std::path::{Path, PathBuf};
#[derive(Serialize, Debug)]
struct App {
    index: u16,
    marker: u8,
    declared_length: u16,
    known_id: &'static str,
}
#[derive(Serialize, Debug)]
pub(crate) struct Headers {
    frame_bytes: usize,
    apps: Vec<App>,
}
fn headers(jpeg: &[u8]) -> Result<Headers> {
    ensure!(
        jpeg.len() <= 2 * 1024 * 1024
            && jpeg.starts_with(&[255, 216])
            && jpeg.ends_with(&[255, 217]),
        "Bounded complete JPEG required"
    );
    let mut at = 2;
    let mut apps = Vec::new();
    let mut index = 0u16;
    while at + 4 <= jpeg.len() {
        ensure!(
            index < 256 && jpeg[at] == 255,
            "Invalid bounded header marker"
        );
        while jpeg.get(at) == Some(&255) {
            at += 1;
        }
        let marker = *jpeg
            .get(at)
            .ok_or_else(|| anyhow::anyhow!("Truncated marker"))?;
        at += 1;
        ensure!(
            !matches!(marker, 0 | 1 | 216 | 217 | 208..=215),
            "Unexpected header marker"
        );
        let bytes = jpeg
            .get(at..at + 2)
            .ok_or_else(|| anyhow::anyhow!("Truncated length"))?;
        let len = u16::from_be_bytes(bytes.try_into().unwrap());
        ensure!(
            len >= 2 && at + len as usize <= jpeg.len(),
            "Truncated header segment"
        );
        let end = at + len as usize;
        if marker == 218 {
            return Ok(Headers {
                frame_bytes: jpeg.len(),
                apps,
            });
        }
        if (224..=239).contains(&marker) {
            ensure!(apps.len() < 32, "APP metadata marker limit");
            let data = &jpeg[at + 2..end];
            let known_id = if data.starts_with(b"JFIF\0") {
                "JFIF"
            } else if data.starts_with(b"AVI1") {
                "AVI1"
            } else if data.starts_with(b"Exif\0\0") {
                "Exif"
            } else if data.starts_with(b"ICC_PROFILE\0") {
                "ICC"
            } else if data.starts_with(b"Adobe") {
                "Adobe"
            } else {
                "unknown"
            };
            apps.push(App {
                index,
                marker,
                declared_length: len,
                known_id,
            });
        }
        index += 1;
        at = end;
    }
    anyhow::bail!("No image scan header")
}
fn binding(
    profile: &Path,
    registered: &Path,
    plan: &Plan,
    source: &str,
    principal: &str,
    destination: &str,
) -> Result<()> {
    ensure!(
        profile == registered
            && plan.valid()
            && plan.kind() == Some(Kind::Camera)
            && plan.source_id == source
            && plan.desktop_uid == 0
            && plan.desktop_session.as_deref() == Some(principal)
            && plan.destination == destination,
        "Camera header proof profile/plan differs"
    );
    Ok(())
}
#[derive(Serialize)]
struct Observed {
    epoch: String,
    headers: Headers,
}
pub(crate) struct VideoProof {
    root: PathBuf,
    plan: String,
    epoch: String,
    active: bool,
    rows: Vec<Observed>,
}
impl VideoProof {
    pub(crate) fn new(profile: &Path) -> Result<Option<Self>> {
        if std::env::var_os(ENV).is_none() {
            return Ok(None);
        }
        let c = Config::load()?;
        c.approve()?;
        ensure!(
            c.kind == Kind::Camera,
            "Camera proof cannot attest microphone data"
        );
        let input = crate::profile::Profile::load(&c.profile)?;
        let registered = c
            .layout()
            .state
            .join(format!("{}.json", crate::service::identity(&input)));
        let plan: Plan = serde_json::from_slice(&crate::profile::read_private(
            &c.root.join("receiver-plan.json"),
        )?)?;
        binding(
            profile,
            &registered,
            &plan,
            &c.source_id,
            &c.desktop_session,
            &input.machine_id,
        )?;
        Ok(Some(Self {
            root: c.root,
            plan: plan.id,
            epoch: String::new(),
            active: false,
            rows: Vec::new(),
        }))
    }
    pub(crate) fn begin(&mut self, epoch: &str, active: bool) -> Result<()> {
        ensure!(
            epoch.len() == 32 && epoch.bytes().all(|b| b.is_ascii_hexdigit()),
            "Invalid header proof epoch"
        );
        self.epoch = epoch.into();
        self.active = active;
        Ok(())
    }
    pub(crate) fn inspect(&self, jpeg: &[u8]) -> Result<Option<Headers>> {
        if self.rows.len() >= 4 {
            Ok(None)
        } else {
            headers(jpeg).map(Some)
        }
    }
    pub(crate) fn accepted(&mut self, epoch: &str, meta: Headers) -> Result<()> {
        ensure!(
            self.active && self.epoch == epoch,
            "Retired camera header proof epoch"
        );
        if self.rows.len() >= 4 {
            return Ok(());
        }
        self.rows.push(Observed {
            epoch: epoch.into(),
            headers: meta,
        });
        let bytes = serde_json::to_vec(
            &serde_json::json!({"plan_id":self.plan,"frames":self.rows,"image_bytes_saved":false}),
        )?;
        ensure!(bytes.len() <= 32768, "Header proof exceeds bound");
        crate::profile::write_private(
            &self.root.join("accepted-video-headers.json"),
            &bytes,
            true,
        )?;
        Ok(())
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    fn jpeg(apps: &[(u8, &[u8])]) -> Vec<u8> {
        let mut v = vec![255, 216];
        for (tag, data) in apps {
            v.extend([255, *tag]);
            v.extend(((data.len() + 2) as u16).to_be_bytes());
            v.extend(*data);
        }
        v.extend([255, 218, 0, 2, 1, 255, 217]);
        v
    }
    #[test]
    fn known_identifiers_are_constant_labels_only() -> Result<()> {
        let v = jpeg(&[
            (224, b"JFIF\0secret"),
            (225, b"Exif\0\0private"),
            (226, b"ICC_PROFILE\0private"),
            (238, b"Adobeprivate"),
            (224, b"AVI1private"),
            (239, b"private"),
        ]);
        let h = headers(&v)?;
        assert_eq!(
            h.apps.iter().map(|a| a.known_id).collect::<Vec<_>>(),
            ["JFIF", "Exif", "ICC", "Adobe", "AVI1", "unknown"]
        );
        let text = serde_json::to_string(&h)?;
        assert!(!text.contains("secret") && !text.contains("private"));
        Ok(())
    }
    #[test]
    fn malformed_truncated_and_marker_limits_fail_closed() {
        assert!(headers(&[255, 216, 255, 224, 0, 99, 255, 217]).is_err());
        assert!(headers(&[255, 216, 255, 224, 0, 1, 255, 217]).is_err());
        assert!(headers(&jpeg(&vec![(224, b"" as &[u8]); 33])).is_err());
        assert_eq!(
            headers(&jpeg(&[(224, b"")])).unwrap().apps[0].declared_length,
            2
        );
    }
    #[test]
    fn profile_kind_principal_binding_is_exact() -> Result<()> {
        let mut p = Plan {
            id: "a".repeat(32),
            source: "b".repeat(24),
            destination: "c".repeat(24),
            desktop_uid: 0,
            desktop_session: Some(format!("windows:{}", "d".repeat(64))),
            source_id: format!("media:{}", "e".repeat(64)),
            name: "Exact".into(),
            identity: porthub_components::media_forward::UsbIdentity {
                vendor: 0x1209,
                product: 1,
            },
            persistent: false,
            mode: "phv1-camera-mjpeg-v1".into(),
        };
        let f = Path::new("/private/exact.json");
        assert!(binding(
            f,
            f,
            &p,
            &p.source_id,
            p.desktop_session.as_deref().unwrap(),
            &p.destination
        )
        .is_ok());
        assert!(binding(
            Path::new("/wrong"),
            f,
            &p,
            &p.source_id,
            p.desktop_session.as_deref().unwrap(),
            &p.destination
        )
        .is_err());
        p.mode = "phm1-microphone-v1".into();
        assert!(binding(
            f,
            f,
            &p,
            &p.source_id,
            p.desktop_session.as_deref().unwrap(),
            &p.destination
        )
        .is_err());
        Ok(())
    }
    #[test]
    fn at_most_four_writes_and_old_epoch_is_never_recorded() -> Result<()> {
        use std::os::unix::fs::PermissionsExt;
        let t = tempfile::tempdir()?;
        std::fs::set_permissions(t.path(), std::fs::Permissions::from_mode(0o700))?;
        let mut p = VideoProof {
            root: t.path().into(),
            plan: "a".repeat(32),
            epoch: String::new(),
            active: false,
            rows: Vec::new(),
        };
        let e = "b".repeat(32);
        p.begin(&e, true)?;
        for _ in 0..4 {
            p.accepted(&e, headers(&jpeg(&[(224, b"")]))?)?;
        }
        assert!(p.inspect(&jpeg(&[]))?.is_none());
        assert_eq!(p.rows.len(), 4);
        p.begin(&"c".repeat(32), false)?;
        assert!(p.accepted(&e, headers(&jpeg(&[]))?).is_err());
        let text = std::fs::read_to_string(t.path().join("accepted-video-headers.json"))?;
        assert!(!text.contains("entropy") && !text.contains("jpeg"));
        Ok(())
    }
}
