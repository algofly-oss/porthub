//! One bounded release document describes core binaries and optional tools.
use crate::catalog::{Blob, Catalog, MAX_CATALOG, MAX_EXECUTABLE, REPOSITORY};
use anyhow::{ensure, Result};
use semver::Version;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

pub const CORE_TARGETS: &[(&str, &str)] = &[
    ("x86_64", "linux"),
    ("x86", "linux"),
    ("arm64", "linux"),
    ("armhf", "linux"),
    ("armv7", "linux"),
    ("darwin_x86_64", "macos"),
    ("darwin_arm64", "macos"),
    ("windows_x86_64", "windows"),
    ("windows_x86", "windows"),
    ("windows_arm64", "windows"),
];
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CoreAsset {
    pub target: String,
    pub asset: String,
    pub executable: Blob,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReleaseManifest {
    pub schema_version: u32,
    pub repository: String,
    pub release: Version,
    /// Core executable version can stay fixed across helper-only releases.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub core_version: Option<Version>,
    pub core_assets: Vec<CoreAsset>,
    pub components: Catalog,
}
impl ReleaseManifest {
    pub fn core_version(&self) -> &Version {
        self.core_version.as_ref().unwrap_or(&self.release)
    }
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        ensure!(
            bytes.len() <= MAX_CATALOG,
            "release manifest exceeds size limit"
        );
        let manifest: Self = serde_json::from_slice(bytes)?;
        manifest.validate()?;
        Ok(manifest)
    }
    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.schema_version == 2
                && self.repository == REPOSITORY
                && self.release.pre.is_empty()
                && self.release.build.is_empty(),
            "unsupported release manifest"
        );
        ensure!(
            self.core_version().pre.is_empty() && self.core_version().build.is_empty(),
            "core version must be stable"
        );
        self.components.validate()?;
        ensure!(
            self.components.release == self.release
                && self.components.repository == self.repository,
            "component and core release identities differ"
        );
        ensure!(
            self.core_assets.len() == CORE_TARGETS.len(),
            "incomplete core release"
        );
        let mut seen = BTreeSet::new();
        for asset in &self.core_assets {
            let (_, os) = CORE_TARGETS
                .iter()
                .find(|(target, _)| *target == asset.target)
                .ok_or_else(|| anyhow::anyhow!("unsupported core target"))?;
            let expected = format!(
                "porthub-{}{}",
                asset.target,
                if *os == "windows" { ".exe" } else { "" }
            );
            ensure!(
                asset.asset == expected && seen.insert(&asset.target),
                "invalid or duplicate core asset"
            );
            asset.executable.validate(MAX_EXECUTABLE)?;
        }
        Ok(())
    }
}
