use anyhow::{ensure, Context, Result};
use semver::{Version, VersionReq};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeSet, fmt};

pub const REPOSITORY: &str = "algofly-oss/porthub";
pub const CATALOG_ASSET: &str = "porthub-components.json";
pub const MAX_CATALOG: usize = 512 * 1024;
pub const MAX_EXECUTABLE: u64 = 256 * 1024 * 1024;
pub const MAX_ARCHIVE: u64 = 512 * 1024 * 1024;
pub const PROTOCOL: u32 = 1;
pub const TARGETS: &[&str] = &[
    "x86_64-unknown-linux-gnu",
    "aarch64-unknown-linux-gnu",
    "i686-unknown-linux-gnu",
    "armv7-unknown-linux-gnueabihf",
    "arm-unknown-linux-gnueabihf",
    "x86_64-apple-darwin",
    "aarch64-apple-darwin",
    "x86_64-pc-windows-msvc",
    "i686-pc-windows-msvc",
    "aarch64-pc-windows-msvc",
];

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Component {
    Tor,
    Terminal,
    Sync,
    Stats,
    Transfer,
}
impl Component {
    pub const ALL: [Self; 5] = [
        Self::Tor,
        Self::Terminal,
        Self::Sync,
        Self::Stats,
        Self::Transfer,
    ];
    pub const OPTIONAL: [Self; 4] = [Self::Tor, Self::Terminal, Self::Sync, Self::Stats];
    pub fn name(self) -> &'static str {
        match self {
            Self::Tor => "tor",
            Self::Terminal => "terminal",
            Self::Sync => "sync",
            Self::Stats => "stats",
            Self::Transfer => "transfer",
        }
    }
    pub fn executable(self, target: &str) -> String {
        format!(
            "porthub-{}{}",
            self.name(),
            if target.contains("windows") {
                ".exe"
            } else {
                ""
            }
        )
    }
}
impl fmt::Display for Component {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}
impl std::str::FromStr for Component {
    type Err = anyhow::Error;
    fn from_str(value: &str) -> Result<Self> {
        Ok(match value {
            "tor" => Self::Tor,
            "terminal" => Self::Terminal,
            "sync" => Self::Sync,
            "stats" => Self::Stats,
            "transfer" => Self::Transfer,
            _ => anyhow::bail!("unknown component; choose tor, terminal, sync, stats, or transfer"),
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Blob {
    pub size: u64,
    pub sha256: String,
}
impl Blob {
    pub fn validate(&self, max: u64) -> Result<()> {
        ensure!(
            (1..=max).contains(&self.size),
            "invalid component artifact size"
        );
        ensure!(digest(&self.sha256), "invalid component artifact digest");
        Ok(())
    }
}
pub fn digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn stable(version: &Version) -> bool {
    version.pre.is_empty() && version.build.is_empty()
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Artifact {
    pub component: Component,
    pub version: Version,
    pub target: String,
    pub core: VersionReq,
    pub protocols: Vec<u32>,
    pub source_revision: String,
    pub build_inputs: String,
    pub executable: Blob,
    pub release: Version,
    pub archive: Blob,
}
impl Artifact {
    /// Repacking a tool in a later coherent release must not change the
    /// executable, its build provenance, or its compatibility under one version.
    pub fn same_tool(&self, other: &Self) -> bool {
        self.component == other.component
            && self.version == other.version
            && self.target == other.target
            && self.core == other.core
            && self.protocols == other.protocols
            && self.source_revision == other.source_revision
            && self.build_inputs == other.build_inputs
            && self.executable == other.executable
    }
    pub fn archive_name(&self) -> String {
        format!("porthub-tools-{}.tar.gz", self.target)
    }
    pub fn member(&self) -> String {
        format!(
            "{}/{}/{}",
            self.component,
            self.version,
            self.component.executable(&self.target)
        )
    }
    pub fn github_url(&self) -> String {
        format!(
            "https://github.com/{REPOSITORY}/releases/download/v{}/{}",
            self.release,
            self.archive_name()
        )
    }
    pub fn gateway_path(&self) -> String {
        format!(
            "api/downloads/components/{}/{}/{}/{}",
            self.component, self.version, self.target, self.executable.sha256
        )
    }
    pub fn validate(&self) -> Result<()> {
        ensure!(
            stable(&self.version) && stable(&self.release),
            "component versions must be stable numeric versions"
        );
        ensure!(
            TARGETS.contains(&self.target.as_str()),
            "unsupported component target"
        );
        ensure!(
            !self.protocols.is_empty()
                && self.protocols.len() <= 8
                && self.protocols.iter().all(|p| *p > 0),
            "invalid component protocols"
        );
        ensure!(
            self.protocols.iter().collect::<BTreeSet<_>>().len() == self.protocols.len(),
            "duplicate component protocol"
        );
        ensure!(
            self.source_revision.len() == 40
                && self
                    .source_revision
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
            "invalid component source revision"
        );
        ensure!(digest(&self.build_inputs), "invalid component build inputs");
        self.executable.validate(MAX_EXECUTABLE)?;
        self.archive.validate(MAX_ARCHIVE)?;
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Catalog {
    pub schema_version: u32,
    pub repository: String,
    /// Version of the coherent release carrying this catalog, not component versions.
    pub release: Version,
    pub artifacts: Vec<Artifact>,
}
impl Catalog {
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        ensure!(
            bytes.len() <= MAX_CATALOG,
            "component catalog exceeds size limit"
        );
        let value: serde_json::Value = serde_json::from_slice(bytes).context("invalid component catalog")?;
        if value.get("schema_version").and_then(serde_json::Value::as_u64) == Some(2) {
            return Ok(crate::manifest::ReleaseManifest::parse(bytes)?.components);
        }
        let catalog: Self = serde_json::from_value(value).context("invalid component catalog")?;
        catalog.validate()?;
        Ok(catalog)
    }
    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.schema_version == 1 && self.repository == REPOSITORY && stable(&self.release),
            "unsupported component catalog"
        );
        ensure!(
            !self.artifacts.is_empty() && self.artifacts.len() <= 512,
            "invalid component catalog length"
        );
        let mut unique = BTreeSet::new();
        let mut archives = std::collections::BTreeMap::new();
        for artifact in &self.artifacts {
            artifact.validate()?;
            ensure!(
                artifact.release <= self.release,
                "component references a future release"
            );
            ensure!(
                unique.insert((artifact.component, &artifact.version, &artifact.target)),
                "duplicate component version and target"
            );
            let key = (&artifact.release, &artifact.target);
            let blob = (&artifact.archive.sha256, artifact.archive.size);
            if let Some(previous) = archives.insert(key, blob) {
                ensure!(previous == blob, "conflicting component archive metadata");
            }
        }
        Ok(())
    }
    pub fn validate_successor(&self, previous: &Self) -> Result<()> {
        ensure!(
            self.release >= previous.release,
            "component catalog downgrade rejected"
        );
        if self.release == previous.release {
            ensure!(
                serde_json::to_vec(self)? == serde_json::to_vec(previous)?,
                "published component catalog changed"
            );
        }
        for artifact in &self.artifacts {
            if let Some(old) = previous.artifacts.iter().find(|old| {
                old.component == artifact.component
                    && old.version == artifact.version
                    && old.target == artifact.target
            }) {
                ensure!(
                    artifact.same_tool(old),
                    "published component version changed"
                );
            }
        }
        Ok(())
    }
    pub fn select(
        &self,
        component: Component,
        core: &Version,
        target: &str,
        pin: Option<&Version>,
    ) -> Option<&Artifact> {
        self.artifacts
            .iter()
            .filter(|a| {
                a.component == component
                    && a.target == target
                    && a.core.matches(core)
                    && a.protocols.contains(&PROTOCOL)
                    && pin.is_none_or(|pin| pin == &a.version)
            })
            .max_by(|a, b| a.version.cmp(&b.version))
    }
}
