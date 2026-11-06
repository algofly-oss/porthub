//! Credential-free registration selection for an optional terminal guest frontend.
use anyhow::Result;
use porthub_components::protocol::terminal::Broker;
pub fn broker(selector: Option<&str>, user: bool) -> Result<Option<Broker>> {
    let selected = select_registration(selector, user)?;
    selected
        .map(|(layout, id)| {
            Ok(Broker {
                endpoint: crate::exposure_broker::endpoint(&layout, &id)?,
                owner: if layout.user {
                    unsafe { libc::geteuid() }
                } else {
                    0
                },
                traffic: false,
            })
        })
        .transpose()
}
fn select_registration(
    selector: Option<&str>,
    user: bool,
) -> Result<Option<(crate::service::Layout, String)>> {
    let layouts = if user {
        vec![crate::service::Layout::user()?]
    } else if selector.is_some() {
        vec![crate::service::Layout::system()?]
    } else {
        vec![
            crate::service::Layout::user()?,
            crate::service::Layout::system()?,
        ]
    };
    select_from(layouts, selector)
}
fn select_from(
    layouts: Vec<crate::service::Layout>,
    selector: Option<&str>,
) -> Result<Option<(crate::service::Layout, String)>> {
    let mut candidates = Vec::new();
    for layout in layouts {
        if selector.is_some() {
            let record = crate::service::readable::select(&layout, selector, Some(false))?;
            return Ok(if record.enabled {
                Some((layout, record.id))
            } else {
                None
            });
        }
        let Ok(records) = crate::service::readable::list(&layout) else {
            return Ok(None);
        };
        for record in records
            .into_iter()
            .filter(|record| !record.private && record.enabled)
        {
            candidates.push((layout.clone(), record.id));
        }
    }
    Ok(if candidates.len() == 1 {
        candidates.pop()
    } else {
        None
    })
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn automatic_registration_selection_requires_one_unambiguous_readable_public_registration(
    ) -> Result<()> {
        let root = tempfile::tempdir()?;
        let layout = crate::service::Layout {
            user: true,
            state: root.path().join("native"),
            releases: root.path().join("releases"),
            units: root.path().join("units"),
        };
        assert!(select_from(vec![layout.clone()], None)?.is_none());
        let status = crate::service::readable::directory(&layout)?;
        crate::service::directory(&status,true)?;
        let record = |id: &str, machine: &str| crate::service::readable::Record {
            format_version: 1,
            id: id.into(),
            machine_id: machine.into(),
            email: "fixture@example.test".into(),
            gateway: "https://example.test".into(),
            private: false,
            enabled: true,
            active: Some(true),
            state: "running".into(),
            agent_version: "test".into(),
            ports: 0,
            route: "public".into(),
            updated_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            strategy: Default::default(),
            strategy_override: false,
            private_status: None,
        };
        let id = "a".repeat(64);
        let other = "b".repeat(64);
        crate::profile::write_private(
            &status.join(format!("{id}.json")),
            &serde_json::to_vec(&record(&id, "1"))?,
            false,
        )?;
        assert_eq!(select_from(vec![layout.clone()], None)?.unwrap().1, id);
        crate::profile::write_private(
            &status.join(format!("{other}.json")),
            &serde_json::to_vec(&record(&other, "2"))?,
            false,
        )?;
        assert!(
            select_from(vec![layout.clone()], None)?.is_none(),
            "auto must not guess between accounts"
        );
        assert_eq!(
            select_from(vec![layout.clone()], Some("aaaaaa"))?
                .unwrap()
                .1,
            id
        );
        crate::profile::write_private(
            &status.join(format!("{other}.json")),
            b"unreadable metadata",
            true,
        )?;
        assert!(
            select_from(vec![layout], None)?.is_none(),
            "unknown registrations cannot approve direct traffic"
        );
        Ok(())
    }
}
