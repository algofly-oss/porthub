//! Default desktop entrypoint: supervise credential-free public registrations.
//! Discovery selects brokers only; each existing broker still authenticates the
//! desktop caller and enforces its enrollment's policy and local grant.
use super::*;
use std::{
    collections::{HashMap, HashSet},
    future::Future,
};
use tokio::{
    task::{AbortHandle, Id, JoinSet},
    time::Instant,
};

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
struct Key {
    state: PathBuf,
    user: bool,
    id: String,
}
struct Registration {
    key: Key,
    layout: crate::service::Layout,
}
#[derive(Clone, Copy)]
enum Retirement {
    Waiting(Instant),
    Aborted,
}
struct Running {
    cancel: CancellationToken,
    task: Id,
    abort: AbortHandle,
    retiring: Option<Retirement>,
}
fn discover(layouts: &[crate::service::Layout]) -> Vec<Registration> {
    let mut candidates = HashMap::new();
    for layout in layouts {
        match crate::service::readable::list(layout) {
            Ok(rows) => {
                for row in rows
                    .into_iter()
                    .filter(|r| !r.private && r.enabled && r.state != "uninstalled")
                {
                    let key = Key {
                        state: layout.state.clone(),
                        user: layout.user,
                        id: row.id,
                    };
                    candidates
                        .entry(key.clone())
                        .or_insert_with(|| Registration {
                            key,
                            layout: layout.clone(),
                        });
                }
            }
            Err(error) => {
                tracing::debug!(reason=%error,"Desktop registration metadata unavailable")
            }
        }
    }
    let mut identities = HashMap::<String, usize>::new();
    for key in candidates.keys() {
        *identities.entry(key.id.clone()).or_default() += 1;
    }
    candidates.into_values().filter(|r|{
        if identities[&r.key.id]>1 {
            tracing::debug!(registration=%r.key.id,"Duplicate desktop registration identity across layouts; remove the duplicate enrollment before desktop startup can serve it");false
        }else{true}
    }).collect()
}
pub(super) async fn supervise(
    layouts: Vec<crate::service::Layout>,
    cancel: CancellationToken,
) -> Result<()> {
    supervise_with(
        layouts,
        cancel,
        Duration::from_secs(5),
        Duration::from_secs(5),
        super::run_registration,
    )
    .await
}
async fn supervise_with<F, Fut>(
    layouts: Vec<crate::service::Layout>,
    cancel: CancellationToken,
    poll: Duration,
    retirement_grace: Duration,
    worker: F,
) -> Result<()>
where
    F: Fn(crate::service::Layout, String, CancellationToken) -> Fut,
    Fut: Future<Output = Result<()>> + Send + 'static,
{
    let mut workers = HashMap::<Key, Running>::new();
    let mut keys = HashMap::<Id, Key>::new();
    let mut tasks = JoinSet::new();
    let mut tick = tokio::time::interval(poll);
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        let retirement = workers
            .values()
            .filter_map(|w| match w.retiring {
                Some(Retirement::Waiting(at)) => Some(at),
                _ => None,
            })
            .min();
        tokio::select! {
            _=cancel.cancelled()=>break,
            _=tick.tick()=>{
                let wanted=discover(&layouts);
                let desired:HashSet<_>=wanted.iter().map(|r|r.key.clone()).collect();
                for (key,running) in &mut workers {
                if !desired.contains(key) && running.retiring.is_none(){
                    running.cancel.cancel();running.retiring=Some(Retirement::Waiting(Instant::now()+retirement_grace));
                }
            }
                for registration in wanted {
                    if workers.contains_key(&registration.key){continue;}
                    let stop=cancel.child_token();
                    let abort=tasks.spawn(worker(registration.layout,registration.key.id.clone(),stop.clone()));
                let task=abort.id();
                    keys.insert(task,registration.key.clone());
                    workers.insert(registration.key,Running{cancel:stop,task,abort,retiring:None});
                }
            },
            _=async{match retirement{Some(at)=>tokio::time::sleep_until(at).await,None=>std::future::pending().await}}=>{
            let now=Instant::now();
            for running in workers.values_mut(){
                if matches!(running.retiring,Some(Retirement::Waiting(at)) if at<=now){running.abort.abort();running.retiring=Some(Retirement::Aborted);}
            }
        },
        joined=tasks.join_next_with_id(),if !tasks.is_empty()=>{
                let id=match joined {Some(Ok((id,result)))=>{if let Err(error)=result {tracing::debug!(reason=%error,"Desktop enrollment worker stopped; waiting for bounded rediscovery");}id},Some(Err(error))=>error.id(),None=>continue};
                if let Some(key)=keys.remove(&id){if workers.get(&key).is_some_and(|w|w.task==id){workers.remove(&key);}}
            }
        }
    }
    for worker in workers.values() {
        worker.cancel.cancel();
    }
    if tokio::time::timeout(Duration::from_secs(5), async {
        while tasks.join_next().await.is_some() {}
    })
    .await
    .is_err()
    {
        tasks.abort_all();
        while tasks.join_next().await.is_some() {}
    }
    Ok(())
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::{
        fs,
        os::unix::fs::PermissionsExt,
        sync::{Arc, Mutex},
    };
    fn fixture_temp() -> tempfile::TempDir {
        let temp = tempfile::tempdir().unwrap();
        fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700)).unwrap();
        temp
    }
    fn layout(root: &Path, name: &str) -> crate::service::Layout {
        let root = root.join(name);
        fs::create_dir_all(&root).unwrap();
        crate::service::Layout {
            user: true,
            state: root.join("native"),
            releases: root.join("releases"),
            units: root.join("units"),
        }
    }
    fn publish(
        layout: &crate::service::Layout,
        id: &str,
        enabled: bool,
        private: bool,
        state: &str,
    ) {
        let root = crate::service::readable::directory(layout).unwrap();
        fs::create_dir_all(&root).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o755)).unwrap();
        let record = crate::service::readable::Record {
            format_version: 1,
            id: id.into(),
            machine_id: id[..24].into(),
            email: String::new(),
            gateway: "http://127.0.0.1".into(),
            private,
            enabled,
            active: Some(true),
            state: state.into(),
            agent_version: "fixture".into(),
            ports: 0,
            route: String::new(),
            updated_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            strategy: Default::default(),
            strategy_override: false,
            private_status: None,
        };
        let p = root.join(format!("{id}.json"));
        fs::write(&p, serde_json::to_vec(&record).unwrap()).unwrap();
        fs::set_permissions(p, fs::Permissions::from_mode(0o644)).unwrap();
    }
    async fn wait_for(mut predicate: impl FnMut() -> bool) {
        tokio::time::timeout(Duration::from_secs(2), async {
            while !predicate() {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .unwrap();
    }
    #[test]
    fn discovery_filters_nonpublic_disabled_uninstalled_and_all_duplicate_layout_ids() {
        let temp = fixture_temp();
        let a = layout(temp.path(), "a");
        let b = layout(temp.path(), "b");
        let unique = "a".repeat(64);
        let duplicate = "b".repeat(64);
        publish(&a, &unique, true, false, "ready");
        publish(&a, &duplicate, true, false, "ready");
        publish(&b, &duplicate, true, false, "ready");
        publish(&a, &"c".repeat(64), false, false, "ready");
        publish(&a, &"d".repeat(64), true, true, "ready");
        publish(&a, &"e".repeat(64), true, false, "uninstalled");
        let found = discover(&[a, b]);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].key.id, unique);
    }
    #[test]
    fn explicit_selector_remains_unique_and_existing_per_id_lock_is_retained() {
        let temp = fixture_temp();
        let a = layout(temp.path(), "a");
        let b = layout(temp.path(), "b");
        let first = "a".repeat(64);
        let second = "c".repeat(64);
        publish(&a, &first, true, false, "ready");
        publish(&b, &second, true, false, "ready");
        assert_eq!(
            super::super::select_registration(vec![a.clone(), b.clone()], Some(&first[..8]))
                .unwrap()
                .1,
            first
        );
        assert!(super::super::select_registration(vec![a, b], None).is_err());
        let root = temp.path().join("keyboard");
        let old = super::super::desktop_lease(&root, &first).unwrap();
        assert!(root.join(format!("{first}.lock")).is_file());
        assert!(super::super::desktop_lease(&root, &first).is_err());
        assert!(super::super::desktop_lease(&root, &second).is_ok());
        drop(old);
        assert!(super::super::desktop_lease(&root, &first).is_ok());
    }
    #[tokio::test]
    async fn hot_add_disable_remove_uninstall_and_parent_cancel_reap_owned_workers() {
        let temp = fixture_temp();
        let a = layout(temp.path(), "a");
        let first = "a".repeat(64);
        let second = "c".repeat(64);
        publish(&a, &first, true, false, "ready");
        let active = Arc::new(Mutex::new(HashSet::new()));
        let starts = Arc::new(Mutex::new(HashMap::<String, usize>::new()));
        let stop = CancellationToken::new();
        let state = active.clone();
        let count = starts.clone();
        let task = tokio::spawn(supervise_with(
            vec![a.clone()],
            stop.clone(),
            Duration::from_millis(20),
            Duration::from_millis(40),
            move |layout, id, cancel| {
                let state = state.clone();
                let count = count.clone();
                async move {
                    let key = (layout.state, id.clone());
                    assert!(state.lock().unwrap().insert(key.clone()));
                    *count.lock().unwrap().entry(id).or_default() += 1;
                    cancel.cancelled().await;
                    state.lock().unwrap().remove(&key);
                    Ok(())
                }
            },
        ));
        wait_for(|| active.lock().unwrap().len() == 1).await;
        publish(&a, &second, true, false, "ready");
        wait_for(|| active.lock().unwrap().len() == 2).await;
        publish(&a, &first, false, false, "ready");
        wait_for(|| active.lock().unwrap().len() == 1).await;
        publish(&a, &first, true, false, "ready");
        wait_for(|| active.lock().unwrap().len() == 2).await;
        fs::remove_file(
            crate::service::readable::directory(&a)
                .unwrap()
                .join(format!("{second}.json")),
        )
        .unwrap();
        wait_for(|| active.lock().unwrap().len() == 1).await;
        publish(&a, &first, true, false, "uninstalled");
        wait_for(|| active.lock().unwrap().is_empty()).await;
        publish(&a, &second, true, false, "ready");
        wait_for(|| active.lock().unwrap().len() == 1).await;
        stop.cancel();
        task.await.unwrap().unwrap();
        assert!(active.lock().unwrap().is_empty());
        assert_eq!(starts.lock().unwrap()[&first], 2);
    }
    #[tokio::test]
    async fn duplicate_added_in_another_layout_retires_all_copies_without_cross_routing() {
        let temp = fixture_temp();
        let a = layout(temp.path(), "a");
        let b = layout(temp.path(), "b");
        let duplicate = "a".repeat(64);
        let unique = "c".repeat(64);
        publish(&a, &duplicate, true, false, "ready");
        publish(&a, &unique, true, false, "ready");
        let active = Arc::new(Mutex::new(HashSet::new()));
        let state = active.clone();
        let starts = Arc::new(Mutex::new(Vec::new()));
        let started = starts.clone();
        let stop = CancellationToken::new();
        let task = tokio::spawn(supervise_with(
            vec![a.clone(), b.clone()],
            stop.clone(),
            Duration::from_millis(20),
            Duration::from_millis(40),
            move |layout, id, cancel| {
                let active = state.clone();
                let starts = started.clone();
                async move {
                    let key = (layout.state, id);
                    assert!(active.lock().unwrap().insert(key.clone()));
                    starts.lock().unwrap().push(key.clone());
                    cancel.cancelled().await;
                    active.lock().unwrap().remove(&key);
                    Ok(())
                }
            },
        ));
        wait_for(|| active.lock().unwrap().len() == 2).await;
        publish(&b, &duplicate, true, false, "ready");
        wait_for(|| active.lock().unwrap().len() == 1).await;
        assert!(active.lock().unwrap().iter().all(|(_, id)| id == &unique));
        fs::remove_file(
            crate::service::readable::directory(&b)
                .unwrap()
                .join(format!("{duplicate}.json")),
        )
        .unwrap();
        wait_for(|| active.lock().unwrap().len() == 2).await;
        stop.cancel();
        task.await.unwrap().unwrap();
        assert!(active.lock().unwrap().is_empty());
        assert!(starts
            .lock()
            .unwrap()
            .iter()
            .all(|(state, _)| state == &a.state));
    }
    #[tokio::test]
    async fn retirement_aborts_uncooperative_worker_and_reclaims_its_lock_without_stopping_sibling()
    {
        let temp = fixture_temp();
        let layout = layout(temp.path(), "layout");
        let stuck = "a".repeat(64);
        let sibling = "c".repeat(64);
        publish(&layout, &stuck, true, false, "ready");
        publish(&layout, &sibling, true, false, "ready");
        let root = temp.path().join("keyboard");
        let locked_root = root.clone();
        let active = Arc::new(Mutex::new(HashSet::new()));
        let state = active.clone();
        let starts = Arc::new(Mutex::new(HashMap::<String, usize>::new()));
        let counts = starts.clone();
        let stop = CancellationToken::new();
        let first = stuck.clone();
        struct Owned {
            id: String,
            active: Arc<Mutex<HashSet<String>>>,
            _lease: std::fs::File,
        }
        impl Drop for Owned {
            fn drop(&mut self) {
                self.active.lock().unwrap().remove(&self.id);
            }
        }
        let task = tokio::spawn(supervise_with(
            vec![layout.clone()],
            stop.clone(),
            Duration::from_millis(20),
            Duration::from_millis(40),
            move |_, id, cancel| {
                let root = locked_root.clone();
                let active = state.clone();
                let starts = counts.clone();
                let stuck = first.clone();
                async move {
                    let lease = super::super::desktop_lease(&root, &id)?;
                    assert!(active.lock().unwrap().insert(id.clone()));
                    let generation = {
                        let mut counts = starts.lock().unwrap();
                        let count = counts.entry(id.clone()).or_default();
                        *count += 1;
                        *count
                    };
                    let _owned = Owned {
                        id: id.clone(),
                        active,
                        _lease: lease,
                    };
                    if id == stuck && generation == 1 {
                        std::future::pending::<()>().await;
                    } else {
                        cancel.cancelled().await;
                    }
                    Ok(())
                }
            },
        ));
        wait_for(|| active.lock().unwrap().len() == 2).await;
        assert!(super::super::desktop_lease(&root, &stuck).is_err());
        publish(&layout, &stuck, false, false, "ready");
        wait_for(|| !active.lock().unwrap().contains(&stuck)).await;
        assert!(active.lock().unwrap().contains(&sibling));
        assert!(super::super::desktop_lease(&root, &stuck).is_ok());
        publish(&layout, &stuck, true, false, "ready");
        wait_for(|| active.lock().unwrap().len() == 2).await;
        assert_eq!(starts.lock().unwrap()[&stuck], 2);
        assert_eq!(starts.lock().unwrap()[&sibling], 1);
        stop.cancel();
        task.await.unwrap().unwrap();
        assert!(active.lock().unwrap().is_empty());
        assert!(super::super::desktop_lease(&root, &stuck).is_ok());
    }
    #[tokio::test]
    async fn distinct_registrations_reach_only_their_own_real_local_brokers_without_input() {
        use tokio::{
            io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader},
            net::UnixListener,
        };
        let temp = fixture_temp();
        let a = layout(temp.path(), "a");
        let b = layout(temp.path(), "b");
        let first = "a".repeat(64);
        let second = "c".repeat(64);
        publish(&a, &first, true, false, "ready");
        publish(&b, &second, true, false, "ready");
        let mut brokers = JoinSet::new();
        let seen = Arc::new(Mutex::new(HashSet::new()));
        for (layout, id) in [(a.clone(), first.clone()), (b.clone(), second.clone())] {
            let listener =
                UnixListener::bind(crate::exposure_broker::endpoint(&layout, &id).unwrap())
                    .unwrap();
            let seen = seen.clone();
            brokers.spawn(async move {
                let (mut stream, _) = listener.accept().await.unwrap();
                let mut line = String::new();
                BufReader::new(&mut stream)
                    .read_line(&mut line)
                    .await
                    .unwrap();
                assert_eq!(
                    serde_json::from_str::<Value>(&line).unwrap(),
                    json!({"operation":"keyboard_host"})
                );
                stream
                    .write_all(b"{\"type\":\"policy\",\"direct\":false}\n")
                    .await
                    .unwrap();
                seen.lock().unwrap().insert(id);
                let mut rest = Vec::new();
                stream.read_to_end(&mut rest).await.unwrap();
                assert!(
                    rest.is_empty(),
                    "no active input or capture command was requested"
                );
            });
        }
        let stop = CancellationToken::new();
        let task = tokio::spawn(supervise_with(
            vec![a, b],
            stop.clone(),
            Duration::from_millis(20),
            Duration::from_millis(40),
            |layout, id, cancel| async move { super::super::session(&layout, &id, cancel).await },
        ));
        wait_for(|| seen.lock().unwrap().len() == 2).await;
        assert_eq!(*seen.lock().unwrap(), HashSet::from([first, second]));
        stop.cancel();
        task.await.unwrap().unwrap();
        while let Some(result) = brokers.join_next().await {
            result.unwrap();
        }
    }
}
