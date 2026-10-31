//! Fixed-destination SSH ingress. Authentication stays in the API role; this
//! listener cannot choose arbitrary destinations or reach a host SSH daemon.
use std::{path::PathBuf, sync::Arc, time::Duration};
use tokio::{
    net::{TcpListener, UnixStream},
    sync::{watch, Semaphore},
    task::JoinSet,
};
pub async fn run(
    listener: TcpListener,
    socket: PathBuf,
    mut stop: watch::Receiver<bool>,
) -> std::io::Result<()> {
    let capacity = Arc::new(Semaphore::new(64));
    let mut tasks = JoinSet::new();
    loop {
        tokio::select! {
            changed=stop.changed()=>{if changed.is_err() || *stop.borrow() {break;}},
            _=tasks.join_next(),if !tasks.is_empty()=>{},
            connection=listener.accept()=>{
                let (mut stream,_)=connection?;
                let Ok(permit)=capacity.clone().try_acquire_owned() else {continue;};
                let socket=socket.clone();let mut stopping=stop.clone();
                let _=stream.set_nodelay(true);
                tasks.spawn(async move {
                    let _permit=permit;
                    let Ok(Ok(mut upstream))=tokio::time::timeout(Duration::from_secs(3),UnixStream::connect(socket)).await else {return;};
                    tokio::select! {_=stopping.changed()=>{},_=tokio::io::copy_bidirectional(&mut stream,&mut upstream)=>{}}
                });
            }
        }
    }
    tasks.abort_all();
    while tasks.join_next().await.is_some() {}
    Ok(())
}
