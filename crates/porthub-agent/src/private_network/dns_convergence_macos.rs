//! Observe configd's effective resolver publication; never flush unrelated DNS.
//! `/etc/resolver` file lifetime is not its asynchronous OS resolver lifetime.
use anyhow::{ensure,Result};
#[derive(Clone,Debug,PartialEq,Eq)]
pub(super) struct Endpoint{pub suffix:String,pub port:u16}
#[derive(Default)]struct Row{domain:Option<String>,servers:Vec<String>,port:Option<u16>}
fn rows(text:&str)->Result<Vec<Row>>{
    ensure!(text.len()<=262144,"macOS DNS observation exceeds bound");
    let mut rows=Vec::new();let mut row=None;
    for line in text.lines(){let line=line.trim();
        if line.starts_with("resolver #"){
            if let Some(old)=row.take(){rows.push(old);}
            ensure!(rows.len()<2048,"macOS DNS resolver count exceeds bound");row=Some(Row::default());continue;
        }
        let Some(current)=row.as_mut()else{continue};
        let Some((key,value))=line.split_once(':')else{continue};let key=key.trim();let value=value.trim();
        if key=="domain"{ensure!(current.domain.is_none()&&value.len()<=253,"ambiguous macOS DNS domain");current.domain=Some(value.trim_end_matches('.').to_ascii_lowercase());}
        else if key=="port"{ensure!(current.port.is_none(),"ambiguous macOS DNS port");current.port=Some(value.parse()?);}
        else if key.starts_with("nameserver["){ensure!(current.servers.len()<16&&value.len()<=128,"macOS DNS nameserver bound exceeded");current.servers.push(value.into());}
    }
    if let Some(old)=row{rows.push(old);}Ok(rows)
}
pub(super) fn converged(text:&str,present:&[Endpoint],absent:&[Endpoint])->Result<bool>{
    ensure!(present.len()<=2048&&absent.len()<=2048,"private DNS convergence scope exceeds bound");
    let rows=rows(text)?;
    for endpoint in present{
        let relevant:Vec<_>=rows.iter().filter(|r|r.domain.as_deref()==Some(endpoint.suffix.as_str())).collect();
        if relevant.is_empty()||relevant.iter().any(|r|r.port.unwrap_or(53)!=endpoint.port||r.servers!=["127.0.0.1"]){return Ok(false);}
    }
    for endpoint in absent{
        if rows.iter().any(|r|r.domain.as_deref()==Some(endpoint.suffix.as_str())&&r.port.unwrap_or(53)==endpoint.port&&r.servers.iter().any(|s|s=="127.0.0.1")){return Ok(false);}
    }Ok(true)
}
fn available(text:&str,suffixes:&[String],owned:&[Endpoint])->Result<bool>{
    ensure!(suffixes.len()<=2048&&owned.len()<=2048,"private DNS preflight scope exceeds bound");
    Ok(rows(text)?.iter().filter(|row|row.domain.as_ref().is_some_and(|domain|suffixes.contains(domain))).all(|row|
        owned.iter().any(|endpoint|row.domain.as_deref()==Some(endpoint.suffix.as_str())
            &&row.port.unwrap_or(53)==endpoint.port&&row.servers==["127.0.0.1"])))
}
#[cfg(target_os="macos")]
pub(super) async fn ensure_available(suffixes:&[String],owned:&[Endpoint])->Result<()>{
    ensure!(available(&observe().await?,suffixes,owned)?,"another resolver owns the requested private DNS suffix");Ok(())
}
#[cfg(target_os="macos")]
async fn observe()->Result<String>{
    use tokio::io::AsyncReadExt;
    let mut child=tokio::process::Command::new("/usr/sbin/scutil").arg("--dns").env_clear().env("PATH","/usr/bin:/bin:/usr/sbin:/sbin")
        .stdin(std::process::Stdio::null()).stdout(std::process::Stdio::piped()).stderr(std::process::Stdio::piped()).kill_on_drop(true).spawn()?;
    let mut stdout=child.stdout.take().unwrap().take(262145);let mut stderr=child.stderr.take().unwrap().take(4097);
    let result=tokio::time::timeout(std::time::Duration::from_secs(2),async{
        let mut out=Vec::new();let mut err=Vec::new();
        let (a,b,status)=tokio::join!(stdout.read_to_end(&mut out),stderr.read_to_end(&mut err),child.wait());
        a?;b?;ensure!(status?.success()&&out.len()<=262144&&err.len()<=4096,"cannot observe bounded macOS DNS state");
        Ok::<_,anyhow::Error>(String::from_utf8(out)?)
    }).await;
    match result{Ok(value)=>value,Err(_)=>{let _=child.kill().await;anyhow::bail!("macOS DNS observation timed out")}}
}
#[cfg(target_os="macos")]
pub(super) async fn wait(present:&[Endpoint],absent:&[Endpoint])->Result<()>{wait_with(present,absent,observe).await}
async fn wait_with<F,Fut>(present:&[Endpoint],absent:&[Endpoint],mut observation:F)->Result<()>
where F:FnMut()->Fut,Fut:std::future::Future<Output=Result<String>>{
    let deadline=tokio::time::Instant::now()+std::time::Duration::from_secs(8);
    loop{
        let text=tokio::time::timeout_at(deadline,observation()).await.map_err(|_|anyhow::anyhow!("macOS DNS convergence observation timed out"))??;
        if converged(&text,present,absent)?{return Ok(());}
        ensure!(tokio::time::Instant::now()<deadline,"macOS owned DNS publication/withdrawal did not converge");
        tokio::time::sleep_until(deadline.min(tokio::time::Instant::now()+std::time::Duration::from_millis(50))).await;
    }
}
#[cfg(test)]mod tests{
    use super::*;
    fn e()->Endpoint{Endpoint{suffix:"private.test".into(),port:53001}}
    fn text(port:u16,server:&str)->String{format!("DNS configuration\nresolver #1\n domain : private.test\n nameserver[0] : {server}\n port : {port}\n")}
    #[test]fn publication_requires_exact_effective_endpoint_not_file_or_foreign_domain(){
        assert!(!converged("DNS configuration",&[e()],&[]).unwrap());
        assert!(!converged(&text(53002,"127.0.0.1"),&[e()],&[]).unwrap());
        assert!(!converged(&text(53001,"192.0.2.1"),&[e()],&[]).unwrap());
        assert!(converged(&text(53001,"127.0.0.1"),&[e()],&[]).unwrap());
    }
    #[test]fn withdrawal_waits_old_effective_endpoint_and_preserves_foreign_state(){
        assert!(!converged(&text(53001,"127.0.0.1"),&[],&[e()]).unwrap());
        assert!(converged(&text(53002,"127.0.0.1"),&[],&[e()]).unwrap());
        assert!(converged(&text(53001,"192.0.2.1"),&[],&[e()]).unwrap());
    }
    #[test]fn duplicate_foreign_endpoint_cannot_fake_publication(){
        assert!(!converged(&(text(53001,"127.0.0.1")+&text(53001,"192.0.2.1")),&[e()],&[]).unwrap());
        assert!(converged(&"x".repeat(262145),&[],&[]).is_err());
    }
    #[test]fn private_namespace_preflight_rejects_foreign_resolvers_before_publication(){
        let suffixes=vec!["private.test".to_owned()];
        assert!(available("DNS configuration",&suffixes,&[]).unwrap());
        assert!(!available(&text(53001,"127.0.0.1"),&suffixes,&[]).unwrap());
        assert!(available(&text(53001,"127.0.0.1"),&suffixes,&[e()]).unwrap());
        assert!(!available(&text(53002,"127.0.0.1"),&suffixes,&[e()]).unwrap());
        assert!(!available(&(text(53001,"127.0.0.1")+&text(53001,"192.0.2.1")),&suffixes,&[e()]).unwrap());
    }
    #[tokio::test(start_paused=true)]async fn actual_waiter_retries_delayed_publication_then_stale_withdrawal(){
        let mut calls=0;let started=tokio::time::Instant::now();
        wait_with(&[e()],&[],||{calls+=1;let ready=calls>=4;async move{Ok(if ready{text(53001,"127.0.0.1")}else{String::new()})}}).await.unwrap();
        assert_eq!(calls,4);assert_eq!(started.elapsed(),std::time::Duration::from_millis(150));
        let mut calls=0;
        wait_with(&[],&[e()],||{calls+=1;let gone=calls>=3;async move{Ok(if gone{String::new()}else{text(53001,"127.0.0.1")})}}).await.unwrap();
        assert_eq!(calls,3);
    }
    #[tokio::test(start_paused=true)]async fn actual_waiter_fails_at_bound_for_stale_or_stalled_os(){
        let started=tokio::time::Instant::now();
        assert!(wait_with(&[],&[e()],||async{Ok(text(53001,"127.0.0.1"))}).await.is_err());
        assert_eq!(started.elapsed(),std::time::Duration::from_secs(8));
        let started=tokio::time::Instant::now();
        assert!(wait_with(&[e()],&[],||std::future::pending::<Result<String>>()).await.is_err());
        assert_eq!(started.elapsed(),std::time::Duration::from_secs(8));
    }

    #[test]fn actual_failed_native_scutil_shape_is_not_clean_with_files_absent(){
        // Owned-only block from run44019690222; no foreign network metadata.
        let endpoint=Endpoint{suffix:"u52d10b39280749b6877304a36b55dbce.phub".into(),port:57215};
        let actual="resolver #8\n  domain   : u52d10b39280749b6877304a36b55dbce.phub\n  nameserver[0] : 127.0.0.1\n  port     : 57215\n  timeout  : 2\n  flags    : Request A records, Request AAAA records\n  order    : 100\n\nDNS configuration (for scoped queries)\n";
        assert!(converged(actual,&[endpoint.clone()],&[]).unwrap());
        assert!(!converged(actual,&[],&[endpoint]).unwrap());
    }

}

#[cfg(all(test,target_os="macos"))]
pub(super) async fn fixture_owned_projection(endpoint:&Endpoint,stage:&str)->Result<()> {
    use std::io::Write;
    let text=observe().await?;let mut count=0u32;let mut request_a=false;let mut request_aaaa=false;let mut scoped=false;let mut reachable=false;let mut reach_bits=0u32;
    for block in text.split("resolver #").skip(1){
        let domain=block.lines().find_map(|l|l.trim().strip_prefix("domain").and_then(|s|s.trim().strip_prefix(':')).map(str::trim));
        if domain!=Some(endpoint.suffix.as_str()){continue}
        let servers:Vec<_>=block.lines().filter_map(|l|{let l=l.trim();if l.starts_with("nameserver["){l.split_once(':').map(|(_,v)|v.trim())}else{None}}).collect();
        let port=block.lines().find_map(|l|l.trim().strip_prefix("port").and_then(|s|s.trim().strip_prefix(':')).and_then(|s|s.trim().parse::<u16>().ok())).unwrap_or(53);
        if servers!=["127.0.0.1"]||port!=endpoint.port{continue}
        count+=1;
        for line in block.lines(){let line=line.trim();
            if let Some(value)=line.strip_prefix("flags").and_then(|s|s.trim().strip_prefix(':')){request_a|=value.contains("Request A records");request_aaaa|=value.contains("Request AAAA records");scoped|=value.contains("Scoped");}
            if let Some(value)=line.strip_prefix("reach").and_then(|s|s.trim().strip_prefix(':')){let word=value.split_whitespace().next().unwrap_or("");if let Some(hex)=word.strip_prefix("0x"){reach_bits|=u32::from_str_radix(hex,16)?;}reachable|=value.contains("Reachable")&&!value.contains("Not Reachable");}
        }
    }
    println!("native_owned_dns_config stage={stage} rows={count} request_a={request_a} request_aaaa={request_aaaa} scoped={scoped} reachable={reachable} reach_bits={reach_bits}");std::io::stdout().flush()?;Ok(())
}
