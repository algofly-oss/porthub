use super::*;
use anyhow::{ensure, Context, Result};
use axum::{
    http::header,
    response::{IntoResponse, Response},
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use porthub_forward_ssh::Master;
use subtle::ConstantTimeEq;

pub(super) fn token(master: &Master, owner: ObjectId, id: ObjectId) -> ApiResult<String> {
    let bytes = master
        .launcher_key(&owner.to_hex(), &id.to_hex())
        .map_err(unavailable)?;
    Ok(URL_SAFE_NO_PAD.encode(bytes.as_ref()))
}

#[derive(Deserialize, Default, Clone, Copy)]
#[serde(rename_all = "lowercase")]
enum Shell {
    #[default]
    Posix,
    Powershell,
}

#[derive(Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub(super) struct Options {
    #[serde(default)]
    shell: Shell,
}

pub(super) async fn download(
    State(app): State<Arc<App>>,
    Path(id): Path<String>,
    axum::extract::Query(options): axum::extract::Query<Options>,
    headers: HeaderMap,
) -> ApiResult<Response> {
    let denied = || ApiError::new(StatusCode::UNAUTHORIZED, "Invalid launcher credential.");
    let id = ObjectId::parse_str(id).map_err(|_| denied())?;
    let mut values = headers.get_all(header::AUTHORIZATION).iter();
    let bearer = values
        .next()
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .filter(|v| v.len() == 43)
        .ok_or_else(denied)?;
    if values.next().is_some() {
        return Err(denied());
    }
    let row = app
        .collection(COLLECTION)
        .find_one(doc! {"_id":id,"state":"active"})
        .await?
        .ok_or_else(denied)?;
    let owner = row.get_object_id("workspace_id").map_err(|_| denied())?;
    let master = app.forward_keys().await.map_err(unavailable)?;
    let expected = token(master, owner, id)?;
    if !bool::from(expected.as_bytes().ct_eq(bearer.as_bytes())) {
        return Err(denied());
    }
    let (pem, key) = master
        .credentials(&owner.to_hex(), &id.to_hex())
        .map_err(unavailable)?;
    if row.get_str("public_key") != Ok(key.as_str()) {
        return Err(denied());
    }
    let (gateway, port) = crate::port_forward_auth::endpoint(&app).map_err(unavailable)?;
    let host_key = master.host_public_key().map_err(unavailable)?;
    let script =
        render(&gateway, port, id, &pem, &host_key, &row, options.shell).map_err(unavailable)?;
    Ok((
        [
            (header::CACHE_CONTROL, "private, no-store"),
            (header::CONTENT_TYPE, "text/plain; charset=utf-8"),
            (header::X_CONTENT_TYPE_OPTIONS, "nosniff"),
        ],
        script,
    )
        .into_response())
}

fn port(mapping: &Document, name: &str) -> Result<u16> {
    let value = mapping
        .get_i32(name)
        .map(i64::from)
        .or_else(|_| mapping.get_i64(name))?;
    let value = u16::try_from(value)?;
    ensure!(value != 0, "invalid forwarding port");
    Ok(value)
}

fn render(
    gateway: &str,
    ssh_port: u16,
    id: ObjectId,
    pem: &str,
    host_key: &str,
    row: &Document,
    shell: Shell,
) -> Result<String> {
    ensure!(
        !gateway.is_empty()
            && !gateway.starts_with('-')
            && gateway
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || b".:-".contains(&c)),
        "invalid SSH gateway"
    );
    let mut rules = Vec::new();
    let mappings = row.get_array("mappings")?;
    ensure!((1..=32).contains(&mappings.len()), "invalid saved mappings");
    for m in mappings {
        let m = m.as_document().context("invalid mapping")?;
        rules.push(match m.get_str("direction")? {
            "host" => {
                ensure!(mappings.len() == 1, "mixed host mappings");
                format!(
                    "-o 'PermitRemoteOpen=127.0.0.1:*' -R 127.0.0.1:{}",
                    port(m, "gatewayPort")?
                )
            }
            "remote" => format!(
                "-R 127.0.0.1:{}:127.0.0.1:{}",
                port(m, "gatewayPort")?,
                port(m, "clientPort")?
            ),
            "local" => {
                let target = m.get_str("target")?;
                ensure!(
                    target
                        .strip_prefix("host-")
                        .is_some_and(porthub_forward_ssh::valid_id),
                    "invalid saved target"
                );
                format!(
                    "-L 127.0.0.1:{}:{target}:{}",
                    port(m, "clientPort")?,
                    port(m, "servicePort")?
                )
            }
            _ => anyhow::bail!("unknown saved forwarding direction"),
        });
    }
    let rules = rules.join(" ");
    let args=format!("-o BatchMode=yes -o ConnectTimeout=10 -o HostKeyAlgorithms=ssh-ed25519 -o IdentitiesOnly=yes -o IdentityAgent=none -o PreferredAuthentications=publickey -o ExitOnForwardFailure=yes -o HostKeyAlias=porthub-forward-gateway -o StrictHostKeyChecking=yes -o UpdateHostKeys=no -o CheckHostIP=no -o ServerAliveInterval=15 -o ServerAliveCountMax=3 -p {ssh_port} -l pf-{id} {rules}");
    if matches!(shell, Shell::Powershell) {
        return Ok(format!(
            r#"& {{
    $ErrorActionPreference = 'Stop'
    $key = $null
    $kh = $null
    try {{
        $key = [IO.Path]::GetTempFileName()
        $kh = [IO.Path]::GetTempFileName()
        $sid = [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value
        & icacls.exe $key /inheritance:r /grant:r "*${{sid}}:(F)" | Out-Null
        if ($LASTEXITCODE) {{ throw 'Unable to secure the SSH identity' }}
        [IO.File]::WriteAllText($key, ((@({lines}) -join [char]10) + [char]10), [Text.Encoding]::ASCII)
        [IO.File]::WriteAllText($kh, ('porthub-forward-gateway {host_key}' + [char]10), [Text.Encoding]::ASCII)
        Push-Location -LiteralPath ([IO.Path]::GetDirectoryName($kh))
        try {{
            & ssh.exe -F NUL -N -T -a -x -n -i $key -o GlobalKnownHostsFile=none -o ("UserKnownHostsFile=./" + [IO.Path]::GetFileName($kh)) {args} '{gateway}'
            if ($LASTEXITCODE) {{ throw "SSH exited with code $LASTEXITCODE" }}
        }} finally {{ Pop-Location }}
    }} finally {{
        try {{ if ($key) {{ [IO.File]::Delete($key) }} }}
        finally {{ if ($kh) {{ [IO.File]::Delete($kh) }} }}
    }}
}}
"#,
            lines = pem
                .lines()
                .map(|line| format!("'{line}'"))
                .collect::<Vec<_>>()
                .join(",")
        ));
    }
    Ok(format!(
        r#"#!/bin/sh
porthub_connect() (
    set -eu
    umask 077
    tmp=$(mktemp -d "${{TMPDIR:-/tmp}}/porthub-ssh.XXXXXXXX") || exit 1
    trap 'rm -rf -- "$tmp"' 0
    trap 'exit 129' HUP
    trap 'exit 130' INT
    trap 'exit 143' TERM
    cd -- "$tmp"
    cat > identity <<'PORTHUB_IDENTITY'
{pem}
PORTHUB_IDENTITY
    cat > known_hosts <<'PORTHUB_GATEWAY'
porthub-forward-gateway {host_key}
PORTHUB_GATEWAY
    ssh -F /dev/null -N -T -a -x -n -i identity -o GlobalKnownHostsFile=/dev/null -o UserKnownHostsFile=known_hosts {args} '{gateway}'
)
porthub_connect
"#,
        pem = pem.trim_end()
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::extract::Query;
    #[cfg(unix)]
    #[test]
    fn rendered_script_uses_pinned_identity_and_removes_temporary_files() -> Result<()> {
        use std::os::unix::fs::PermissionsExt;
        use std::process::Command;
        let dir = tempfile::tempdir()?;
        let bin = dir.path().join("ssh");
        std::fs::write(
            &bin,
            r#"#!/bin/sh
set -eu
test -s identity
test -s known_hosts
test "$(cat known_hosts)" = 'porthub-forward-gateway fixture'
printf '%s\n' "$@"
"#,
        )?;
        std::fs::set_permissions(&bin, std::fs::Permissions::from_mode(0o755))?;
        let id = ObjectId::new();
        let local_target = format!("host-{id}");
        let both = doc! {"mappings":[{"direction":"remote","clientPort":8888,"gatewayPort":27101},{"direction":"local","clientPort":3333,"target":&local_target,"servicePort":22}]};
        let script = render(
            "ssh.example",
            443,
            id,
            "dummy key",
            "fixture",
            &both,
            Shell::Posix,
        )?;
        let tmp = dir.path().join("temp with spaces");
        std::fs::create_dir(&tmp)?;
        let path = format!("{}:{}", dir.path().display(), std::env::var("PATH")?);
        let child = Command::new("sh")
            .arg("-c")
            .arg(script)
            .env("TMPDIR", &tmp)
            .env("PATH", path)
            .output()?;
        ensure!(
            child.status.success(),
            "{}",
            String::from_utf8_lossy(&child.stderr)
        );
        let args = String::from_utf8(child.stdout)?;
        assert!(args.contains("-R\n127.0.0.1:27101:127.0.0.1:8888"));
        assert!(args.contains(&format!("-L\n127.0.0.1:3333:{local_target}:22")));
        assert!(args.contains("StrictHostKeyChecking=yes"));
        assert!(std::fs::read_dir(tmp)?.next().is_none());
        assert!(render(
            "good;false",
            443,
            id,
            "dummy",
            "fixture",
            &both,
            Shell::Posix
        )
        .is_err());
        Ok(())
    }

    #[tokio::test]
    #[ignore = "uses an isolated MongoDB database"]
    async fn scoped_reusable_launchers_follow_grant_lifetime() -> Result<()> {
        let db = mongodb::Client::with_uri_str(std::env::var("PORTHUB_TEST_MONGO_URI")?)
            .await?
            .database(&format!("ph_launcher_{}", ObjectId::new()));
        let app = Arc::new(App::new(
            crate::config::Config {
                private_relay_tls_origin: Some("https://ssh.example:8243".into()),
                ..Default::default()
            },
            db.clone(),
        ));
        let result=async {
            let dir=tempfile::tempdir()?;
            let master=Master::open(&dir.path().join("master"))?;
            let (id,owner)=(ObjectId::new(),ObjectId::new());
            let (pem,key)=master.credentials(&owner.to_hex(),&id.to_hex())?;
            let auth=|owner|->Result<HeaderMap>{let mut h=HeaderMap::new();let token=token(&master,owner,id).map_err(|e|anyhow::anyhow!("{}",e.detail))?;h.insert(header::AUTHORIZATION,format!("Bearer {token}").parse()?);Ok(h)};
            let headers=auth(owner)?;
            let foreign=auth(ObjectId::new())?;
            app.forward_keys.set(master).map_err(|_|anyhow::anyhow!("master already initialized"))?;
            let grant=doc!{"_id":id,"workspace_id":owner,"state":"active","public_key":key,"mappings":[{"direction":"host","gatewayPort":27001}]};
            app.collection(COLLECTION).insert_one(grant).await?;
            let get=|shell,h| download(State(app.clone()),Path(id.to_hex()),Query(Options{shell}),h);
            for shell in [Shell::Posix,Shell::Posix,Shell::Powershell] {
                let resp=get(shell,headers.clone()).await.map_err(|e|anyhow::anyhow!("{}",e.detail))?;
                assert_eq!(resp.headers()[header::CACHE_CONTROL],"private, no-store");
                let body=axum::body::to_bytes(resp.into_body(),32768).await?;
                let script=std::str::from_utf8(&body)?;
                assert!(script.contains("-o StrictHostKeyChecking=yes"));
                assert!(script.contains("-R 127.0.0.1:27001"));
                assert!(script.contains(pem.lines().nth(1).unwrap()));
                match shell {Shell::Powershell=>assert!(script.contains("icacls.exe")),Shell::Posix=>assert!(script.ends_with("porthub_connect\n"))}
            }
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let socket=tokio::net::TcpListener::bind("127.0.0.1:0").await?;
                let url=format!("http://{}/api/port-forwards/{id}/launcher", socket.local_addr()?);
                let service=router().with_state(app.clone());
                let _server=tokio_util::task::AbortOnDropHandle::new(tokio::spawn(async move{axum::serve(socket,service).await}));
                let shim=dir.path().join("ssh");
                std::fs::write(&shim, r#"#!/bin/sh
set -eu
test -s identity
test -s known_hosts
test "$(ls -ld . | cut -c 2-10)" = 'rwx------'
test "$(ls -l identity | cut -c 2-10)" = 'rw-------'
printf '%s\n' "$@"
"#)?;
                std::fs::set_permissions(&shim,std::fs::Permissions::from_mode(0o755))?;
                let scratch=dir.path().join("scratch");
                std::fs::create_dir(&scratch)?;
                for _ in 0..2 {
                    let out=tokio::process::Command::new("sh").args(["-c",r#"curl -fsS -H "$HEADER" "$URL" | sh"#])
                        .env("URL",&url).env("HEADER",format!("Authorization: {}",headers[header::AUTHORIZATION].to_str()?))
                        .env("TMPDIR",&scratch).env("PATH",format!("{}:{}",dir.path().display(),std::env::var("PATH")?)).output().await?;
                    ensure!(out.status.success(),"launcher command failed");
                    assert!(String::from_utf8(out.stdout)?.contains("-R\n127.0.0.1:27001"));
                    assert!(std::fs::read_dir(&scratch)?.next().is_none());
                }
            }
            for invalid in [HeaderMap::new(),foreign] {
                assert_eq!(get(Shell::Posix,invalid).await.unwrap_err().status,StatusCode::UNAUTHORIZED);
            }
            let col=app.collection(COLLECTION);
            col.update_one(doc!{"_id":id},doc!{"$set":{"public_key":"wrong"}}).await?;
            assert_eq!(get(Shell::Posix,headers.clone()).await.unwrap_err().status,StatusCode::UNAUTHORIZED);
            col.delete_one(doc!{"_id":id}).await?;
            assert_eq!(get(Shell::Posix,headers).await.unwrap_err().status,StatusCode::UNAUTHORIZED);
            Ok::<_,anyhow::Error>(())
        }.await;
        db.drop().await?;
        result
    }
}
