//! Native Windows Service Control Manager support and service entry point.
use super::{Manager, Spec, State, OPERATION_TIMEOUT};
use anyhow::{ensure, Context, Result};
use async_trait::async_trait;
use std::{
    ffi::{OsStr, OsString},
    path::PathBuf,
    sync::OnceLock,
    time::Duration,
};
use tokio_util::sync::CancellationToken;
use windows_service::{
    define_windows_service,
    service::{
        ServiceAccess, ServiceControl, ServiceControlAccept, ServiceErrorControl, ServiceExitCode,
        ServiceInfo, ServiceStartType, ServiceState, ServiceStatus, ServiceType,
    },
    service_control_handler::{self, ServiceControlHandlerResult},
    service_dispatcher,
    service_manager::{ServiceManager, ServiceManagerAccess},
};

static DISPATCH_NAME: OnceLock<String> = OnceLock::new();
static PROFILE: OnceLock<PathBuf> = OnceLock::new();
static STOP: OnceLock<CancellationToken> = OnceLock::new();
static LOGS: OnceLock<crate::logs::Buffer> = OnceLock::new();

pub struct Windows;

impl Windows {
    pub fn connect(user: bool) -> Result<Self> {
        ensure!(!user, "per-user Windows services are not supported");
        Ok(Self)
    }
}

fn scm(access: ServiceManagerAccess) -> Result<ServiceManager> {
    Ok(ServiceManager::local_computer(None::<&str>, access)?)
}

fn service(
    spec: &Spec,
    access: ServiceAccess,
) -> Result<Option<windows_service::service::Service>> {
    let manager = scm(ServiceManagerAccess::CONNECT)?;
    let access = access | ServiceAccess::QUERY_CONFIG | ServiceAccess::QUERY_STATUS;
    match manager.open_service(&spec.service, access) {
        Ok(service) => Ok(Some(service)),
        Err(windows_service::Error::Winapi(error)) if error.raw_os_error() == Some(1060) => {
            Ok(None)
        }
        Err(error) => Err(error.into()),
    }
}

fn service_info(spec: &Spec, start_type: ServiceStartType) -> Result<ServiceInfo> {
    let profile = spec
        .profile
        .to_str()
        .context("Windows service profile path must be Unicode")?;
    ensure!(
        spec.profile.is_absolute(),
        "Windows service profile must be absolute"
    );
    Ok(ServiceInfo {
        name: OsString::from(&spec.service),
        display_name: OsString::from(format!("PortHub agent {}", &spec.identity[..12])),
        service_type: ServiceType::OWN_PROCESS,
        start_type,
        error_control: ServiceErrorControl::Normal,
        executable_path: spec.executable.clone(),
        launch_arguments: vec![
            "__windows-service".into(),
            format!("--service-name={}", spec.service).into(),
            format!("--service-id={}", spec.identity).into(),
            format!("--profile={profile}").into(),
        ],
        dependencies: vec![],
        account_name: None,
        account_password: None,
    })
}

fn verify_owned(spec: &Spec, service: &windows_service::service::Service) -> Result<ServiceState> {
    let config = service.query_config()?;
    let command = config.executable_path.to_string_lossy();
    let expected_profile = spec
        .profile
        .to_str()
        .context("Windows service profile path must be Unicode")?;
    ensure!(
        config.service_type == ServiceType::OWN_PROCESS
            && config.display_name
                == OsString::from(format!("PortHub agent {}", &spec.identity[..12]))
            && command.contains(&spec.executable.to_string_lossy().to_string())
            && command.contains("__windows-service")
            && command.contains(&format!("--service-id={}", spec.identity))
            && command.contains(&format!("--profile={expected_profile}")),
        "Windows service name is occupied by a foreign registration"
    );
    Ok(service.query_status()?.current_state)
}

fn with_owned_service<T>(
    spec: &Spec,
    access: ServiceAccess,
    f: impl FnOnce(&windows_service::service::Service) -> Result<T>,
) -> Result<Option<T>> {
    let Some(service) = service(spec, access)? else {
        return Ok(None);
    };
    verify_owned(spec, &service)?;
    f(&service).map(Some)
}

async fn wait_state(spec: &Spec, expected: ServiceState) -> Result<()> {
    tokio::time::timeout(OPERATION_TIMEOUT, async {
        loop {
            if with_owned_service(spec, ServiceAccess::QUERY_STATUS, |service| {
                Ok(service.query_status()?.current_state == expected)
            })?
            .unwrap_or(false)
            {
                return Ok(());
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    })
    .await
    .context("Windows service operation timed out")?
}

#[async_trait]
impl Manager for Windows {
    async fn state(&self, spec: &Spec) -> Result<State> {
        let Some((current, start_type)) = with_owned_service(
            spec,
            ServiceAccess::QUERY_CONFIG | ServiceAccess::QUERY_STATUS,
            |service| {
                Ok((
                    service.query_status()?.current_state,
                    service.query_config()?.start_type,
                ))
            },
        )?
        else {
            return Ok(State {
                installed: false,
                enabled: false,
                active: false,
            });
        };
        Ok(State {
            installed: true,
            enabled: start_type == ServiceStartType::AutoStart,
            active: current == ServiceState::Running,
        })
    }

    async fn reload(&self) -> Result<()> {
        Ok(())
    }

    async fn enable(&self, spec: &Spec) -> Result<()> {
        if with_owned_service(spec, ServiceAccess::CHANGE_CONFIG, |_| Ok(()))?.is_some() {
            let service = service(spec, ServiceAccess::CHANGE_CONFIG)?
                .context("Windows service disappeared")?;
            service.change_config(&service_info(spec, ServiceStartType::AutoStart)?)?;
        } else {
            let manager =
                scm(ServiceManagerAccess::CONNECT | ServiceManagerAccess::CREATE_SERVICE)?;
            manager.create_service(
                &service_info(spec, ServiceStartType::AutoStart)?,
                ServiceAccess::QUERY_CONFIG
                    | ServiceAccess::QUERY_STATUS
                    | ServiceAccess::START
                    | ServiceAccess::STOP
                    | ServiceAccess::CHANGE_CONFIG
                    | ServiceAccess::DELETE,
            )?;
        }
        Ok(())
    }

    async fn disable(&self, spec: &Spec) -> Result<()> {
        let Some(service) = service(spec, ServiceAccess::CHANGE_CONFIG)? else {
            return Ok(());
        };
        verify_owned(spec, &service)?;
        service.change_config(&service_info(spec, ServiceStartType::Disabled)?)?;
        Ok(())
    }

    async fn start(&self, spec: &Spec) -> Result<()> {
        let Some(current) = with_owned_service(
            spec,
            ServiceAccess::START | ServiceAccess::QUERY_STATUS,
            |service| Ok(service.query_status()?.current_state),
        )?
        else {
            anyhow::bail!("Windows PortHub service is not installed")
        };
        if current != ServiceState::Running {
            let service =
                service(spec, ServiceAccess::START)?.context("Windows service disappeared")?;
            service.start::<&OsStr>(&[])?;
        }
        wait_state(spec, ServiceState::Running).await
    }

    async fn stop(&self, spec: &Spec) -> Result<()> {
        let Some(current) = with_owned_service(
            spec,
            ServiceAccess::STOP | ServiceAccess::QUERY_STATUS,
            |service| Ok(service.query_status()?.current_state),
        )?
        else {
            return Ok(());
        };
        if current != ServiceState::Stopped {
            let service =
                service(spec, ServiceAccess::STOP)?.context("Windows service disappeared")?;
            service.stop()?;
        }
        wait_state(spec, ServiceState::Stopped).await
    }

    async fn remove(&self, spec: &Spec) -> Result<()> {
        let Some(service) = service(spec, ServiceAccess::DELETE | ServiceAccess::QUERY_STATUS)?
        else {
            return Ok(());
        };
        ensure!(
            verify_owned(spec, &service)? == ServiceState::Stopped,
            "Windows service must stop before it can be removed"
        );
        service.delete()?;
        Ok(())
    }
}

pub fn require_administrator() -> Result<()> {
    scm(ServiceManagerAccess::CONNECT | ServiceManagerAccess::CREATE_SERVICE)
        .context("run with administrator privileges to manage Windows services")?;
    Ok(())
}

pub fn run_dispatcher(
    name: String,
    identity: String,
    profile: PathBuf,
    logs: crate::logs::Buffer,
) -> Result<()> {
    ensure!(
        identity.len() == 64
            && identity.bytes().all(|byte| byte.is_ascii_hexdigit())
            && name == format!("porthub-{}", &identity[..24]),
        "invalid Windows PortHub service name"
    );
    ensure!(
        profile.is_absolute(),
        "Windows service profile must be absolute"
    );
    DISPATCH_NAME
        .set(name.clone())
        .map_err(|_| anyhow::anyhow!("Windows service dispatcher already started"))?;
    PROFILE
        .set(profile)
        .map_err(|_| anyhow::anyhow!("Windows service profile already set"))?;
    LOGS.set(logs)
        .map_err(|_| anyhow::anyhow!("Windows service logger already set"))?;
    STOP.set(CancellationToken::new())
        .map_err(|_| anyhow::anyhow!("Windows service stop controller already set"))?;
    service_dispatcher::start(&name, ffi_service_main)?;
    Ok(())
}

define_windows_service!(ffi_service_main, service_main);

fn service_main(_arguments: Vec<OsString>) {
    if let Err(error) = run_service() {
        tracing::error!(%error, "Windows PortHub service stopped after an error");
    }
}

fn run_service() -> Result<()> {
    let name = DISPATCH_NAME.get().context("service name missing")?.clone();
    let profile = PROFILE.get().context("service profile missing")?.clone();
    let stop = STOP
        .get()
        .context("service stop controller missing")?
        .clone();
    let logs = LOGS.get().context("service logger missing")?.clone();
    let handler_stop = stop.clone();
    let status = service_control_handler::register(&name, move |event| match event {
        ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
        ServiceControl::Stop | ServiceControl::Shutdown => {
            handler_stop.cancel();
            ServiceControlHandlerResult::NoError
        }
        _ => ServiceControlHandlerResult::NotImplemented,
    })?;
    status.set_service_status(ServiceStatus {
        service_type: ServiceType::OWN_PROCESS,
        current_state: ServiceState::StartPending,
        controls_accepted: ServiceControlAccept::empty(),
        exit_code: ServiceExitCode::Win32(0),
        checkpoint: 1,
        wait_hint: Duration::from_secs(15),
        process_id: None,
    })?;
    let runtime = (|| -> Result<tokio::runtime::Runtime> {
        crate::profile::Profile::load(&profile)?;
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()?;
        status.set_service_status(ServiceStatus {
            service_type: ServiceType::OWN_PROCESS,
            current_state: ServiceState::Running,
            controls_accepted: ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN,
            exit_code: ServiceExitCode::Win32(0),
            checkpoint: 0,
            wait_hint: Duration::default(),
            process_id: None,
        })?;
        Ok(runtime)
    })();
    let result = match runtime {
        Ok(runtime) => runtime.block_on(crate::runtime::run_with_logs(
            profile,
            stop,
            Default::default(),
            logs,
        )),
        Err(error) => Err(error),
    };
    if let Err(error) = &result {
        tracing::error!(%error, "Windows PortHub agent runtime failed");
    }
    status.set_service_status(ServiceStatus {
        service_type: ServiceType::OWN_PROCESS,
        current_state: ServiceState::Stopped,
        controls_accepted: ServiceControlAccept::empty(),
        exit_code: ServiceExitCode::Win32(if result.is_err() { 1 } else { 0 }),
        checkpoint: 0,
        wait_hint: Duration::default(),
        process_id: None,
    })?;
    result?;
    Ok(())
}
