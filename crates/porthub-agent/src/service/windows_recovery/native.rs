use super::{ensure_recovery, Recovery, RESET_AFTER, RESTART_DELAYS};
use anyhow::Result;
use std::ffi::OsString;
use windows_service::service::{
    Service, ServiceAction, ServiceActionType, ServiceFailureActions, ServiceFailureResetPeriod,
};

fn actions() -> ServiceFailureActions {
    ServiceFailureActions {
        reset_period: ServiceFailureResetPeriod::After(RESET_AFTER),
        reboot_msg: Some(OsString::new()),
        command: Some(OsString::new()),
        actions: Some(
            RESTART_DELAYS
                .into_iter()
                .map(|delay| ServiceAction {
                    action_type: if delay.is_some() {
                        ServiceActionType::Restart
                    } else {
                        ServiceActionType::None
                    },
                    delay: delay.unwrap_or_default(),
                })
                .collect(),
        ),
    }
}
impl Recovery for Service {
    fn matches(&self) -> Result<bool> {
        let observed = self.get_failure_actions()?;
        let wanted = actions();
        Ok(observed.reset_period == wanted.reset_period
            && observed.actions == wanted.actions
            && observed.command.as_ref().is_none_or(|v| v.is_empty())
            && observed.reboot_msg.as_ref().is_none_or(|v| v.is_empty())
            && self.get_failure_actions_on_non_crash_failures()?)
    }
    fn configure(&self) -> Result<()> {
        self.update_failure_actions(actions())?;
        self.set_failure_actions_on_non_crash_failures(true)?;
        Ok(())
    }
}

pub(crate) fn ensure(service: &Service) -> Result<()> {
    ensure_recovery(service)
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::{ensure as check, Context};
    use std::time::{SystemTime, UNIX_EPOCH};
    use windows_service::{
        service::{ServiceAccess, ServiceErrorControl, ServiceInfo, ServiceStartType, ServiceType},
        service_manager::{ServiceManager, ServiceManagerAccess},
    };

    #[test]
    fn native_actions_never_reboot_or_execute_a_command() {
        let policy = actions();
        assert_eq!(policy.command, Some(OsString::new()));
        assert_eq!(policy.reboot_msg, Some(OsString::new()));
        assert_eq!(policy.reset_period.to_raw(), 3600);
        let actions = policy.actions.unwrap();
        assert_eq!(actions.len(), 4);
        assert_eq!(actions[3].action_type, ServiceActionType::None);
        assert!(actions[..3]
            .iter()
            .all(|a| a.action_type == ServiceActionType::Restart));
    }

    /// Creates a uniquely named, never-started fixture service, tests actual SCM
    /// persistence/reconciliation, and deletes only that service on every path.
    #[test]
    #[ignore = "explicit disposable SCM fixture authorization and administrator token required"]
    fn actual_scm_policy_reconciles_without_starting_a_service() -> Result<()> {
        check!(
            std::env::var("PORTHUB_TEST_SCM_RECOVERY").as_deref()
                == Ok("owned-never-started-service"),
            "SCM fixture authorization required"
        );
        let nonce = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
        let name = format!("porthub-recovery-test-{}-{nonce:x}", std::process::id());
        let manager = ServiceManager::local_computer(
            None::<&str>,
            ServiceManagerAccess::CONNECT | ServiceManagerAccess::CREATE_SERVICE,
        )?;
        let service = manager.create_service(
            &ServiceInfo {
                name: name.clone().into(),
                display_name: name.clone().into(),
                service_type: ServiceType::OWN_PROCESS,
                start_type: ServiceStartType::OnDemand,
                error_control: ServiceErrorControl::Normal,
                executable_path: std::env::current_exe()?,
                launch_arguments: vec![],
                dependencies: vec![],
                account_name: None,
                account_password: None,
            },
            ServiceAccess::QUERY_CONFIG
                | ServiceAccess::QUERY_STATUS
                | ServiceAccess::CHANGE_CONFIG
                | ServiceAccess::START
                | ServiceAccess::DELETE,
        )?;
        struct Cleanup(Service);
        impl Drop for Cleanup {
            fn drop(&mut self) {
                let _ = self.0.delete();
            }
        }
        let cleanup = Cleanup(service);
        let result = (|| -> Result<()> {
            check!(
                cleanup.0.query_status()?.current_state
                    == windows_service::service::ServiceState::Stopped
            );
            super::ensure(&cleanup.0)?;
            check!(cleanup.0.matches()?);
            super::ensure(&cleanup.0)?; // already-configured/repeated reconciliation
            cleanup.0.set_failure_actions_on_non_crash_failures(false)?;
            super::ensure(&cleanup.0)?; // repair a partially configured old service
            check!(cleanup.0.matches()?);
            check!(cleanup.0.query_config()?.start_type == ServiceStartType::OnDemand);
            check!(
                cleanup.0.query_status()?.current_state
                    == windows_service::service::ServiceState::Stopped
            );
            Ok(())
        })();
        cleanup
            .0
            .delete()
            .context("delete owned never-started SCM fixture")?;
        drop(cleanup);
        match manager.open_service(&name, ServiceAccess::QUERY_STATUS) {
            Err(windows_service::Error::Winapi(e)) if e.raw_os_error() == Some(1060) => {}
            _ => anyhow::bail!("owned SCM fixture remained after deletion"),
        }
        result
    }
}
