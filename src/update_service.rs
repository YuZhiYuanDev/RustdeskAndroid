use std::ffi::OsString;
use std::thread;
use std::time::Duration;
use windows_service::{
    define_windows_service,
    service::{
        ServiceAccess, ServiceErrorControl, ServiceInfo, ServiceStartType, ServiceType, ServiceState,
        ServiceStatus, ServiceExitCode, ServiceControlAccept, ServiceControl,
    },
    service_control_handler::{self, ServiceControlHandlerResult},
    service_dispatcher,
    service_manager::{ServiceManager, ServiceManagerAccess},
    Error as WinServiceError
};

use crate::updater; // 调用你的更新逻辑

const SERVICE_NAME: &str = "RustDeskUpdater";
const SERVICE_DISPLAY_NAME: &str = "RustDesk Updater Service";
const SERVICE_DESCRIPTION: &str = "Performs periodic update checks for RustDesk.";

define_windows_service!(ffi_update_service_main, update_service_main);

pub fn update_service_main(_arguments: Vec<OsString>) {
    if let Err(e) = run_update_service() {
        eprintln!("Failed to run update service: {e:?}");
    }
}

pub fn run_update_service() -> windows_service::Result<()> {
    let event_handler = |control_event| -> ServiceControlHandlerResult {
        match control_event {
            ServiceControl::Stop | ServiceControl::Shutdown => ServiceControlHandlerResult::NoError,
            _ => ServiceControlHandlerResult::NoError,
        }
    };

    let status_handle = service_control_handler::register(SERVICE_NAME, event_handler)?;

    status_handle.set_service_status(ServiceStatus {
        service_type: ServiceType::OWN_PROCESS,
        current_state: ServiceState::Running,
        controls_accepted: ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN,
        exit_code: ServiceExitCode::Win32(0),
        checkpoint: 0,
        wait_hint: Duration::ZERO,
        process_id: None,
    })?;

    std::thread::spawn(|| {
        loop {
            updater::manually_check_update();
            std::thread::sleep(Duration::from_secs(10 * 60)); //60 * 60
        }
    });

    loop {
        std::thread::sleep(Duration::from_secs(5));
    }
}

/// 安装更新服务
pub fn install_update_service() -> windows_service::Result<()> {
    let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CREATE_SERVICE)?;
    let executable_path = std::env::current_exe()
        .map_err(|e| WinServiceError::Winapi(e))?;

    let service_info = ServiceInfo {
        name: SERVICE_NAME.into(),
        display_name: SERVICE_DISPLAY_NAME.into(),
        service_type: ServiceType::OWN_PROCESS,
        start_type: ServiceStartType::AutoStart,
        error_control: ServiceErrorControl::Normal,
        executable_path,
        launch_arguments: vec!["--update-service-run".into()],
        dependencies: vec![],
        account_name: None,
        account_password: None,
    };

    let service = manager.create_service(&service_info, ServiceAccess::CHANGE_CONFIG)?;
    service.set_description(SERVICE_DESCRIPTION)?;

    println!("Update service installed successfully.");
    Ok(())
}

/// 卸载更新服务
pub fn uninstall_update_service() -> windows_service::Result<()> {
    let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)?;
    let service = manager.open_service(SERVICE_NAME, ServiceAccess::DELETE)?;
    service.delete()?;
    println!("Update service uninstalled successfully.");
    Ok(())
}
