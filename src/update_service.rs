use std::ffi::OsString;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
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
use hbb_common::log;

use crate::updater;

const SERVICE_NAME: &str = "RustDeskUpdater";
const SERVICE_DISPLAY_NAME: &str = "RustDesk Updater Service";
const SERVICE_DESCRIPTION: &str = "Performs periodic update checks for RustDesk.";

define_windows_service!(ffi_update_service_main, update_service_main);

pub fn update_service_main(_arguments: Vec<OsString>) {
    if let Err(e) = run_update_service() {
        log::error!("Failed to run update service: {e:?}");
    }
}

pub fn run_update_service() -> Result<(), WinServiceError> {
    log::info!("Starting update service...");

    let stopped = Arc::new(AtomicBool::new(false));
    let stopped_handler = stopped.clone();

    // 注册服务控制事件处理函数
    let event_handler = move |control_event| -> ServiceControlHandlerResult {
        match control_event {
            ServiceControl::Stop => {
                log::info!("Service stop command received");
                stopped_handler.store(true, Ordering::SeqCst);
                ServiceControlHandlerResult::NoError
            }
            ServiceControl::Shutdown => {
                log::info!("System shutdown event received");
                stopped_handler.store(true, Ordering::SeqCst);
                ServiceControlHandlerResult::NoError
            }
            _ => {
                log::info!("Unhandled service control event received");
                ServiceControlHandlerResult::NotImplemented
            }
        }
    };

    let status_handle = service_control_handler::register(SERVICE_NAME, event_handler)?;
    log::info!("Service control handler registered");

    // 报告服务正在启动 (StartPending)
    log::info!("Reporting service state as StartPending...");
    status_handle.set_service_status(ServiceStatus {
        service_type: ServiceType::OWN_PROCESS,
        current_state: ServiceState::StartPending,
        controls_accepted: ServiceControlAccept::empty(),
        exit_code: ServiceExitCode::Win32(0),
        checkpoint: 1,
        wait_hint: Duration::from_secs(30),
        process_id: None,
    })?;

    // 启动更新线程
    let stopped_thread = stopped.clone();
    thread::spawn(move || {
        log::info!("Update check thread started");
        while !stopped_thread.load(Ordering::SeqCst) {
            log::info!("Checking for updates...");
            updater::manually_check_update();
            log::info!("Sleeping for 10 minutes before next update check");
            thread::sleep(Duration::from_secs(10 * 60)); // 每10分钟检查一次
        }
        log::info!("Update check thread exiting");
    });

    // 报告服务正在运行 (Running)
    log::info!("Reporting service state as Running...");
    status_handle.set_service_status(ServiceStatus {
        service_type: ServiceType::OWN_PROCESS,
        current_state: ServiceState::Running,
        controls_accepted: ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN,
        exit_code: ServiceExitCode::Win32(0),
        checkpoint: 0,
        wait_hint: Duration::ZERO,
        process_id: None,
    })?;

    // 主循环 - 等待停止信号
    log::info!("Main loop waiting for stop signal...");
    while !stopped.load(Ordering::SeqCst) {
        thread::sleep(Duration::from_secs(1));
    }

    // 报告服务已停止 (Stopped)
    log::info!("Service is stopping. Reporting state as Stopped...");
    status_handle.set_service_status(ServiceStatus {
        service_type: ServiceType::OWN_PROCESS,
        current_state: ServiceState::Stopped,
        controls_accepted: ServiceControlAccept::empty(),
        exit_code: ServiceExitCode::Win32(0),
        checkpoint: 0,
        wait_hint: Duration::ZERO,
        process_id: None,
    })?;

    log::info!("Service has been stopped successfully.");
    Ok(())
}

/// 安装更新服务
pub fn install_update_service() -> windows_service::Result<()> {
    log::info!("Installing update service...");

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

    log::info!("Update service installed successfully.");
    Ok(())
}

/// 卸载更新服务
pub fn uninstall_update_service() -> windows_service::Result<()> {
    log::info!("Uninstalling update service...");

    let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)?;
    let service = manager.open_service(SERVICE_NAME, ServiceAccess::DELETE)?;
    service.delete()?;

    log::info!("Update service uninstalled successfully.");
    Ok(())
}
