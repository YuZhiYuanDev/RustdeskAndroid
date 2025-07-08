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

use crate::updater;

const SERVICE_NAME: &str = "RustDeskUpdater";
const SERVICE_DISPLAY_NAME: &str = "RustDesk Updater Service";
const SERVICE_DESCRIPTION: &str = "Performs periodic update checks for RustDesk.";

define_windows_service!(ffi_update_service_main, update_service_main);

pub fn update_service_main(_arguments: Vec<OsString>) {
    if let Err(e) = run_update_service() {
        eprintln!("Failed to run update service: {e:?}");
    }
}

pub fn run_update_service() -> Result<(), WinServiceError> {
    let stopped = Arc::new(AtomicBool::new(false));
    let stopped_handler = stopped.clone();

    // 事件处理函数 - 处理服务控制命令
    let event_handler = move |control_event| -> ServiceControlHandlerResult {
        match control_event {
            ServiceControl::Stop | ServiceControl::Shutdown => {
                // 设置停止标志
                stopped_handler.store(true, Ordering::SeqCst);
                ServiceControlHandlerResult::NoError
            }
            _ => ServiceControlHandlerResult::NotImplemented,
        }
    };

    // 注册服务控制处理器
    let status_handle = service_control_handler::register(SERVICE_NAME, event_handler)?;

    // 报告服务正在启动 (关键步骤!)
    status_handle.set_service_status(ServiceStatus {
        service_type: ServiceType::OWN_PROCESS,
        current_state: ServiceState::StartPending,
        controls_accepted: ServiceControlAccept::empty(), // 启动期间不接受控制命令
        exit_code: ServiceExitCode::Win32(0),
        checkpoint: 1,
        wait_hint: Duration::from_secs(30), // 30秒超时窗口
        process_id: None,
    })?;

    // 启动更新检查线程
    let stopped_thread = stopped.clone();
    thread::spawn(move || {
        while !stopped_thread.load(Ordering::SeqCst) {
            updater::manually_check_update();
            thread::sleep(Duration::from_secs(10 * 60)); // 每10分钟检查一次
        }
    });

    // 报告服务正在运行
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
    while !stopped.load(Ordering::SeqCst) {
        thread::sleep(Duration::from_secs(1));
    }

    // 报告服务已停止
    status_handle.set_service_status(ServiceStatus {
        service_type: ServiceType::OWN_PROCESS,
        current_state: ServiceState::Stopped,
        controls_accepted: ServiceControlAccept::empty(),
        exit_code: ServiceExitCode::Win32(0),
        checkpoint: 0,
        wait_hint: Duration::ZERO,
        process_id: None,
    })?;

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
