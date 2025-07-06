use hbb_common::{
    allow_err,
    anyhow::anyhow,
    bail,
    config::{self, Config},
    libc::{c_int, wchar_t},
    log,
    message_proto::{DisplayInfo, Resolution, WindowsSession},
    sleep,
    sysinfo::{Pid, System},
    timeout,
    tokio,
    ResultType,
};
use std::{
    collections::HashMap,
    ffi::{CString, OsString},
    fs,
    io::{self, prelude::*},
    mem,
    os::{
        raw::c_ulong,
        windows::{ffi::OsStringExt, process::CommandExt},
    },
    path::*,
    ptr::null_mut,
    sync::{atomic::Ordering, Arc, Mutex},
    time::{Duration, Instant},
};
use windows_service::{
    define_windows_service,
    service::{
        ServiceControl, ServiceControlAccept, ServiceExitCode, ServiceState, ServiceStatus,
        ServiceType,
    },
    service_control_handler::{self, ServiceControlHandlerResult},
};

/// 定义服务类型为独立进程。
///
/// 表示该服务将在自己的进程中运行（而不是共享主机进程）。
const SERVICE_TYPE: ServiceType = ServiceType::OWN_PROCESS;

// 更新检查间隔（1小时）（生产环境）
//const UPDATE_CHECK_INTERVAL: Duration = Duration::from_secs(60 * 60); 

// 更新检查间隔（5分钟）（测试环境）
const UPDATE_CHECK_INTERVAL: Duration = Duration::from_secs(5 * 60); 

// 更新服务名称
const UPDATE_SERVICE_NAME: &str = "RustDeskUpdater";

// 定义更新服务的主函数
define_windows_service!(ffi_update_service_main, update_service_main);

fn update_service_main(arguments: Vec<OsString>) {
    if let Err(e) = run_update_service(arguments) {
        log::error!("Update service failed: {}", e);
    }
}

// 启动更新服务分发器
pub fn start_update_service() {
    if let Err(e) = windows_service::service_dispatcher::start(UPDATE_SERVICE_NAME, ffi_update_service_main) {
        log::error!("启动更新服务失败: {}", e);
    }
}

#[tokio::main(flavor = "current_thread")]
async fn run_update_service(_arguments: Vec<OsString>) -> ResultType<()> {
    // 注册服务控制处理器
    let event_handler = move |control_event| -> ServiceControlHandlerResult {
        log::info!("Update service received control event: {:?}", control_event);
        match control_event {
            ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
            ServiceControl::Stop | ServiceControl::Preshutdown | ServiceControl::Shutdown => {
                // 设置服务停止标志
                SERVICE_STOP_REQUESTED.store(true, std::sync::atomic::Ordering::SeqCst);
                ServiceControlHandlerResult::NoError
            }
            _ => ServiceControlHandlerResult::NotImplemented,
        }
    };

    let status_handle = service_control_handler::register(UPDATE_SERVICE_NAME, event_handler)?;

    // 报告服务正在运行
    let running_status = ServiceStatus {
        service_type: SERVICE_TYPE,
        current_state: ServiceState::Running,
        controls_accepted: ServiceControlAccept::STOP,
        exit_code: ServiceExitCode::Win32(0),
        checkpoint: 0,
        wait_hint: Duration::default(),
        process_id: None,
    };
    status_handle.set_service_status(running_status)?;

    // 服务主循环
    while !SERVICE_STOP_REQUESTED.load(std::sync::atomic::Ordering::SeqCst) {
        // 执行更新检查命令
        if let Err(e) = run_update_check().await {
            log::error!("更新检查失败: {}", e);
        }
        
        // 等待下一次检查
        let mut interval = tokio::time::interval(Duration::from_secs(1));
        for _ in 0..UPDATE_CHECK_INTERVAL.as_secs() {
            interval.tick().await;
            if SERVICE_STOP_REQUESTED.load(Ordering::Relaxed) {
                break;
            }
        }
    }

    // 报告服务已停止
    status_handle.set_service_status(ServiceStatus {
        service_type: SERVICE_TYPE,
        current_state: ServiceState::Stopped,
        controls_accepted: ServiceControlAccept::empty(),
        exit_code: ServiceExitCode::Win32(0),
        checkpoint: 0,
        wait_hint: Duration::default(),
        process_id: None,
    })?;

    Ok(())
}

// 全局服务停止标志
static SERVICE_STOP_REQUESTED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

// 运行更新检查命令
async fn run_update_check() -> ResultType<()> {
    log::info!("开始检查更新...");
    // 调用 updater 模块中的手动检查更新函数
    match crate::updater::manually_check_update() {
        Ok(()) => {
            log::info!("更新检查完成");
            Ok(())
        }
        Err(e) => {
            log::error!("更新检查失败: {}", e);
            Err(e)
        }
    }
}
