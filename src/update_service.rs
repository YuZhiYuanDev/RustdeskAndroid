//! RustDesk 更新服务模块
//!
//! 该模块实现了 Windows 系统服务功能，用于定期检查并自动更新 RustDesk 软件。
//! 主要功能包括服务注册、注销、运行以及软件更新逻辑。

use crate::{common::do_check_software_update, hbbs_http::create_http_client};
use hbb_common::{bail, log, ResultType};
use std::{fs, io::{self, Write, Read}, path::PathBuf, thread, time::{Duration, Instant}, sync::atomic::{AtomicBool, Ordering}, sync::Arc};
use windows_service::{
    define_windows_service,
    service::{ServiceControl, ServiceControlAccept, ServiceExitCode, ServiceState, ServiceStatus, ServiceType, ServiceStartType},
    service_control_handler::{self, ServiceControlHandlerResult},
};

// 服务常量定义
const SERVICE_NAME: &str = "RustDeskUpdateService"; // 服务名称
const CHECK_INTERVAL: Duration = Duration::from_secs(1 * 60 * 60); // 检查更新间隔(1小时)

// 定义Windows服务入口点
define_windows_service!(ffi_service_main, service_main);

/// 注册Windows服务
///
/// # 返回值
/// - 成功时返回 `Ok(())`
/// - 失败时返回错误信息
pub fn register_service(app_path: &str) -> ResultType<()> {
    use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};
    use windows_service::service::{ServiceAccess, ServiceInfo, ServiceErrorControl, ServiceStartType};

    // 使用传入的应用程序路径作为服务二进制路径
    let service_binary_path = PathBuf::from(app_path);

    // 验证路径是否存在
    if !service_binary_path.exists() {
        let msg = format!("Specified application path does not exist: {}", app_path);
        updater_log(&msg);
        bail!(msg);
    }

    // 配置服务信息
    let service_info = ServiceInfo {
        name: SERVICE_NAME.into(), // 服务名称
        display_name: "RustDesk Updater Service".into(), // 显示名称
        service_type: ServiceType::OWN_PROCESS, // 服务类型(独立进程)
        start_type: ServiceStartType::AutoStart, // 启动类型(自动启动)
        error_control: ServiceErrorControl::Normal, // 错误处理级别
        executable_path: service_binary_path.clone(), // 可执行文件路径
        launch_arguments: vec!["--update-service".into()], // 启动参数
        dependencies: vec![], // 依赖服务
        account_name: None, // 运行账户(默认系统账户)
        account_password: None, // 账户密码
    };

    // 连接服务管理器
    let manager_access = ServiceManagerAccess::CONNECT | ServiceManagerAccess::CREATE_SERVICE;
    let service_manager = ServiceManager::local_computer(None::<&str>, manager_access)?;

    // 创建服务
    match service_manager.create_service(&service_info, ServiceAccess::START | ServiceAccess::CHANGE_CONFIG) {
        Ok(service) => {
            log::info!("Service registered.");
            updater_log("Service registered.");

            // 尝试启动服务
            match service.start::<&std::ffi::OsStr>(&[]) {
                Ok(_) => {
                    log::info!("Service started successfully.");
                    updater_log("Service started successfully.");
                }
                Err(e) => {
                    log::warn!("Failed to start service: {}", e);
                    updater_log(&format!("Failed to start service: {}", e));
                }
            }
        }
        Err(e) => {
            updater_log(&format!("Failed to register service: {}", e));
            bail!("Failed to register service: {}", e);
        }
    }

    Ok(())
}

/// 注销Windows服务
///
/// # 返回值
/// - 成功时返回 `Ok(())`
/// - 失败时返回错误信息
pub fn unregister_service() -> ResultType<()> {
    use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};
    use windows_service::service::ServiceAccess;

    // 连接服务管理器
    let manager_access = ServiceManagerAccess::CONNECT;
    let service_manager = ServiceManager::local_computer(None::<&str>, manager_access)?;
    
    // 打开服务
    let service = service_manager.open_service(SERVICE_NAME, ServiceAccess::STOP | ServiceAccess::DELETE)?;

    // 停止服务
    match service.stop() {
        Ok(_) => {
            log::info!("Service stopped.");
            updater_log("Service stopped.");
        }
        Err(e) => {
            log::warn!("Failed to stop service: {}", e);
            updater_log(&format!("Failed to stop service: {}", e));
        }
    }

    // 删除服务
    service.delete()?;
    log::info!("Service unregistered.");
    updater_log("Service unregistered.");
    Ok(())
}

/// 启动服务调度器
///
/// # 返回值
/// - 成功时返回 `Ok(())`
/// - 失败时返回错误信息
pub fn start_service_dispatcher() -> ResultType<()> {
    windows_service::service_dispatcher::start(SERVICE_NAME, ffi_service_main)?;
    updater_log("Service dispatcher has exited.");
    Ok(())
}

/// Windows服务主函数
///
/// # 参数
/// - `_arguments`: 服务启动参数
fn service_main(_arguments: Vec<std::ffi::OsString>) {
    if let Err(e) = run_service() {
        log::error!("Service failed: {}", e);
        updater_log(&format!("Service failed: {}", e));
    }
}

/// 运行服务主逻辑
///
/// # 返回值
/// - 成功时返回 `Ok(())`
/// - 失败时返回错误信息
fn run_service() -> ResultType<()> {
    // 创建停止标志(原子布尔值)
    let stop_requested = Arc::new(AtomicBool::new(false));
    let stop_flag = Arc::clone(&stop_requested);

    // 定义服务控制事件处理函数
    let event_handler = move |control_event| match control_event {
        ServiceControl::Stop => {
            // 收到停止命令时设置停止标志
            stop_flag.store(true, Ordering::SeqCst);
            ServiceControlHandlerResult::NoError
        }
        _ => ServiceControlHandlerResult::NotImplemented,
    };

    // 注册服务控制处理器
    let status_handle = service_control_handler::register(SERVICE_NAME, event_handler)?;

    // 设置服务状态为运行中
    status_handle.set_service_status(ServiceStatus {
        service_type: ServiceType::OWN_PROCESS, // 服务类型
        current_state: ServiceState::Running, // 当前状态
        controls_accepted: ServiceControlAccept::STOP, // 接受的控制命令
        exit_code: ServiceExitCode::Win32(0), // 退出代码
        checkpoint: 0, // 检查点
        wait_hint: Duration::default(), // 等待提示时间
        process_id: None, // 进程ID
    })?;

    // 初始化上次检查时间
    let mut last_check = Instant::now() - CHECK_INTERVAL;

    // 服务主循环
    while !stop_requested.load(Ordering::SeqCst) {
        // 检查是否到达检查间隔
        if last_check.elapsed() >= CHECK_INTERVAL {
            // 执行更新检查
            if let Err(e) = perform_update() {
                log::error!("Update check failed: {}", e);
                updater_log(&format!("Update check failed: {}", e));
            }
            last_check = Instant::now();
        }

        // 每100毫秒检查一次停止标志(共检查10次，即1秒)
        for _ in 0..10 {
            thread::sleep(Duration::from_millis(100));
            if stop_requested.load(Ordering::SeqCst) {
                break;
            }
        }
    }

    // 设置服务状态为已停止
    status_handle.set_service_status(ServiceStatus {
        service_type: ServiceType::OWN_PROCESS,
        current_state: ServiceState::Stopped,
        controls_accepted: ServiceControlAccept::empty(),
        exit_code: ServiceExitCode::Win32(0),
        checkpoint: 0,
        wait_hint: Duration::default(),
        process_id: None,
    })?;

    Ok(())
}

/// 执行更新检查与下载
///
/// # 返回值
/// - 成功时返回 `Ok(())`
/// - 失败时返回错误信息
fn perform_update() -> ResultType<()> {
    // 检查是否有可用更新
    if !do_check_software_update().is_ok() {
        return Ok(());
    }

    // 获取更新URL
    let update_url = crate::common::SOFTWARE_UPDATE_URL.lock().unwrap().clone();
    if update_url.is_empty() {
        log::debug!("No update available.");
        updater_log("No update available.");
        return Ok(());
    }

    // 构造下载URL和版本号
    let mut download_url = update_url.replace("tag", "download");
    let version = download_url.split('/').last().unwrap_or_default();
    updater_log(format!("download_url: {}, version: {}", download_url, version).as_str());

    // 检查是否通过MSI安装
    #[cfg(target_os = "windows")]
    let is_msi = crate::platform::is_msi_installed()?;

    // 根据构建配置构造最终的下载URL
    #[cfg(target_os = "windows")]
    let download_url = if cfg!(feature = "flutter") {
        format!("{}/rustdesk-{}-x86_64.{}", download_url, version, if is_msi { "msi" } else { "exe" })
    } else {
        format!("{}/rustdesk-{}-x86-sciter.exe", download_url, version)
    };

    log::debug!("New version available: {}", &version);
    updater_log(&format!("New version available: {}", &version));

    // 创建HTTP客户端
    let client = create_http_client();

    updater_log(&format!("Final download URL: {}", download_url));

    // 从URL获取下载文件路径
    let Some(file_path) = crate::updater::get_download_file_from_url(&download_url) else {
        updater_log(&format!("Failed to get file path from URL: {}", download_url));
        bail!("Failed to get file path from URL: {}", download_url);
    };

    // 检查文件是否已存在且完整
    let mut is_file_exists = false;
    if !download_url.contains("gitee.com") {
        if file_path.exists() {
            let file_size = fs::metadata(&file_path)?.len();
            let response = client.head(&download_url).send()?;
            if !response.status().is_success() {
                updater_log(&format!("Failed to get file size: {}", response.status()));
                bail!("Failed to get file size: {}", response.status());
            }
            let total_size = response.headers()
                .get(reqwest::header::CONTENT_LENGTH)
                .and_then(|v| v.to_str().ok())
                .and_then(|v| v.parse::<u64>().ok());
            if let Some(total_size) = total_size {
                if file_size == total_size {
                    is_file_exists = true;
                } else {
                    fs::remove_file(&file_path)?;
                }
            }
        }
    } else {
        if file_path.exists() {
            fs::remove_file(&file_path)?;
        }
    }

    // 如果文件不存在或不完整，则下载
    if !is_file_exists {
        match crate::hbbs_http::downloader::download_file(download_url.clone(), Some(file_path.clone()), Some(Duration::from_secs(1))) {
            Ok(id) => {
                updater_log(&format!("Download started. id={}, file_path={:?}", id, file_path.to_str()));

                let mut last_printed = std::time::Instant::now();

                // 下载进度监控循环
                loop {
                    std::thread::sleep(std::time::Duration::from_millis(500));

                    match crate::hbbs_http::downloader::get_download_data(&id) {
                        Ok(data) => {
                            let downloaded_size = data.downloaded_size;
                            let total_size = data.total_size.unwrap_or(0);
                            let progress = if total_size > 0 {
                                format!("{:.2}%", downloaded_size as f64 / total_size as f64 * 100.0)
                            } else {
                                String::from("Unknown %")
                            };

                            // 每秒打印一次下载进度
                            if last_printed.elapsed() > std::time::Duration::from_secs(1) {
                                updater_log(&format!(
                                    "[DOWNLOAD PROGRESS] downloaded_size: {}, total_size: {}, progress: {}, path: {:?}",
                                    downloaded_size,
                                    total_size,
                                    progress,
                                    data.path.as_ref().map(|p| p.display().to_string()).unwrap_or_else(|| "<None>".to_string())
                                ));
                                last_printed = std::time::Instant::now();
                            }

                            // 处理下载错误
                            if let Some(err) = data.error {
                                updater_log(&format!("Download failed: {}, url={}", err, download_url));
                                bail!("Download failed: {}", err);
                            }

                            // 检查下载是否完成
                            if let Some(path) = data.path {
                                if path.exists() {
                                    if total_size > 0 && downloaded_size >= total_size {
                                        updater_log(&format!("Download finished successfully. File saved at: {}", path.display()));
                                        break;
                                    }
                                }
                            }
                        }
                        Err(e) => {
                            updater_log(&format!("Failed to get download status: {}, url={}", e.to_string(), download_url));
                            bail!("Failed to get download status: {}", e);
                        }
                    }
                }
            }
            Err(e) => {
                updater_log(&format!("Download failed: {}, url={}", e.to_string(), download_url));
                bail!("Download failed: {}", e);
            }
        }
    }

    // 执行新版本更新
    updater_log(&format!("Call function update_new_version with is_msi: {}, version: {}, file_path: {:?}", is_msi, version, file_path.to_str()));
    #[cfg(target_os = "windows")]
    update_new_version(is_msi, &version, &file_path);

    updater_log("Update process completed.");

    Ok(())
}

/// 执行新版本更新
///
/// # 参数
/// - `is_msi`: 是否通过MSI安装包安装
/// - `version`: 新版本号
/// - `file_path`: 下载的更新文件路径
#[cfg(target_os = "windows")]
fn update_new_version(is_msi: bool, version: &str, file_path: &PathBuf) {
    log::debug!("New version is downloaded, update begin, is msi: {is_msi}, version: {version}, file: {:?}", file_path.to_str());
    updater_log(&format!("New version is downloaded, update begin, is msi: {}, version: {}, file: {:?}", is_msi, version, file_path.to_str()));
    if let Some(p) = file_path.to_str() {
        if let Some(session_id) = crate::platform::get_current_process_session_id() {
            if is_msi {
                // MSI安装包更新逻辑
                match crate::platform::update_me_msi(p, true) {
                    Ok(_) => {
                        log::debug!("New version \"{}\" updated.", version);
                        updater_log(&format!("New version \"{}\" updated.", version));
                    }
                    Err(e) => {
                        log::error!("Failed to install the new msi version  \"{}\": {}", version, e);
                        updater_log(&format!("Failed to install the new msi version \"{}\": {}", version, e));
                    }
                }
            } else {
                // EXE文件更新逻辑
                let exe_path = std::path::Path::new(p);
                let exe_dir = exe_path.parent().unwrap();
                let exe_filename = exe_path.file_name().unwrap().to_string_lossy();
                
                // 获取更新批处理脚本内容
                let cmd_content = format!("@echo off\r\nchcp 65001 >nul\r\ncd /d \"{}\"\r\n\"{}\" --update\r\n", exe_dir.display(), exe_filename);

                // 获取批处理文件创建路径
                let temp_dir = std::env::temp_dir();
                let cmd_path: PathBuf = temp_dir.join(format!("update_{}.cmd", version));
                updater_log(&format!("Temp dir: {}", temp_dir.display()));
                updater_log(&format!("Cmd path: {}", cmd_path.display()));

                // 写入批处理文件
                match fs::File::create(&cmd_path) {
                    Ok(mut f) => {
                        if let Err(e) = f.write_all(cmd_content.as_bytes()) {
                            updater_log(&format!("Failed to write .cmd file: {}", e));
                            return;
                        }
                    }
                    Err(e) => {
                        updater_log(&format!("Failed to create .cmd file: {}", e));
                        return;
                    }
                }

                updater_log(&format!("Created .cmd file at: {}", cmd_path.display()));

                // 执行批处理文件
                let output = std::process::Command::new("cmd.exe")
                    .arg("/C")
                    .arg(cmd_path.to_str().unwrap())
                    .output();

                // 记录执行结果
                match output {
                    Ok(output) => {
                        updater_log(&format!("Update script executed. Exit code: {:?}", output.status.code()));
                        updater_log(&format!("Stdout: {}", String::from_utf8_lossy(&output.stdout)));
                        updater_log(&format!("Stderr: {}", String::from_utf8_lossy(&output.stderr)));
                    }
                    Err(e) => {
                        updater_log(&format!("Failed to run the update script: {}", e));
                    }
                }
            }
        } else {
            log::error!("Failed to get the current process session id, Error {}", io::Error::last_os_error());
            updater_log(&format!("Failed to get the current process session id, Error {}", io::Error::last_os_error()));
        }
    } else {
        log::error!("Failed to convert the file path to string: {}", file_path.display());
        updater_log(&format!("Failed to convert the file path to string: {}", file_path.display()));
    }
}

/// 更新服务日志记录函数
///
/// # 参数
/// - `msg`: 要记录的日志消息
fn updater_log(msg: &str) {
    // #[cfg(debug_assertions)]
    // {
        // 获取ProgramData目录路径
        let program_data = match std::env::var("ProgramData") {
            Ok(val) => val,
            Err(e) => {
                eprintln!("Failed to get ProgramData env var: {}", e);
                return;
            }
        };

        // 构造日志目录路径
        let mut log_dir = PathBuf::from(program_data);
        log_dir.push("RustDesk");

        // 创建日志目录
        if let Err(e) = std::fs::create_dir_all(&log_dir) {
            eprintln!("Failed to create log directory {:?}: {}", log_dir, e);
            return;
        }

        // 构造日志文件路径
        let log_path = log_dir.join("update_service.log");

        // 打开日志文件并追加写入日志
        if let Ok(mut file) =  std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&log_path)
        {
            let now = chrono::Local::now();
            let _ = writeln!(file, "[{}] {}", now.format("%Y-%m-%d %H:%M:%S"), msg);
        }
    // }
}
