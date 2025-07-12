use crate::{common::do_check_software_update, hbbs_http::create_http_client};
use hbb_common::{bail, log, ResultType};
use std::{fs, io::{self, Write, Read}, path::PathBuf, thread, time::{Duration, Instant}, sync::atomic::{AtomicBool, Ordering}, sync::Arc};
use windows_service::{
    define_windows_service,
    service::{ServiceControl, ServiceControlAccept, ServiceExitCode, ServiceState, ServiceStatus, ServiceType, ServiceStartType},
    service_control_handler::{self, ServiceControlHandlerResult},
};

const SERVICE_NAME: &str = "RustDeskUpdateService";
const CHECK_INTERVAL: Duration = Duration::from_secs(10 * 60);

define_windows_service!(ffi_service_main, service_main);

pub fn register_service() -> ResultType<()> {
    use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};
    use windows_service::service::{ServiceAccess, ServiceInfo, ServiceErrorControl, ServiceStartType};

    let service_binary_path = ::std::env::current_exe()?;

    let service_info = ServiceInfo {
        name: SERVICE_NAME.into(),
        display_name: "RustDesk Updater Service".into(),
        service_type: ServiceType::OWN_PROCESS,
        start_type: ServiceStartType::AutoStart,
        error_control: ServiceErrorControl::Normal,
        executable_path: service_binary_path,
        launch_arguments: vec!["--update-service".into()],
        dependencies: vec![],
        account_name: None,
        account_password: None,
    };

    let manager_access = ServiceManagerAccess::CONNECT | ServiceManagerAccess::CREATE_SERVICE;
    let service_manager = ServiceManager::local_computer(None::<&str>, manager_access)?;

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

pub fn unregister_service() -> ResultType<()> {
    use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};
    use windows_service::service::ServiceAccess;

    let manager_access = ServiceManagerAccess::CONNECT;
    let service_manager = ServiceManager::local_computer(None::<&str>, manager_access)?;
    let service = service_manager.open_service(SERVICE_NAME, ServiceAccess::STOP | ServiceAccess::DELETE)?;

    // Attempt to stop the service if it's running
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

    service.delete()?;
    log::info!("Service unregistered.");
    updater_log("Service unregistered.");
    Ok(())
}

pub fn start_service_dispatcher() -> ResultType<()> {
    windows_service::service_dispatcher::start(SERVICE_NAME, ffi_service_main)?;
    updater_log("Service started successfully.");
    Ok(())
}

fn service_main(_arguments: Vec<std::ffi::OsString>) {
    if let Err(e) = run_service() {
        log::error!("Service failed: {}", e);
        updater_log(&format!("Service failed: {}", e));
    }
}

fn run_service() -> ResultType<()> {
    let stop_requested = Arc::new(AtomicBool::new(false));
    let stop_flag = Arc::clone(&stop_requested);

    let event_handler = move |control_event| match control_event {
        ServiceControl::Stop => {
            stop_flag.store(true, Ordering::SeqCst);
            ServiceControlHandlerResult::NoError
        }
        _ => ServiceControlHandlerResult::NotImplemented,
    };

    let status_handle = service_control_handler::register(SERVICE_NAME, event_handler)?;

    status_handle.set_service_status(ServiceStatus {
        service_type: ServiceType::OWN_PROCESS,
        current_state: ServiceState::Running,
        controls_accepted: ServiceControlAccept::STOP,
        exit_code: ServiceExitCode::Win32(0),
        checkpoint: 0,
        wait_hint: Duration::default(),
        process_id: None,
    })?;

    let mut last_check = Instant::now() - CHECK_INTERVAL;

    while !stop_requested.load(Ordering::SeqCst) {
        if last_check.elapsed() >= CHECK_INTERVAL {
            if let Err(e) = perform_update() {
                log::error!("Update check failed: {}", e);
                updater_log(&format!("Update check failed: {}", e));
            }
            last_check = Instant::now();
        }

        for _ in 0..10 {
            thread::sleep(Duration::from_millis(100));
            if stop_requested.load(Ordering::SeqCst) {
                break;
            }
        }
    }

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

fn perform_update() -> ResultType<()> {
    if !do_check_software_update().is_ok() {
        return Ok(());
    }

    let update_url = crate::common::SOFTWARE_UPDATE_URL.lock().unwrap().clone();
    if update_url.is_empty() {
        log::debug!("No update available.");
        updater_log("No update available.");
        return Ok(());
    }

    let mut download_url = update_url.replace("tag", "download");
    let version = download_url.split('/').last().unwrap_or_default();
    updater_log(format!("download_url: {}, version: {}", download_url, version).as_str());

    #[cfg(target_os = "windows")]
    let is_msi = crate::platform::is_msi_installed()?;

    #[cfg(target_os = "windows")]
    let download_url = if cfg!(feature = "flutter") {
        format!("{}/rustdesk-{}-x86_64.{}", download_url, version, if is_msi { "msi" } else { "exe" })
    } else {
        format!("{}/rustdesk-{}-x86-sciter.exe", download_url, version)
    };

    log::debug!("New version available: {}", &version);
    updater_log(&format!("New version available: {}", &version));

    let client = create_http_client();

    updater_log(&format!("Final download URL: {}", download_url));

    let Some(file_path) = crate::updater::get_download_file_from_url(&download_url) else {
        updater_log(&format!("Failed to get file path from URL: {}", download_url));
        bail!("Failed to get file path from URL: {}", download_url);
    };

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
            // 不信任旧文件，强制重下
            fs::remove_file(&file_path)?;
        }
    }

    if !is_file_exists {
        match crate::hbbs_http::downloader::download_file(download_url.clone(), Some(file_path.clone()), Some(Duration::from_secs(3))) {
            Ok(id) => {
                updater_log(&format!("Download succeeded. id={}, file_path={:?}", id, file_path.to_str()));
            }
            Err(e) => {
                updater_log(&format!("Download failed: {}, url={}", e.to_string(), download_url));
                bail!("Download failed: {}", e);
            }
        }
    }

    updater_log(&format!("Call function update_new_version with is_msi: {}, version: {}, file_path: {:?}", is_msi, version, file_path.to_str()));
    #[cfg(target_os = "windows")]
    update_new_version(is_msi, &version, &file_path);

    Ok(())
}

#[cfg(target_os = "windows")]
fn update_new_version(is_msi: bool, version: &str, file_path: &PathBuf) {
    log::debug!("New version is downloaded, update begin, is msi: {is_msi}, version: {version}, file: {:?}", file_path.to_str());
    updater_log(&format!("New version is downloaded, update begin, is msi: {}, version: {}, file: {:?}", is_msi, version, file_path.to_str()));
    if let Some(p) = file_path.to_str() {
        if let Some(session_id) = crate::platform::get_current_process_session_id() {
            if is_msi {
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
                updater_log(&format!("Checking if file exists: {}", file_path.display()));
                match std::fs::metadata(&file_path) {
                    Ok(meta) => updater_log(&format!("File exists. Size: {} bytes", meta.len())),
                    Err(e) => {
                        updater_log(&format!("File does NOT exist or cannot be accessed: {}. Error: {}", file_path.display(), e));
                        return;
                    }
                }

                let cmd_content = format!("@echo off\r\nchcp 65001 >nul\r\n\"{}\" --update\r\n", p);

                let exe_path = std::path::Path::new(p);
                let exe_dir = exe_path.parent().unwrap();
                let cmd_path = exe_dir.join(format!("update_{}.cmd", version));

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

                let output = std::process::Command::new("cmd.exe")
                    .arg("/C")
                    .arg(cmd_path.to_str().unwrap())
                    .output();

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

pub fn updater_log(msg: &str) {
    let program_data = match std::env::var("ProgramData") {
        Ok(val) => val,
        Err(e) => {
            eprintln!("Failed to get ProgramData env var: {}", e);
            return;
        }
    };

    let mut log_dir = PathBuf::from(program_data);
    log_dir.push("RustDesk");

    if let Err(e) = std::fs::create_dir_all(&log_dir) {
        eprintln!("Failed to create log directory {:?}: {}", log_dir, e);
        return;
    }

    let log_path = log_dir.join("update_service.log");

    if let Ok(mut file) =  std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&log_path)
    {
        let now = chrono::Local::now();
        let _ = writeln!(file, "[{}] {}", now.format("%Y-%m-%d %H:%M:%S"), msg);
    }
}
