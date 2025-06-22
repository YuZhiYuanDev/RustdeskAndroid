use crate::{common::do_check_software_update, hbbs_http::create_http_client};
use hbb_common::{bail, config, log, ResultType};
use std::{
    io::{self, Write},
    path::PathBuf,
    sync::{
        atomic::{AtomicUsize, Ordering},
        mpsc::{channel, Receiver, Sender},
        Mutex,
    },
    time::{Duration, Instant},
};

// 定义更新消息枚举类型，用于发送不同的更新操作指令
enum UpdateMsg {
    CheckUpdate, // 触发软件更新检查的消息
    Exit, // 退出自动更新检查的消息
}

// 使用lazy_static宏创建一个全局Sender实例，用于发送更新消息
lazy_static::lazy_static! {
    static ref TX_MSG : Mutex<Sender<UpdateMsg>> = Mutex::new(start_auto_update_check());
}

// 创建一个原子计数器，用于记录正在控制的会话数量
static CONTROLLING_SESSION_COUNT: AtomicUsize = AtomicUsize::new(0);

// 定义一天的时间间隔常量
const DUR_ONE_DAY: Duration = Duration::from_secs(60 * 60 * 24);

// 更新正在控制的会话数量
pub fn update_controlling_session_count(count: usize) {
    CONTROLLING_SESSION_COUNT.store(count, Ordering::SeqCst);
}

// 启动自动更新功能，实际只是获取Sender实例
pub fn start_auto_update() {
    let _sender = TX_MSG.lock().unwrap();
}

// 手动触发软件更新检查
pub fn manually_check_update() -> ResultType<()> {
    let sender = TX_MSG.lock().unwrap();
    sender.send(UpdateMsg::CheckUpdate)?; // 发送CheckUpdate消息以手动触发更新检查
    Ok(())
}

// 停止自动更新功能
#[allow(dead_code)]
pub fn stop_auto_update() {
    let sender = TX_MSG.lock().unwrap();
    sender.send(UpdateMsg::Exit).unwrap_or_default(); // 发送Exit消息以停止自动更新
}

// 检查是否有活动连接
#[inline]
fn has_no_active_conns() -> bool {
    let conns = crate::Connection::alive_conns(); // 获取所有活跃连接
    conns.is_empty() && has_no_controlling_conns() // 如果没有活跃连接且没有控制会话，则返回true
}

// 根据目标操作系统和特性配置检查是否有控制会话
#[cfg(any(not(target_os = "windows"), feature = "flutter"))]
fn has_no_controlling_conns() -> bool {
    CONTROLLING_SESSION_COUNT.load(Ordering::SeqCst) == 0 // 返回控制会话计数是否为零
}

// 对于Windows系统且未启用Flutter特性的情况，检查是否有控制会话
#[cfg(not(any(not(target_os = "windows"), feature = "flutter")))]
fn has_no_controlling_conns() -> bool {
    let app_exe = format!("{}.exe", crate::get_app_name().to_lowercase()); // 获取应用程序可执行文件名
    for arg in [
        "--connect",
        "--play",
        "--file-transfer",
        "--view-camera",
        "--port-forward",
        "--rdp",
    ] {
        if !crate::platform::get_pids_of_process_with_first_arg(&app_exe, arg).is_empty() {
            return false; // 如果发现有相关的进程，则返回false
        }
    }
    true // 如果没有找到相关进程，则返回true
}

// 启动自动更新检查线程，并返回一个Sender实例用于发送更新消息
fn start_auto_update_check() -> Sender<UpdateMsg> {
    let (tx, rx) = channel(); // 创建通道，用于在主线程和子线程之间通信
    std::thread::spawn(move || start_auto_update_check_(rx)); // 启动一个新线程来处理自动更新检查
    return tx; // 返回Sender实例，用于发送更新消息
}

// 自动更新检查的主要逻辑函数，在单独的线程中运行
fn start_auto_update_check_(rx_msg: Receiver<UpdateMsg>) {
    // 初始延迟30秒后开始执行第一次更新检查
    std::thread::sleep(Duration::from_secs(30));
    if let Err(e) = check_update(false) {
        log::error!("Error checking for updates: {}", e); // 记录错误信息
    }

    // 定义最小检查间隔时间和重试间隔时间
    const MIN_INTERVAL: Duration = Duration::from_secs(60 * 10); // 最小检查间隔10分钟
    const RETRY_INTERVAL: Duration = Duration::from_secs(60 * 30); // 重试间隔30分钟
    let mut last_check_time = Instant::now(); // 记录上次检查的时间点
    let mut check_interval = DUR_ONE_DAY; // 初始化检查间隔为一天
    loop {
        // 接收消息或超时等待
        let recv_res = rx_msg.recv_timeout(check_interval);
        match &recv_res {
            Ok(UpdateMsg::CheckUpdate) | Err(_) => {
                // 如果距离上次检查时间小于最小间隔，则跳过本次检查
                if last_check_time.elapsed() < MIN_INTERVAL {
                    // log::debug!("Update check skipped due to minimum interval.");
                    continue;
                }
                // 如果存在活动连接，则调整检查间隔并跳过本次检查
                // Don't check update if there are alive connections.
                if !has_no_active_conns() {
                    check_interval = RETRY_INTERVAL;
                    continue;
                }
                // 执行更新检查，如果手动触发则忽略配置中的自动更新选项
                if let Err(e) = check_update(matches!(recv_res, Ok(UpdateMsg::CheckUpdate))) {
                    log::error!("Error checking for updates: {}", e); // 记录错误信息
                    check_interval = RETRY_INTERVAL; // 设置重试间隔
                } else {
                    last_check_time = Instant::now(); // 更新上次检查的时间点
                    check_interval = DUR_ONE_DAY; // 恢复默认的一天检查间隔
                }
            }
            Ok(UpdateMsg::Exit) => break, // 收到Exit消息时退出循环
        }
    }
}

// 检查软件更新的主要逻辑函数
fn check_update(manually: bool) -> ResultType<()> {
    #[cfg(target_os = "windows")]
    // 检查是否通过MSI安装
    let is_msi = crate::platform::is_msi_installed()?;
    // 如果不是手动触发且配置中不允许自动更新，则直接返回成功
    if !(manually || config::Config::get_bool_option(config::keys::OPTION_ALLOW_AUTO_UPDATE)) {
        return Ok(());
    }
    // 调用通用的软件更新检查函数
    if !do_check_software_update().is_ok() {
        // 忽略错误情况
        // ignore
        return Ok(());
    }

    // 获取更新URL
    let update_url = crate::common::SOFTWARE_UPDATE_URL.lock().unwrap().clone();
    // 如果没有可用的更新，则记录日志并返回成功
    if update_url.is_empty() {
        log::debug!("No update available.");
    } else {
        // 构建下载URL
        let download_url = update_url.replace("tag", "download");
        let version = download_url.split('/').last().unwrap_or_default();
        #[cfg(target_os = "windows")]
        // 根据是否是MSI安装构建不同的下载URL
        let download_url = if cfg!(feature = "flutter") {
            format!(
                "{}/rustdesk-{}-x86_64.{}",
                download_url,
                version,
                if is_msi { "msi" } else { "exe" }
            )
        } else {
            format!("{}/rustdesk-{}-x86-sciter.exe", download_url, version)
        };
        log::debug!("New version available: {}", &version); // 记录新版本号
        // 创建HTTP客户端
        let client = create_http_client();
        // 从URL获取下载文件路径
        let Some(file_path) = get_download_file_from_url(&download_url) else {
            bail!("Failed to get the file path from the URL: {}", download_url); // 抛出错误
        };
        // 检查本地文件是否存在并且大小一致
        let mut is_file_exists = false;
        if file_path.exists() {
            // Check if the file size is the same as the server file size
            // If the file size is the same, we don't need to download it again.
            let file_size = std::fs::metadata(&file_path)?.len(); // 获取本地文件大小
            let response = client.head(&download_url).send()?; // 发送HEAD请求获取服务器文件元数据
            if !response.status().is_success() {
                bail!("Failed to get the file size: {}", response.status()); // 抛出错误
            }
            let total_size = response
                .headers()
                .get(reqwest::header::CONTENT_LENGTH)
                .and_then(|ct_len| ct_len.to_str().ok())
                .and_then(|ct_len| ct_len.parse::<u64>().ok());
            let Some(total_size) = total_size else {
                bail!("Failed to get content length"); // 抛出错误
            };
            if file_size == total_size {
                is_file_exists = true; // 文件大小一致，无需重新下载
            } else {
                std::fs::remove_file(&file_path)?; // 文件大小不一致，删除旧文件
            }
        }
        // 下载新版本文件
        if !is_file_exists {
            let response = client.get(&download_url).send()?; // 发送GET请求下载文件
            if !response.status().is_success() {
                bail!(
                    "Failed to download the new version file: {}",
                    response.status() // 抛出错误
                );
            }
            let file_data = response.bytes()?; // 获取文件内容
            let mut file = std::fs::File::create(&file_path)?; // 创建新的文件
            file.write_all(&file_data)?; // 将文件内容写入文件
        }
        // 再次检查是否有活动连接，如果没有则进行更新
        // We have checked if the `conns`` is empty before, but we need to check again.
        // No need to care about the downloaded file here, because it's rare case that the `conns` are empty
        // before the download, but not empty after the download.
        if has_no_active_conns() {
            #[cfg(target_os = "windows")]
            update_new_version(is_msi, &version, &file_path); // 在Windows上更新新版本
        }
    }
    Ok(())
}

// 在Windows系统上更新新版本的逻辑
#[cfg(target_os = "windows")]
fn update_new_version(is_msi: bool, version: &str, file_path: &PathBuf) {
    log::debug!("New version is downloaded, update begin, is msi: {is_msi}, version: {version}, file: {:?}", file_path.to_str()); // 记录更新开始的日志
    if let Some(p) = file_path.to_str() {
        if let Some(session_id) = crate::platform::get_current_process_session_id() {
            if is_msi {
                match crate::platform::update_me_msi(p, true) {
                    Ok(_) => {
                        log::debug!("New version \"{}\" updated.", version); // 记录更新成功的日志
                    }
                    Err(e) => {
                        log::error!(
                            "Failed to install the new msi version  \"{}\": {}",
                            version,
                            e // 记录安装失败的错误信息
                        );
                    }
                }
            } else {
                match crate::platform::launch_privileged_process(
                    session_id,
                    &format!("{} --update", p),
                ) {
                    Ok(h) => {
                        if h.is_null() {
                            log::error!("Failed to update to the new version: {}", version); // 记录更新失败的错误信息
                        }
                    }
                    Err(e) => {
                        log::error!("Failed to run the new version: {}", e); // 记录运行失败的错误信息
                    }
                }
            }
        } else {
            log::error!(
                "Failed to get the current process session id, Error {}",
                io::Error::last_os_error() // 记录获取session ID失败的错误信息
            );
        }
    } else {
        // unreachable!()
        log::error!(
            "Failed to convert the file path to string: {}",
            file_path.display() // 记录文件路径转换失败的错误信息
        );
    }
}

// 根据URL获取下载文件的路径
pub fn get_download_file_from_url(url: &str) -> Option<PathBuf> {
    let filename = url.split('/').last()?; // 从URL中提取文件名
    Some(std::env::temp_dir().join(filename)) // 返回临时目录下的文件路径
}
