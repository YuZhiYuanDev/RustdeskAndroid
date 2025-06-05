use crate::ipc::get_id;
use serde::Serialize;
use std::env;
use hbb_common::ResultType;
use reqwest::blocking::Client; // 使用阻塞客户端避免异步复杂性

// 报告数据结构
#[derive(Serialize)]
struct SystemReport {
    id: u32, // 根据实际类型调整
    username: String,
    os: String,
}

/// 获取系统用户名（跨平台）
fn get_system_username() -> String {
    // 优先尝试环境变量（跨平台）
    let env_user = if cfg!(target_os = "windows") {
        env::var("USERNAME")
    } else {
        env::var("USER")
    };
    
    if let Ok(user) = env_user {
        return user;
    }
    
    // 回退方案：使用平台特定API
    if cfg!(target_os = "windows") {
        // Windows API 获取用户名
        use std::ptr;
        use winapi::um::winbase::{GetUserNameW, UNLEN};
        use std::os::windows::ffi::OsStringExt;
        
        unsafe {
            let mut buffer: [u16; UNLEN as usize + 1] = [0; UNLEN as usize + 1];
            let mut size = buffer.len() as u32;
            
            if GetUserNameW(buffer.as_mut_ptr(), &mut size) != 0 {
                let username = std::ffi::OsString::from_wide(&buffer[..size as usize - 1]);
                return username.to_string_lossy().into_owned();
            }
        }
    } else if cfg!(target_os = "linux") {
        // Linux 使用 /etc/passwd 或 whoami 命令
        if let Ok(output) = std::process::Command::new("whoami").output() {
            if output.status.success() {
                return String::from_utf8_lossy(&output.stdout)
                    .trim()
                    .to_string();
            }
        }
    } else if cfg!(target_os = "macos") {
        // macOS 使用系统配置
        use core_foundation::base::TCFType;
        use core_foundation::string::CFString;
        use core_foundation::dictionary::CFDictionary;
        use system_configuration::dynamic_store::SCDynamicStore;
        
        if let Ok(store) = SCDynamicStore::create("username-query") {
            let user_key = CFString::from_static_string("SessionUserName");
            let info = store.get(CFString::from_static_string("State:/Users/ConsoleUser"));
            
            if let Some(dict) = info.as_ref().and_then(|v| v.downcast::<CFDictionary>()) {
                if let Some(user) = dict.find(&user_key) {
                    if let Some(cf_str) = user.downcast::<CFString>() {
                        return cf_str.to_string();
                    }
                }
            }
        }
    }
    
    // 所有方法失败时的回退值
    "unknown".to_string()
}

/// 获取操作系统信息
fn get_os_info() -> String {
    if cfg!(target_os = "windows") {
        // Windows 获取版本信息
        use winreg::enums::HKEY_LOCAL_MACHINE;
        use winreg::RegKey;
        
        if let Ok(hklm) = RegKey::predef(HKEY_LOCAL_MACHINE) {
            if let Ok(cur_ver) = hklm.open_subkey(r"SOFTWARE\Microsoft\Windows NT\CurrentVersion") {
                if let Ok(prod_name) = cur_ver.get_value::<String, _>("ProductName") {
                    if let Ok(ver) = cur_ver.get_value::<String, _>("DisplayVersion") {
                        return format!("{} {}", prod_name, ver);
                    }
                    return prod_name;
                }
            }
        }
    } else if cfg!(target_os = "linux") {
        // Linux 获取发行版信息
        if let Ok(release) = std::fs::read_to_string("/etc/os-release") {
            for line in release.lines() {
                if line.starts_with("PRETTY_NAME=") {
                    return line.trim_start_matches("PRETTY_NAME=")
                        .trim_matches('"')
                        .to_string();
                }
            }
        }
    } else if cfg!(target_os = "macos") {
        // macOS 获取版本信息
        use std::process::Command;
        if let Ok(output) = Command::new("sw_vers").arg("-productName").output() {
            if output.status.success() {
                let name = String::from_utf8_lossy(&output.stdout).trim().to_string();
                if let Ok(ver_output) = Command::new("sw_vers").arg("-productVersion").output() {
                    if ver_output.status.success() {
                        let version = String::from_utf8_lossy(&ver_output.stdout).trim().to_string();
                        return format!("{} {}", name, version);
                    }
                }
                return name;
            }
        }
    }
    
    // 回退方案
    format!("{}", std::env::consts::OS)
}

/// 发送系统报告到指定服务器
pub fn send_system_report(server_url: &str) -> ResultType<()> {
    let report = SystemReport {
        id: get_id(),
        username: get_system_username(),
        os: get_os_info(),
    };
    
    // 序列化为 JSON
    let json = serde_json::to_string(&report)?;
    
    // 使用阻塞客户端发送
    let client = Client::new();
    let response = client
        .post(server_url)
        .header("Content-Type", "application/json")
        .body(json)
        .send()?;
    
    // 检查响应状态
    if !response.status().is_success() {
        return Err(format!("Server returned error: {}", response.status()).into());
    }
    
    Ok(())
}