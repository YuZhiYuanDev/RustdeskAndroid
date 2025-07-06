use hbb_common::{ResultType, anyhow::anyhow};

#[cfg(not(any(target_os = "android", target_os = "ios")))]
pub fn get_device_id() -> ResultType<String> {
    cfg_if::cfg_if! {
        if #[cfg(target_os = "windows")] {
            get_windows_device_id()
        } else if #[cfg(target_os = "macos")] {
            get_macos_device_id()
        } else if #[cfg(target_os = "linux")] {
            get_linux_device_id()
        } else {
            Err(anyhow!("Unsupported platform"))
        }
    }
}

#[cfg(any(target_os = "android", target_os = "ios"))]
pub fn get_device_id() -> ResultType<String> {
    get_fallback_device_id()
}

#[cfg(target_os = "windows")]
fn get_windows_device_id() -> ResultType<String> {
    use winreg::RegKey;
    use winreg::enums::HKEY_LOCAL_MACHINE;

    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
    let path = r"SOFTWARE\Microsoft\Cryptography";
    let key = hklm.open_subkey(path)?;
    
    let guid: String = key.get_value("MachineGuid")?;
    Ok(guid)
}

#[cfg(target_os = "macos")]
fn get_macos_device_id() -> ResultType<String> {
    use std::process::Command;

    let output = Command::new("ioreg")
        .arg("-rd1")
        .arg("-c")
        .arg("IOPlatformExpertDevice")
        .output()
        .map_err(|e| anyhow!("Failed to execute ioreg: {}", e))?;
    
    if !output.status.success() {
        return Err(anyhow!("ioreg command failed"));
    }
    
    let output_str = String::from_utf8_lossy(&output.stdout);
    
    for line in output_str.lines() {
        if line.contains("IOPlatformUUID") {
            if let Some(start) = line.find('"') {
                let rest = &line[start + 1..];
                if let Some(end) = rest.find('"') {
                    return Ok(rest[..end].to_string());
                }
            }
        }
    }
    
    Err(anyhow!("Failed to find IOPlatformUUID"))
}

#[cfg(target_os = "linux")]
fn get_linux_device_id() -> ResultType<String> {
    use std::fs;
    
    let paths = [
        "/etc/machine-id",
        "/var/lib/dbus/machine-id",
    ];
    
    for path in &paths {
        if let Ok(contents) = fs::read_to_string(path) {
            let trimmed = contents.trim();
            if !trimmed.is_empty() {
                return Ok(trimmed.to_string());
            }
        }
    }
    
    get_fallback_device_id()
}

#[allow(unused)]
fn get_fallback_device_id() -> ResultType<String> {
    use mac_address::get_mac_address;

    match get_mac_address() {
        Ok(Some(addr)) => Ok(addr.to_string()),
        Ok(None) => Err(anyhow!("No MAC address found")),
        Err(e) => Err(anyhow!("MAC address error: {}", e)),
    }
}