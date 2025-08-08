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

#[cfg(target_os = "ios")]
pub fn get_device_id() -> ResultType<String> {
    get_fallback_device_id()
}

#[cfg(target_os = "android")]
pub fn get_device_id() -> ResultType<String> {
    match get_android_id() {
        Ok(id) => {
            if id.is_empty() {
                Ok("".to_string())
            } else {
                Ok(id)
            }
        }
        Err(_) => Ok("".to_string()),
    }
}

#[cfg(target_os = "android")]
fn get_android_id() -> ResultType<String> {
    use jni::{
        objects::{JValue, JObject, JString},
        JNIEnv,
    };

    // 1. 获取 Android 全局上下文
    let ctx = ndk_context::android_context();
    let vm = unsafe { jni::JavaVM::from_raw(ctx.vm().cast()) }?;
    let env = vm.attach_current_thread()?;
    let context = JObject::from(ctx.context().cast());

    // 2. 获取 ContentResolver
    let content_resolver = env
        .call_method(
            context,
            "getContentResolver",
            "()Landroid/content/ContentResolver;",
            &[],
        )?
        .l()?;

    // 3. 获取 Settings.Secure 类
    let settings_secure = env.find_class("android/provider/Settings$Secure")?;

    // 4. 调用 getString 方法获取 ANDROID_ID
    let jstring = env
        .call_static_method(
            settings_secure,
            "getString",
            "(Landroid/content/ContentResolver;Ljava/lang/String;)Ljava/lang/String;",
            &[
                JValue::Object(&content_resolver),
                JValue::Object(&env.new_string("android_id")?.into()),
            ],
        )?
        .l()?;

    // 5. 转换为 Rust 字符串
    let android_id: String = env.get_string(unsafe { JString::from_raw(jstring.into_raw()) })?.into();

    // 如果为空，返回空字符串 ""，否则返回实际值
    Ok(android_id)
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

#[cfg(any(target_os = "linux", target_os = "ios"))]
fn get_fallback_device_id() -> ResultType<String> {
    #[cfg(not(target_os = "android"))]
    {
        use mac_address::get_mac_address;

        match get_mac_address() {
            Ok(Some(addr)) => Ok(addr.to_string()),
            Ok(None) => Err(anyhow!("No MAC address found")),
            Err(e) => Err(anyhow!("MAC address error: {}", e)),
        }
    }
    
    #[cfg(target_os = "android")]
    {
        Ok("".to_string())
    }
}