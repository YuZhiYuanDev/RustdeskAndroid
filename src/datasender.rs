use serde::Serialize;
use hbb_common::{ResultType, bail, tokio};
use reqwest::Client;
use std::collections::HashMap;
use std::time::Duration;
use std::future::Future;
use hbb_common::tokio::time;
use chrono::Utc;

// 统一的数据类型枚举 (可扩展)
#[derive(Debug, Serialize, Clone)]
#[serde(tag = "data_type", content = "payload")]
pub enum DataPayload {
    User { id: String, username: String },
    // 添加其他数据类型
    // DeviceInfo { ... },
    // PerformanceMetrics { ... },
    // 自定义类型
    Custom { type_name: String, data: HashMap<String, String> },
}

/// 创建用户数据
pub fn create_user_data(id: &str, username: &str) -> DataPayload {
    DataPayload::User {
        id: id.to_string(),
        username: username.to_string(),
    }
}

/// 创建自定义数据
pub fn create_custom_data(type_name: &str, data: HashMap<&str, &str>) -> DataPayload {
    let converted_data = data.iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();
    
    DataPayload::Custom {
        type_name: type_name.to_string(),
        data: converted_data,
    }
}

/// 创建自定义数据 (使用字符串值)
pub fn create_custom_data_str(type_name: &str, data: HashMap<&str, String>) -> DataPayload {
    let converted_data = data.iter()
        .map(|(k, v)| (k.to_string(), v.clone()))
        .collect();
    
    DataPayload::Custom {
        type_name: type_name.to_string(),
        data: converted_data,
    }
}

/// 异步发送函数
pub async fn send_data_async(url: &str, data: &DataPayload) -> ResultType<()> {
    // 创建合适的客户端
    let client = create_client().await?;
    
    let response = client
        .post(url)
        .json(&serde_json::json!({
            "payload": data,
            "timestamp": Utc::now().to_rfc3339(),
        }))
        .send()
        .await?
        .error_for_status()?;
    
    // 记录响应状态
    log::info!("Data sent to {}: status={}", url, response.status());
    Ok(())
}

/// 带有重试逻辑的异步发送函数
pub async fn send_data_with_retry(
    url: &str, 
    data: &DataPayload,
    max_retries: usize,
    base_delay: Duration
) -> ResultType<()> {
    let mut retries = 0;
    let mut delay = base_delay;
    
    while retries <= max_retries {
        match send_data_async(url, data).await {
            Ok(_) => return Ok(()),
            Err(e) => {
                if retries == max_retries {
                    log::error!("Failed to send data after {} retries: {}", max_retries, e);
                    return Err(e);
                }
                
                log::warn!("Send attempt {} failed: {}. Retrying in {:?}...", 
                    retries + 1, e, delay);
                
                // 指数退避延迟
                time::sleep(delay).await;
                delay = delay * 2;
                retries += 1;
            }
        }
    }
    
    bail!("Failed to send data after {} retries", max_retries)
}

/// 批量发送函数 (异步)
pub async fn send_batch_async(url: &str, data: &[DataPayload]) -> ResultType<()> {
    if data.is_empty() {
        bail!("No data to send");
    }
    
    // 创建合适的客户端
    let client = create_client().await?;
    
    let response = client
        .post(url)
        .json(&serde_json::json!({
            "batch": data,
            "count": data.len(),
            "timestamp": Utc::now().to_rfc3339(),
        }))
        .send()
        .await?
        .error_for_status()?;
    
    log::info!("Batch of {} items sent to {}: status={}", 
        data.len(), url, response.status());
    Ok(())
}

/// 创建合适的HTTP客户端
async fn create_client() -> ResultType<Client> {
    // 根据平台构建不同配置的客户端
    #[cfg(any(target_os = "macos", target_os = "windows"))]
    {
        Ok(Client::builder()
            .timeout(Duration::from_secs(30))
            .build()?)
    }
    
    #[cfg(not(any(target_os = "macos", target_os = "windows")))]
    {
        Ok(Client::builder()
            .timeout(Duration::from_secs(30))
            .build()?)
    }
}

/// 用于测试的模拟发送函数
#[cfg(test)]
pub async fn mock_send_data_async(url: &str, data: &DataPayload) -> ResultType<()> {
    log::debug!("Mock sending to {}: {:?}", url, data);
    // 模拟网络延迟
    time::sleep(Duration::from_millis(50)).await;
    Ok(())
}