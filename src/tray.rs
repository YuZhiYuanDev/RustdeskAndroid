// 引入必要的模块和函数
use crate::client::translate; // 翻译模块
// Windows 特定：使用 IPC（进程间通信）模块中的 Data 结构
#[cfg(windows)]
use crate::ipc::Data;
// 使用 tokio 库用于异步处理
#[cfg(windows)]
use hbb_common::tokio;
// 公共库中的日志和错误处理工具
use hbb_common::{allow_err, log};
// 标准库中用于线程同步的 Arc 和 Mutex
use std::sync::{Arc, Mutex};
// Windows 特定：使用 Duration 表示时间间隔
#[cfg(windows)]
use std::time::Duration;

/// 启动系统托盘图标的功能
pub fn start_tray() {
    // // 如果配置了隐藏托盘图标，则根据平台执行不同操作
    // if crate::ui_interface::get_builtin_option(hbb_common::config::keys::OPTION_HIDE_TRAY) == "Y" {
        // macOS 上，如果隐藏托盘图标，则进入无限循环，防止程序退出
        #[cfg(target_os = "macos")]
        {
            loop {
                std::thread::sleep(std::time::Duration::from_secs(1));
            }
        }
        // 非 macOS 平台则直接返回，不创建托盘图标
        #[cfg(not(target_os = "macos"))]
        {
            return;
        }
    // }
    // // 创建托盘图标，允许出错但记录错误信息
    // allow_err!(make_tray());

    #[cfg(target_os = "linux")]
    crate::server::check_zombie();

    allow_err!(make_tray());
}

/// 实际创建系统托盘图标的函数
fn make_tray() -> hbb_common::ResultType<()> {
    // 导入相关模块
    // https://github.com/tauri-apps/tray-icon/blob/dev/examples/tao.rs
    use hbb_common::anyhow::Context;
    use tao::event_loop::{ControlFlow, EventLoopBuilder};
    use tray_icon::{
        menu::{Menu, MenuEvent, MenuItem},
        TrayIcon, TrayIconBuilder, TrayIconEvent as TrayEvent,
    };
    // 根据操作系统选择不同的托盘图标文件
    let icon;
    #[cfg(target_os = "macos")]
    {
        icon = include_bytes!("../res/mac-tray-dark-x2.png"); // use as template, so color is not important
    }
    #[cfg(not(target_os = "macos"))]
    {
        icon = include_bytes!("../res/tray-icon.ico");
    }

    // 加载图标数据，并转换为 RGBA 格式
    let (icon_rgba, icon_width, icon_height) = {
        let image = load_icon_from_asset()
            .unwrap_or(image::load_from_memory(icon).context("Failed to open icon path")?)
            .into_rgba8();
        let (width, height) = image.dimensions();
        let rgba = image.into_raw();
        (rgba, width, height)
    };
    // 创建托盘图标对象
    let icon = tray_icon::Icon::from_rgba(icon_rgba, icon_width, icon_height)
        .context("Failed to open icon")?;

    // 创建事件循环
    let mut event_loop = EventLoopBuilder::new().build();

    // 创建托盘菜单
    let tray_menu = Menu::new();
    let quit_i = MenuItem::new(translate("Stop service".to_owned()), true, None); // 停止服务
    let open_i = MenuItem::new(translate("Open".to_owned()), true, None); // 打开主界面
    tray_menu.append_items(&[&open_i, &quit_i]).ok(); // 添加菜单项
    // 动态生成托盘提示文本（tooltip）
    let tooltip = |count: usize| {
        if count == 0 {
            format!(
                "{} {}",
                crate::get_app_name(),
                translate("Service is running".to_owned()),
            )
        } else {
            format!(
                "{} - {}\n{}",
                crate::get_app_name(),
                translate("Ready".to_owned()),
                translate("{".to_string() + &format!("{count}") + "} sessions"),
            )
        }
    };
    // 托盘图标实例，使用 Arc<Mutex<Option<TrayIcon>>> 来支持跨线程访问
    let mut _tray_icon: Arc<Mutex<Option<TrayIcon>>> = Default::default();

    // 接收菜单点击事件
    let menu_channel = MenuEvent::receiver();
    // 接收托盘图标点击事件
    let tray_channel = TrayEvent::receiver();
    // Windows 特定：设置 IPC 通道，用于获取会话数量
    #[cfg(windows)]
    let (ipc_sender, ipc_receiver) = std::sync::mpsc::channel::<Data>();

    // 打开主界面的操作函数
    let open_func = move || {
        if cfg!(not(feature = "flutter")) {
            crate::run_me::<&str>(vec![]).ok();
            return;
        }
        // macOS：调用特定方法打开无标题文件
        #[cfg(target_os = "macos")]
        crate::platform::macos::handle_application_should_open_untitled_file();
        // Windows：直接运行主程序
        #[cfg(target_os = "windows")]
        {
            // Do not use "start uni link" way, it may not work on some Windows, and pop out error
            // dialog, I found on one user's desktop, but no idea why, Windows is shit.
            // Use `run_me` instead.
            // `allow_multiple_instances` in `flutter/windows/runner/main.cpp` allows only one instance without args.
            crate::run_me::<&str>(vec![]).ok();
        }
        // Linux：尝试通过 D-Bus 调用新连接，失败则运行主程序
        #[cfg(target_os = "linux")]
        {
            // Do not use "xdg-open", it won't read the config.
            if crate::dbus::invoke_new_connection(crate::get_uri_prefix()).is_err() {
                if let Ok(task) = crate::run_me::<&str>(vec![]) {
                    crate::server::CHILD_PROCESS.lock().unwrap().push(task);
                }
            }
        }
    };

    // Windows 特定：启动一个线程用于查询当前会话数
    #[cfg(windows)]
    std::thread::spawn(move || {
        start_query_session_count(ipc_sender.clone());
    });
    // Windows 特定：记录上一次点击时间，防双击触发两次
    #[cfg(windows)]
    let mut last_click = std::time::Instant::now();
    // macOS 特定：设置事件循环为“附件”模式，隐藏 Dock 图标
    #[cfg(target_os = "macos")]
    {
        use tao::platform::macos::EventLoopExtMacOS;
        event_loop.set_activation_policy(tao::platform::macos::ActivationPolicy::Accessory);
    }
    // 运行事件循环
    event_loop.run(move |event, _, control_flow| {
        *control_flow = ControlFlow::WaitUntil(
            std::time::Instant::now() + std::time::Duration::from_millis(100),
        );

        // 初始化时创建托盘图标
        if let tao::event::Event::NewEvents(tao::event::StartCause::Init) = event {
            // We create the icon once the event loop is actually running
            // to prevent issues like https://github.com/tauri-apps/tray-icon/issues/90
            let tray = TrayIconBuilder::new()
                .with_menu(Box::new(tray_menu.clone()))
                .with_tooltip(tooltip(0))
                .with_icon(icon.clone())
                .with_icon_as_template(true) // mac only
                .build();
            match tray {
                Ok(tray) => _tray_icon = Arc::new(Mutex::new(Some(tray))),
                Err(err) => {
                    log::error!("Failed to create tray icon: {}", err);
                }
            };

            // macOS 特定：强制刷新 RunLoop，确保图标立即显示
            // We have to request a redraw here to have the icon actually show up.
            // Tao only exposes a redraw method on the Window so we use core-foundation directly.
            #[cfg(target_os = "macos")]
            unsafe {
                use core_foundation::runloop::{CFRunLoopGetMain, CFRunLoopWakeUp};

                let rl = CFRunLoopGetMain();
                CFRunLoopWakeUp(rl);
            }
        }

        // 处理菜单点击事件
        if let Ok(event) = menu_channel.try_recv() {
            if event.id == quit_i.id() {
                // 点击“停止服务”时卸载服务或退出程序
                /* failed in windows, seems no permission to check system process
                if !crate::check_process("--server", false) {
                    *control_flow = ControlFlow::Exit;
                    return;
                }
                */
                if !crate::platform::uninstall_service(false, false) {
                    *control_flow = ControlFlow::Exit;
                }
            } else if event.id == open_i.id() {
                // 点击“打开”时启动主界面
                open_func();
            }
        }

        // 处理托盘图标点击事件
        if let Ok(_event) = tray_channel.try_recv() {
            #[cfg(target_os = "windows")]
            match _event {
                TrayEvent::Click {
                    button,
                    button_state,
                    ..
                } => {
                    // 左键单击且释放时打开主界面
                    if button == tray_icon::MouseButton::Left
                        && button_state == tray_icon::MouseButtonState::Up
                    {
                        if last_click.elapsed() < std::time::Duration::from_secs(1) {
                            return; // 防止快速双击重复打开
                        }
                        open_func();
                        last_click = std::time::Instant::now();
                    }
                }
                _ => {}
            }
        }

        // Windows 特定：接收 IPC 消息更新会话数量
        #[cfg(windows)]
        if let Ok(data) = ipc_receiver.try_recv() {
            match data {
                Data::ControlledSessionCount(count) => {
                    _tray_icon
                        .lock()
                        .unwrap()
                        .as_mut()
                        .map(|t| t.set_tooltip(Some(tooltip(count))));
                }
                _ => {}
            }
        }
    });
}

/// Windows 特定：异步查询受控会话数量的函数
#[cfg(windows)]
#[tokio::main(flavor = "current_thread")]
async fn start_query_session_count(sender: std::sync::mpsc::Sender<Data>) {
    let mut last_count = 0;
    loop {
        if let Ok(mut c) = crate::ipc::connect(1000, "").await {
            let mut timer = crate::rustdesk_interval(tokio::time::interval(Duration::from_secs(1)));
            loop {
                tokio::select! {
                    res = c.next() => {
                        match res {
                            Err(err) => {
                                log::error!("ipc connection closed: {}", err);
                                break;
                            }

                            Ok(Some(Data::ControlledSessionCount(count))) => {
                                if count != last_count {
                                    last_count = count;
                                    sender.send(Data::ControlledSessionCount(count)).ok();
                                }
                            }
                            _ => {}
                        }
                    }

                    _ = timer.tick() => {
                        c.send(&Data::ControlledSessionCount(0)).await.ok();
                    }
                }
            }
        }
        hbb_common::sleep(1.).await;
    }
}

/// 尝试从 assets 文件夹加载自定义图标
fn load_icon_from_asset() -> Option<image::DynamicImage> {
    // 获取当前可执行文件路径
    let Some(path) = std::env::current_exe().map_or(None, |x| x.parent().map(|x| x.to_path_buf()))
    else {
        return None;
    };
    // 根据平台构建图标路径
    #[cfg(target_os = "macos")]
    let path = path.join("../Frameworks/App.framework/Resources/flutter_assets/assets/icon.png");
    #[cfg(windows)]
    let path = path.join(r"data\flutter_assets\assets\icon.png");
    #[cfg(target_os = "linux")]
    let path = path.join(r"data/flutter_assets/assets/icon.png");
    // 如果图标存在则加载并返回
    if path.exists() {
        if let Ok(image) = image::open(path) {
            return Some(image);
        }
    }
    None
}
