mod breached_passwords;
mod dns_lookup;
mod email_headers;
mod email_scam;
mod finding;
mod ip_info;
mod network;
mod qr_scam;
mod tls_check;
mod url_check;
mod windows_security;

// The window starts hidden, so the interface can choose its look before it appears. If the interface
// never does, this shows it anyway, so the window can never stay hidden.
const SHOW_AFTER: std::time::Duration = std::time::Duration::from_secs(4);

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .setup(|app| {
            let handle = app.handle().clone();
            std::thread::spawn(move || {
                std::thread::sleep(SHOW_AFTER);
                if let Some(window) = tauri::Manager::get_webview_window(&handle, "main") {
                    let _ = window.show();
                }
            });
            Ok(())
        })
        // Every command the interface is allowed to call is listed here.
        .invoke_handler(tauri::generate_handler![
            breached_passwords::check_breached_password,
            dns_lookup::lookup_dns,
            email_headers::analyse_email_headers,
            email_scam::check_email_scam,
            ip_info::inspect_ip,
            ip_info::lookup_ip_owner,
            ip_info::reverse_dns,
            tls_check::check_tls,
            network::network_access,
            network::set_network_access,
            qr_scam::check_qr,
            url_check::check_url,
            windows_security::check_windows_security,
            windows_security::settings::open_settings
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
