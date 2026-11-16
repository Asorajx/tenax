mod breached_passwords;
mod dns_lookup;
mod email_headers;
mod email_scam;
mod finding;
mod ip_info;
mod url_check;
mod windows_security;

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        // Every command the interface is allowed to call is listed here.
        .invoke_handler(tauri::generate_handler![
            breached_passwords::check_breached_password,
            dns_lookup::lookup_dns,
            email_headers::analyse_email_headers,
            email_scam::check_email_scam,
            ip_info::inspect_ip,
            ip_info::lookup_ip_owner,
            ip_info::reverse_dns,
            url_check::check_url,
            windows_security::check_windows_security
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
