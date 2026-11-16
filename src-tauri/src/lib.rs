mod breached_passwords;
mod email_headers;
mod email_scam;
mod finding;
mod url_check;
mod windows_security;

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        // Every command the interface is allowed to call is listed here.
        .invoke_handler(tauri::generate_handler![
            breached_passwords::check_breached_password,
            email_headers::analyse_email_headers,
            email_scam::check_email_scam,
            url_check::check_url,
            windows_security::check_windows_security
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
