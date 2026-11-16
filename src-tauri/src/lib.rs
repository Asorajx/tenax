mod finding;
mod windows_security;

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        // Every command the interface is allowed to call is listed here.
        .invoke_handler(tauri::generate_handler![
            windows_security::check_windows_security
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
