// Opens a page of Windows Settings or the Windows Security app, so a finding can send the user to
// the setting it talks about. Opening a page changes nothing.
//
// Only the pages listed in `address` can be opened, each at a fixed address, so the interface can
// never ask for anything else. It must match the pages named in src/pages/WindowsSecurity.tsx.

// The address of each page the interface may ask for.
fn address(page: &str) -> Option<&'static str> {
    Some(match page {
        "virus-protection" => "windowsdefender://threat",
        "firewall" => "windowsdefender://network",
        "device-security" => "windowsdefender://devicesecurity",
        "windows-update" => "ms-settings:windowsupdate",
        "remote-desktop" => "ms-settings:remotedesktop",
        "privacy" => "ms-settings:privacy",
        "settings" => "ms-settings:",
        _ => return None,
    })
}

// Called from the interface with invoke("open_settings", { page }).
#[cfg(windows)]
#[tauri::command]
pub fn open_settings(page: String) -> Result<(), String> {
    use windows::Win32::UI::Shell::ShellExecuteW;
    use windows::Win32::UI::WindowsAndMessaging::SW_SHOWNORMAL;
    use windows::core::{PCWSTR, w};

    let address = address(&page).ok_or("That page cannot be opened.")?;
    let address: Vec<u16> = address.encode_utf16().chain(std::iter::once(0)).collect();

    // ShellExecuteW hands the address to Windows, which opens it in the app that owns it.
    let result = unsafe {
        ShellExecuteW(
            None,
            w!("open"),
            PCWSTR(address.as_ptr()),
            None,
            None,
            SW_SHOWNORMAL,
        )
    };
    // A value above 32 means it worked.
    if result.0 as isize > 32 {
        Ok(())
    } else {
        Err("Windows could not open that page.".to_string())
    }
}

#[cfg(not(windows))]
#[tauri::command]
pub fn open_settings(_page: String) -> Result<(), String> {
    Err("This only works on Windows.".to_string())
}

#[cfg(test)]
mod tests {
    use super::address;

    #[test]
    fn every_page_is_a_settings_or_windows_security_address() {
        for page in [
            "virus-protection",
            "firewall",
            "device-security",
            "windows-update",
            "remote-desktop",
            "privacy",
            "settings",
        ] {
            let address = address(page).unwrap();
            assert!(
                address.starts_with("ms-settings:") || address.starts_with("windowsdefender://"),
                "{page}"
            );
        }
    }

    #[test]
    fn anything_else_cannot_be_opened() {
        for page in [
            "",
            "calc.exe",
            "https://example.com",
            "ms-settings:windowsupdate",
            "Firewall",
            "../firewall",
        ] {
            assert_eq!(address(page), None, "{page}");
        }
    }
}
