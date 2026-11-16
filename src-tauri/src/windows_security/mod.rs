// Windows Security check: reads antivirus, firewall and Windows Update settings.
// Nothing is changed on the PC.
//
// reader.rs   talks to Windows and returns raw values
// findings.rs turns those values into findings, with no Windows code in it

mod findings;
#[cfg(windows)]
mod reader;

use crate::finding::Finding;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProductState {
    On,
    Off,
    Snoozed,
    Expired,
}

// An antivirus or firewall product registered with Windows Security Center.
pub struct SecurityProduct {
    pub name: String,
    pub state: ProductState,
    pub definitions_up_to_date: bool,
}

pub struct FirewallProfiles {
    pub domain: bool,
    pub private: bool,
    pub public: bool,
}

pub struct UpdateStatus {
    // Whether the components automatic updates need are available. Not a user setting.
    pub service_enabled: bool,
    // None means Windows has no record of it.
    pub days_since_check: Option<f64>,
    pub days_since_install: Option<f64>,
    pub restart_pending: bool,
    // Such as "Windows 11 25H2 · build 26200.9711". None if it could not be read.
    pub windows_version: Option<String>,
}

// Each check can fail on its own, so one failure does not hide the others.
pub struct Readings {
    pub antivirus: Result<Vec<SecurityProduct>, String>,
    pub firewall: Result<FirewallProfiles, String>,
    // Firewalls from other products, such as a security suite.
    pub other_firewalls: Result<Vec<SecurityProduct>, String>,
    pub updates: Result<UpdateStatus, String>,
}

// Called from the interface with invoke("check_windows_security").
// The readings run on a worker thread so the window stays responsive.
#[cfg(windows)]
#[tauri::command]
pub async fn check_windows_security() -> Result<Vec<Finding>, String> {
    tauri::async_runtime::spawn_blocking(|| {
        let (readings, steps) = reader::read();
        let mut findings = findings::build(&readings);
        // Each finding carries the steps that produced it.
        for finding in &mut findings {
            finding.steps = steps
                .iter()
                .filter(|(id, _)| *id == finding.id)
                .map(|(_, step)| step.clone())
                .collect();
        }
        findings
    })
    .await
        .map_err(|error| error.to_string())
}

#[cfg(not(windows))]
#[tauri::command]
pub async fn check_windows_security() -> Result<Vec<Finding>, String> {
    Err("This check only runs on Windows.".to_string())
}
