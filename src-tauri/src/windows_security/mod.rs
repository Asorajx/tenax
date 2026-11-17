// Windows Security check: reads antivirus, firewall, Windows Update, Secure Boot, TPM, drive
// encryption, User Account Control, remote access and automatic sign-in settings.
// Nothing is changed on the PC.
//
// reader.rs   talks to Windows and returns raw values
// findings.rs turns those values into findings, with no Windows code in it
// settings.rs opens a page of Windows Settings, from a fixed list of pages

mod findings;
#[cfg(windows)]
mod reader;
pub(crate) mod settings;

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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecureBoot {
    On,
    Off,
    // The PC starts with the old BIOS, which has no Secure Boot at all.
    LegacyBios,
}

// Who is running Tenax, as the token Windows gave this process describes it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Account {
    Standard,
    // An administrator account running without elevation, which is how Windows normally runs one.
    Administrator,
    // Tenax itself was started as administrator.
    Elevated,
    // An administrator account while User Account Control is off, so there is no split.
    AdministratorUacOff,
}

#[derive(Debug)]
pub struct Uac {
    pub enabled: bool,
    // ConsentPromptBehaviorAdmin: 0 never asks, 2 always asks, 5 is the default.
    pub prompt: u32,
    // Whether the screen is dimmed while the question is shown.
    pub secure_desktop: bool,
    pub account: Account,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServiceState {
    NotInstalled,
    Stopped,
    Running,
}

#[derive(Debug)]
pub struct RemoteDesktop {
    // The Windows setting that allows connections.
    pub enabled: bool,
    // Whether a connection must sign in before the session starts (Network Level Authentication).
    pub nla: bool,
    pub port: u16,
    // Whether something is actually accepting connections on that port right now.
    pub listening: bool,
}

#[derive(Debug)]
pub struct RemoteAccess {
    pub desktop: RemoteDesktop,
    pub assistance: bool,
    pub winrm: ServiceState,
    pub ssh: ServiceState,
}

// What Windows reports for the drive that holds Windows. The meanings are the ones Windows itself
// lists for the property. A code that is not on that list is kept as it is and never guessed at.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EncryptionState {
    On,
    Off,
    Encrypting,
    Decrypting,
    Suspended,
    Locked,
    NotEncryptable,
    WaitingForActivation,
    // Windows gave no value at all for the drive. This is not the same as a value of 0.
    NotReported,
    Unrecognised(u32),
}

impl EncryptionState {
    // The values are the ones Windows lists for the property. Chromium reads the same property.
    pub fn from_code(code: u32) -> EncryptionState {
        match code {
            1 => EncryptionState::On,
            2 => EncryptionState::Off,
            3 => EncryptionState::Encrypting,
            4 => EncryptionState::Decrypting,
            5 => EncryptionState::Suspended,
            6 => EncryptionState::Locked,
            7 => EncryptionState::NotEncryptable,
            8 => EncryptionState::WaitingForActivation,
            other => EncryptionState::Unrecognised(other),
        }
    }
}

#[derive(Debug)]
pub struct DriveEncryption {
    // Such as "C:".
    pub drive: String,
    pub state: EncryptionState,
    // The BitLocker service. It is not installed on editions without BitLocker or Device encryption.
    pub service: ServiceState,
}

// Each check can fail on its own, so one failure does not hide the others.
pub struct Readings {
    pub antivirus: Result<Vec<SecurityProduct>, String>,
    pub firewall: Result<FirewallProfiles, String>,
    // Firewalls from other products, such as a security suite.
    pub other_firewalls: Result<Vec<SecurityProduct>, String>,
    pub updates: Result<UpdateStatus, String>,
    pub secure_boot: Result<SecureBoot, String>,
    // None means no TPM was found. Otherwise the version, such as "2.0".
    pub tpm: Result<Option<String>, String>,
    pub uac: Result<Uac, String>,
    pub remote_access: Result<RemoteAccess, String>,
    pub auto_sign_in: Result<bool, String>,
    pub drive_encryption: Result<DriveEncryption, String>,
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
