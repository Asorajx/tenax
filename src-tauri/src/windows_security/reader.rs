// Reads raw security settings from Windows. Read-only: nothing here changes a setting.
//
// Windows exposes these settings through COM, its system for sharing objects
// between programs. Each function below creates one COM object and asks it questions.

use std::time::{Instant, SystemTime, UNIX_EPOCH};

use windows::Win32::Foundation::{
    CloseHandle, E_FAIL, ERROR_FILE_NOT_FOUND, ERROR_NOT_FOUND, ERROR_SERVICE_DOES_NOT_EXIST,
    HANDLE, PROPERTYKEY,
};
use windows::Win32::NetworkManagement::IpHelper::{
    GetExtendedTcpTable, MIB_TCP6ROW_OWNER_PID, MIB_TCPROW_OWNER_PID, TCP_TABLE_OWNER_PID_LISTENER,
};
use windows::Win32::NetworkManagement::WindowsFirewall::{
    INetFwPolicy2, NET_FW_PROFILE2_DOMAIN, NET_FW_PROFILE2_PRIVATE, NET_FW_PROFILE2_PUBLIC,
    NetFwPolicy2,
};
use windows::Win32::Networking::WinSock::{AF_INET, AF_INET6};
use windows::Win32::Security::{
    CheckTokenMembership, CreateWellKnownSid, GetTokenInformation, PSID, TOKEN_ELEVATION_TYPE,
    TOKEN_QUERY, TokenElevationType, TokenElevationTypeFull, TokenElevationTypeLimited,
    WinBuiltinAdministratorsSid,
};
use windows::Win32::System::Com::StructuredStorage::PropVariantToInt64;
use windows::Win32::System::Com::{
    CLSCTX_INPROC_SERVER, COINIT_APARTMENTTHREADED, CoCreateInstance, CoInitializeEx,
    CoUninitialize,
};
use windows::Win32::System::Registry::{
    HKEY, HKEY_LOCAL_MACHINE, RRF_RT_REG_DWORD, RRF_RT_REG_SZ, RegGetValueW,
};
use windows::Win32::System::SecurityCenter::{
    IWSCProductList, WSC_SECURITY_PRODUCT_STATE_EXPIRED, WSC_SECURITY_PRODUCT_STATE_ON,
    WSC_SECURITY_PRODUCT_STATE_SNOOZED, WSC_SECURITY_PRODUCT_UP_TO_DATE, WSC_SECURITY_PROVIDER,
    WSC_SECURITY_PROVIDER_ANTIVIRUS, WSC_SECURITY_PROVIDER_FIREWALL, WSCProductList,
};
use windows::Win32::System::Services::{
    CloseServiceHandle, OpenSCManagerW, OpenServiceW, QueryServiceStatus, SC_MANAGER_CONNECT,
    SERVICE_QUERY_STATUS, SERVICE_RUNNING, SERVICE_STATUS,
};
use windows::Win32::System::SystemInformation::{FIRMWARE_TYPE, FirmwareTypeBios, GetFirmwareType};
use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};
use windows::Win32::System::TpmBaseServices::{TPM_DEVICE_INFO, Tbsi_GetDeviceInfo};
use windows::Win32::System::UpdateAgent::{
    AutomaticUpdates, IAutomaticUpdates2, ISystemInformation, SystemInformation,
};
use windows::Win32::System::Variant::{VARIANT, VT_DATE, VT_EMPTY, VT_NULL};
use windows::Win32::UI::Shell::PropertiesSystem::PSGetPropertyKeyFromName;
use windows::Win32::UI::Shell::{IShellItem2, SHCreateItemFromParsingName};
use windows::core::{PCWSTR, Result, w};

use crate::finding::Step;

use super::{
    Account, DriveEncryption, EncryptionState, FirewallProfiles, ProductState, Readings,
    RemoteAccess, RemoteDesktop, SecureBoot, SecurityProduct, ServiceState, Uac, UpdateStatus,
};

// Each step is tagged with the id of the finding it belongs to.
pub type Steps = Vec<(&'static str, Step)>;

pub fn read() -> (Readings, Steps) {
    // COM has to be started on this thread before any COM object is created.
    let com_started = unsafe { CoInitializeEx(None, COINIT_APARTMENTTHREADED) }.is_ok();
    let mut steps = Steps::new();

    let readings = Readings {
        antivirus: traced(
            &mut steps,
            "antivirus",
            "Queried Windows Security Center for antivirus status",
            "Looked up which antivirus programs are registered on this PC and whether they are on",
            "COM WSCProductList > IWSCProductList::Initialize(WSC_SECURITY_PROVIDER_ANTIVIRUS),              Count, get_Item, ProductName, ProductState, SignatureStatus",
            || products(WSC_SECURITY_PROVIDER_ANTIVIRUS),
            |found| format!("{} product(s) registered", found.len()),
        ),
        firewall: traced(
            &mut steps,
            "firewall",
            "Checked Windows Firewall profiles",
            "Checked whether Windows Firewall is on for home, work and public networks",
            "COM NetFwPolicy2 > INetFwPolicy2::get_FirewallEnabled(DOMAIN, PRIVATE, PUBLIC)",
            firewall,
            |_| "3 profiles read".to_string(),
        ),
        other_firewalls: traced(
            &mut steps,
            "firewall",
            "Queried Windows Security Center for other firewalls",
            "Looked for firewall programs from other companies",
            "COM WSCProductList > IWSCProductList::Initialize(WSC_SECURITY_PROVIDER_FIREWALL),              Count, get_Item, ProductName, ProductState, SignatureStatus",
            || products(WSC_SECURITY_PROVIDER_FIREWALL),
            |found| format!("{} product(s) registered", found.len()),
        ),
        updates: traced(
            &mut steps,
            "updates",
            "Read Windows Update history and restart state",
            "Asked Windows Update when it last checked and installed, whether a restart is waiting, and which version of Windows is installed",
            "COM AutomaticUpdates > IAutomaticUpdates2::Results, ServiceEnabled, \
             LastSearchSuccessDate, LastInstallationSuccessDate; \
             COM SystemInformation > ISystemInformation::RebootRequired; \
             registry HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion (DisplayVersion, CurrentBuild, UBR)",
            updates,
            |_| "Dates, restart flag and Windows version read".to_string(),
        ),
        secure_boot: traced(
            &mut steps,
            "startup",
            "Read the Secure Boot state",
            "Checked whether this PC starts in a mode that only allows trusted startup software",
            "Win32 GetFirmwareType; registry HKLM\\SYSTEM\\CurrentControlSet\\Control\\SecureBoot\\State (UEFISecureBootEnabled)",
            secure_boot,
            |state| {
                match state {
                    SecureBoot::On => "On",
                    SecureBoot::Off => "Off",
                    SecureBoot::LegacyBios => "Legacy BIOS, no Secure Boot",
                }
                .to_string()
            },
        ),
        tpm: traced(
            &mut steps,
            "startup",
            "Asked Windows whether a TPM is present",
            "Checked whether this PC has a security chip (TPM) and which version",
            "Win32 Tbsi_GetDeviceInfo (TPM Base Services)",
            tpm,
            |found| match found {
                Some(version) => format!("TPM {version} found"),
                None => "No TPM found".to_string(),
            },
        ),
        uac: traced(
            &mut steps,
            "uac",
            "Read User Account Control settings and the account type",
            "Checked whether Windows asks before programs make changes, and what kind of account is signed in",
            "registry HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System (EnableLUA, ConsentPromptBehaviorAdmin, PromptOnSecureDesktop); \
             Win32 OpenProcessToken > GetTokenInformation(TokenElevationType), CheckTokenMembership",
            uac,
            |uac| format!("UAC {}", if uac.enabled { "on" } else { "off" }),
        ),
        remote_access: traced(
            &mut steps,
            "remote",
            "Read the remote access settings",
            "Checked whether Remote Desktop, Remote Assistance and other remote tools are switched on",
            "registry HKLM\\SYSTEM\\CurrentControlSet\\Control (Terminal Server, Remote Assistance); \
             Win32 GetExtendedTcpTable (listening ports); Service Control Manager (WinRM, sshd)",
            remote_access,
            |_| "Remote Desktop, Remote Assistance, WinRM and SSH read".to_string(),
        ),
        auto_sign_in: traced(
            &mut steps,
            "signin",
            "Read the automatic sign-in setting",
            "Checked whether Windows signs in without asking for a password",
            "registry HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon (AutoAdminLogon). The saved password is never read.",
            auto_sign_in,
            |on| format!("Automatic sign-in {}", if *on { "on" } else { "off" }),
        ),
        drive_encryption: traced(
            &mut steps,
            "encryption",
            "Asked Windows whether the drive that holds Windows is encrypted",
            "Checked whether the drive that holds Windows is protected by BitLocker or Device encryption",
            "Shell SHCreateItemFromParsingName > IShellItem2::GetProperty(System.Volume.BitLockerProtection); Service Control Manager (BDESVC)",
            drive_encryption,
            |found| format!("{} {:?}", found.drive, found.state),
        ),
    };

    if com_started {
        unsafe { CoUninitialize() };
    }
    (readings, steps)
}

// Runs one reading, records what it was and how it went, and passes the result on.
fn traced<T>(
    steps: &mut Steps,
    check: &'static str,
    action: &str,
    plain: &str,
    method: &str,
    run: impl FnOnce() -> Result<T>,
    describe: impl Fn(&T) -> String,
) -> std::result::Result<T, String> {
    let started = Instant::now();
    let outcome = run().map_err(|error| error.message());
    let (ok, result) = match &outcome {
        Ok(value) => (true, describe(value)),
        Err(error) => (false, format!("Failed: {error}")),
    };
    steps.push((
        check,
        Step {
            action: action.to_string(),
            plain: plain.to_string(),
            method: method.to_string(),
            ok,
            result,
            ms: started.elapsed().as_secs_f64() * 1000.0,
            redact: None,
        },
    ));
    outcome
}

// Asks Windows Security Center which products of one kind (antivirus or firewall) are registered.
fn products(kind: WSC_SECURITY_PROVIDER) -> Result<Vec<SecurityProduct>> {
    unsafe {
        let list: IWSCProductList = CoCreateInstance(&WSCProductList, None, CLSCTX_INPROC_SERVER)?;
        list.Initialize(kind)?;

        let mut products = Vec::new();
        for index in 0..list.Count()? {
            let product = list.get_Item(index as u32)?;
            let state = match product.ProductState()? {
                WSC_SECURITY_PRODUCT_STATE_ON => ProductState::On,
                WSC_SECURITY_PRODUCT_STATE_SNOOZED => ProductState::Snoozed,
                WSC_SECURITY_PRODUCT_STATE_EXPIRED => ProductState::Expired,
                _ => ProductState::Off,
            };
            products.push(SecurityProduct {
                name: product.ProductName()?.to_string(),
                state,
                definitions_up_to_date: product.SignatureStatus()?
                    == WSC_SECURITY_PRODUCT_UP_TO_DATE,
            });
        }
        Ok(products)
    }
}

// Asks Windows Firewall whether it is on for each network profile.
fn firewall() -> Result<FirewallProfiles> {
    unsafe {
        let policy: INetFwPolicy2 = CoCreateInstance(&NetFwPolicy2, None, CLSCTX_INPROC_SERVER)?;
        Ok(FirewallProfiles {
            domain: policy
                .get_FirewallEnabled(NET_FW_PROFILE2_DOMAIN)?
                .as_bool(),
            private: policy
                .get_FirewallEnabled(NET_FW_PROFILE2_PRIVATE)?
                .as_bool(),
            public: policy
                .get_FirewallEnabled(NET_FW_PROFILE2_PUBLIC)?
                .as_bool(),
        })
    }
}

// Asks Windows Update when it last checked and installed, and whether a restart is waiting.
fn updates() -> Result<UpdateStatus> {
    unsafe {
        let updates: IAutomaticUpdates2 =
            CoCreateInstance(&AutomaticUpdates, None, CLSCTX_INPROC_SERVER)?;
        let system: ISystemInformation =
            CoCreateInstance(&SystemInformation, None, CLSCTX_INPROC_SERVER)?;
        let results = updates.Results()?;

        Ok(UpdateStatus {
            service_enabled: updates.ServiceEnabled()?.as_bool(),
            days_since_check: days_since(&results.LastSearchSuccessDate()?),
            days_since_install: days_since(&results.LastInstallationSuccessDate()?),
            restart_pending: system.RebootRequired()?.as_bool(),
            windows_version: windows_version(),
        })
    }
}

// Reads the Windows version from the registry. The product name there still says "Windows 10"
// on Windows 11, so the name comes from the build number instead (22000 and above is Windows 11).
fn windows_version() -> Option<String> {
    const KEY: PCWSTR = w!(r"SOFTWARE\Microsoft\Windows NT\CurrentVersion");

    // A value that cannot be read is simply left out of the version text.
    let text = |name: PCWSTR| registry_text(HKEY_LOCAL_MACHINE, KEY, name).ok().flatten();
    let number = |name: PCWSTR| {
        registry_number(HKEY_LOCAL_MACHINE, KEY, name)
            .ok()
            .flatten()
    };

    let build: u32 = text(w!("CurrentBuild"))?.parse().ok()?;
    let name = if build >= 22000 {
        "Windows 11"
    } else {
        "Windows 10"
    };
    let release = text(w!("DisplayVersion"))
        .map(|version| format!(" {version}"))
        .unwrap_or_default();
    let revision = number(w!("UBR"))
        .map(|ubr| format!(".{ubr}"))
        .unwrap_or_default();
    Some(format!("{name}{release} · build {build}{revision}"))
}

// Windows Update returns dates as a count of days since 30 December 1899, in UTC.
// A zero or missing date means Windows has no record.
fn days_since(date: &VARIANT) -> Option<f64> {
    const DAYS_FROM_1899_TO_1970: f64 = 25569.0;
    const SECONDS_PER_DAY: f64 = 86400.0;

    let value = unsafe { &date.Anonymous.Anonymous };
    if value.vt != VT_DATE {
        return None;
    }
    let then = unsafe { value.Anonymous.date };
    if then <= 0.0 {
        return None;
    }

    let seconds = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()?
        .as_secs_f64();
    let now = seconds / SECONDS_PER_DAY + DAYS_FROM_1899_TO_1970;
    Some((now - then).max(0.0))
}

// =========================
// Startup protection
// =========================

// Reads one number from the registry. A value that is not there is Ok(None). Any other failure is
// an error, so an unreadable setting is never mistaken for one that is off.
fn registry_number(hive: HKEY, key: PCWSTR, name: PCWSTR) -> Result<Option<u32>> {
    let mut value = 0u32;
    let mut size = std::mem::size_of::<u32>() as u32;
    let status = unsafe {
        RegGetValueW(
            hive,
            key,
            name,
            RRF_RT_REG_DWORD,
            None,
            Some((&mut value as *mut u32).cast()),
            Some(&mut size),
        )
    };
    if status == ERROR_FILE_NOT_FOUND {
        return Ok(None);
    }
    status.ok()?;
    Ok(Some(value))
}

// The same for text. A longer value than the buffer is an error, not a cut-off answer.
fn registry_text(hive: HKEY, key: PCWSTR, name: PCWSTR) -> Result<Option<String>> {
    let mut buffer = [0u16; 64];
    let mut size = std::mem::size_of_val(&buffer) as u32;
    let status = unsafe {
        RegGetValueW(
            hive,
            key,
            name,
            RRF_RT_REG_SZ,
            None,
            Some(buffer.as_mut_ptr().cast()),
            Some(&mut size),
        )
    };
    if status == ERROR_FILE_NOT_FOUND {
        return Ok(None);
    }
    status.ok()?;
    let length = buffer
        .iter()
        .position(|&unit| unit == 0)
        .unwrap_or(buffer.len());
    Ok(Some(String::from_utf16_lossy(&buffer[..length])))
}

fn secure_boot() -> Result<SecureBoot> {
    let mut firmware = FIRMWARE_TYPE::default();
    unsafe { GetFirmwareType(&mut firmware)? };
    if firmware == FirmwareTypeBios {
        return Ok(SecureBoot::LegacyBios);
    }

    // On a UEFI PC, Windows records the state here.
    let state = registry_number(
        HKEY_LOCAL_MACHINE,
        w!(r"SYSTEM\CurrentControlSet\Control\SecureBoot\State"),
        w!("UEFISecureBootEnabled"),
    )?;
    match state {
        Some(0) => Ok(SecureBoot::Off),
        Some(_) => Ok(SecureBoot::On),
        None => Err(windows::core::Error::new(
            E_FAIL,
            "Windows has no Secure Boot state recorded.",
        )),
    }
}

// The version of the TPM, or None when there is none. TBS_E_TPM_NOT_FOUND is an answer, not a failure.
fn tpm() -> Result<Option<String>> {
    const TBS_SUCCESS: u32 = 0;
    const TBS_E_TPM_NOT_FOUND: u32 = 0x8028_400F;

    let mut info = TPM_DEVICE_INFO::default();
    let result = unsafe {
        Tbsi_GetDeviceInfo(
            std::mem::size_of::<TPM_DEVICE_INFO>() as u32,
            (&mut info as *mut TPM_DEVICE_INFO).cast(),
        )
    };
    match result {
        TBS_SUCCESS => Ok(Some(match info.tpmVersion {
            1 => "1.2".to_string(),
            2 => "2.0".to_string(),
            other => format!("(version code {other})"),
        })),
        TBS_E_TPM_NOT_FOUND => Ok(None),
        other => Err(windows::core::Error::new(
            windows::core::HRESULT(other as i32),
            "Windows could not read the TPM.",
        )),
    }
}

// =========================
// User Account Control
// =========================

fn uac() -> Result<Uac> {
    const KEY: PCWSTR = w!(r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System");
    let number = |name: PCWSTR| registry_number(HKEY_LOCAL_MACHINE, KEY, name);

    // Windows treats a missing value as its default: on, ask for non-Windows programs, dim the screen.
    Ok(Uac {
        enabled: number(w!("EnableLUA"))?.unwrap_or(1) != 0,
        prompt: number(w!("ConsentPromptBehaviorAdmin"))?.unwrap_or(5),
        secure_desktop: number(w!("PromptOnSecureDesktop"))?.unwrap_or(1) != 0,
        account: account()?,
    })
}

// What kind of account is running Tenax. An administrator under User Account Control holds a
// "limited" token, so the elevation type is the reliable signal. Group membership alone is not,
// because the Administrators group is switched off in a limited token.
fn account() -> Result<Account> {
    unsafe {
        let mut token = HANDLE::default();
        OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token)?;

        let mut kind = TOKEN_ELEVATION_TYPE::default();
        let mut returned = 0u32;
        let result = GetTokenInformation(
            token,
            TokenElevationType,
            Some((&mut kind as *mut TOKEN_ELEVATION_TYPE).cast()),
            std::mem::size_of::<TOKEN_ELEVATION_TYPE>() as u32,
            &mut returned,
        );
        let _ = CloseHandle(token);
        result?;

        if kind == TokenElevationTypeFull {
            return Ok(Account::Elevated);
        }
        if kind == TokenElevationTypeLimited {
            return Ok(Account::Administrator);
        }

        // A default token is either a standard user or an administrator with the split switched off.
        let mut sid_bytes = [0u8; 68];
        let mut size = sid_bytes.len() as u32;
        let sid = PSID(sid_bytes.as_mut_ptr().cast());
        CreateWellKnownSid(WinBuiltinAdministratorsSid, None, Some(sid), &mut size)?;
        let mut member = false.into();
        CheckTokenMembership(None, sid, &mut member)?;
        Ok(if member.as_bool() {
            Account::AdministratorUacOff
        } else {
            Account::Standard
        })
    }
}

// =========================
// Remote access
// =========================

fn remote_access() -> Result<RemoteAccess> {
    const TERMINAL_SERVER: PCWSTR = w!(r"SYSTEM\CurrentControlSet\Control\Terminal Server");
    const RDP_TCP: PCWSTR =
        w!(r"SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp");
    const ASSISTANCE: PCWSTR = w!(r"SYSTEM\CurrentControlSet\Control\Remote Assistance");
    let number = |key: PCWSTR, name: PCWSTR| registry_number(HKEY_LOCAL_MACHINE, key, name);

    // fDenyTSConnections is 1 unless someone allowed Remote Desktop.
    let enabled = number(TERMINAL_SERVER, w!("fDenyTSConnections"))?.unwrap_or(1) == 0;
    let port = number(RDP_TCP, w!("PortNumber"))?.unwrap_or(3389) as u16;

    Ok(RemoteAccess {
        desktop: RemoteDesktop {
            enabled,
            nla: number(RDP_TCP, w!("UserAuthentication"))?.unwrap_or(1) != 0,
            port,
            listening: is_listening(port)?,
        },
        assistance: number(ASSISTANCE, w!("fAllowToGetHelp"))?.unwrap_or(0) != 0,
        winrm: service_state(w!("WinRM"))?,
        ssh: service_state(w!("sshd"))?,
    })
}

// Whether any program is accepting connections on a port, on IPv4 or IPv6.
fn is_listening(port: u16) -> Result<bool> {
    Ok(listening_ports(AF_INET.0 as u32)?.contains(&port)
        || listening_ports(AF_INET6.0 as u32)?.contains(&port))
}

// The ports with a listener. Windows is asked how much room it needs, then for the table itself.
// The buffer is made of u32 so that the rows inside it are properly aligned.
pub(super) fn listening_ports(family: u32) -> Result<Vec<u16>> {
    unsafe {
        let mut size = 0u32;
        // The first call only reports the size, so its "buffer too small" answer is expected.
        GetExtendedTcpTable(
            None,
            &mut size,
            false,
            family,
            TCP_TABLE_OWNER_PID_LISTENER,
            0,
        );

        let mut buffer = vec![0u32; (size as usize).div_ceil(4)];
        let status = GetExtendedTcpTable(
            Some(buffer.as_mut_ptr().cast()),
            &mut size,
            false,
            family,
            TCP_TABLE_OWNER_PID_LISTENER,
            0,
        );
        if status != 0 {
            return Err(windows::core::Error::new(
                windows::core::HRESULT::from_win32(status),
                "Windows could not list the open ports.",
            ));
        }

        // The table starts with a count, followed by that many rows.
        let count = buffer[0] as usize;
        let rows = buffer.as_ptr().add(1);
        // The port is held in the low 16 bits, in network byte order.
        let port = |raw: u32| u16::from_be(raw as u16);
        Ok(if family == AF_INET.0 as u32 {
            std::slice::from_raw_parts(rows.cast::<MIB_TCPROW_OWNER_PID>(), count)
                .iter()
                .map(|row| port(row.dwLocalPort))
                .collect()
        } else {
            std::slice::from_raw_parts(rows.cast::<MIB_TCP6ROW_OWNER_PID>(), count)
                .iter()
                .map(|row| port(row.dwLocalPort))
                .collect()
        })
    }
}

// A service that is not installed is a normal answer, such as on a PC without OpenSSH.
fn service_state(name: PCWSTR) -> Result<ServiceState> {
    unsafe {
        let manager = OpenSCManagerW(None, None, SC_MANAGER_CONNECT)?;
        let outcome = match OpenServiceW(manager, name, SERVICE_QUERY_STATUS) {
            Ok(service) => {
                let mut status = SERVICE_STATUS::default();
                let result = QueryServiceStatus(service, &mut status);
                let _ = CloseServiceHandle(service);
                result.map(|_| {
                    if status.dwCurrentState == SERVICE_RUNNING {
                        ServiceState::Running
                    } else {
                        ServiceState::Stopped
                    }
                })
            }
            Err(error) if error.code() == ERROR_SERVICE_DOES_NOT_EXIST.to_hresult() => {
                Ok(ServiceState::NotInstalled)
            }
            Err(error) => Err(error),
        };
        let _ = CloseServiceHandle(manager);
        outcome
    }
}

// =========================
// Automatic sign-in
// =========================

// Only whether it is on. The saved password, and the account it signs in to, are never read.
fn auto_sign_in() -> Result<bool> {
    let value = registry_text(
        HKEY_LOCAL_MACHINE,
        w!(r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"),
        w!("AutoAdminLogon"),
    )?;
    Ok(value.as_deref() == Some("1"))
}

// =========================
// Drive encryption
// =========================

// Reads the state Windows shows for the drive that holds Windows, as Chromium does: the property of
// the drive's shell item. It needs no administrator rights, unlike asking BitLocker directly. The
// property is not in Microsoft's documentation, but Windows lists its values itself
// (System.Volume.BitLockerProtection, read from the property system on this PC); see
// EncryptionState::from_code. A drive with no value at all is NotReported, and never a state.
// Asking the This PC folder for the same detail was tried and rejected: it answers 0 where there
// is no value, which cannot be told from a real 0.
fn drive_encryption() -> Result<DriveEncryption> {
    let drive = std::env::var("SystemDrive").unwrap_or_else(|_| "C:".to_string());
    let path: Vec<u16> = format!("{drive}\\")
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();

    let reading = unsafe {
        let item: IShellItem2 = SHCreateItemFromParsingName(PCWSTR(path.as_ptr()), None)?;
        let mut key = PROPERTYKEY::default();
        PSGetPropertyKeyFromName(w!("System.Volume.BitLockerProtection"), &mut key)?;
        item.GetProperty(&key)
    };

    let state = match reading {
        // No value, or no such property for this item: Windows has not said anything.
        Err(error) if error.code() == ERROR_NOT_FOUND.to_hresult() => EncryptionState::NotReported,
        Err(error) => return Err(error),
        Ok(value) if matches!(value.vt(), VT_EMPTY | VT_NULL) => EncryptionState::NotReported,
        Ok(value) => {
            let code = unsafe { PropVariantToInt64(&value) }
                .ok()
                .and_then(|n| u32::try_from(n).ok());
            match code {
                Some(code) => EncryptionState::from_code(code),
                None => {
                    return Err(windows::core::Error::new(
                        E_FAIL,
                        "Windows gave the encryption state in a form Tenax does not read.",
                    ));
                }
            }
        }
    };
    Ok(DriveEncryption {
        drive,
        state,
        service: service_state(w!("BDESVC"))?,
    })
}
