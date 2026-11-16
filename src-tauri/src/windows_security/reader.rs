// Reads raw security settings from Windows. Read-only: nothing here changes a setting.
//
// Windows exposes these settings through COM, its system for sharing objects
// between programs. Each function below creates one COM object and asks it questions.

use std::time::{Instant, SystemTime, UNIX_EPOCH};

use windows::Win32::NetworkManagement::WindowsFirewall::{
    INetFwPolicy2, NET_FW_PROFILE2_DOMAIN, NET_FW_PROFILE2_PRIVATE, NET_FW_PROFILE2_PUBLIC,
    NetFwPolicy2,
};
use windows::Win32::System::Com::{
    CLSCTX_INPROC_SERVER, COINIT_APARTMENTTHREADED, CoCreateInstance, CoInitializeEx,
    CoUninitialize,
};
use windows::Win32::System::Registry::{
    HKEY_LOCAL_MACHINE, RRF_RT_REG_DWORD, RRF_RT_REG_SZ, RegGetValueW,
};
use windows::Win32::System::SecurityCenter::{
    IWSCProductList, WSC_SECURITY_PRODUCT_STATE_EXPIRED, WSC_SECURITY_PRODUCT_STATE_ON,
    WSC_SECURITY_PRODUCT_STATE_SNOOZED, WSC_SECURITY_PRODUCT_UP_TO_DATE, WSC_SECURITY_PROVIDER,
    WSC_SECURITY_PROVIDER_ANTIVIRUS, WSC_SECURITY_PROVIDER_FIREWALL, WSCProductList,
};
use windows::Win32::System::UpdateAgent::{
    AutomaticUpdates, IAutomaticUpdates2, ISystemInformation, SystemInformation,
};
use windows::Win32::System::Variant::{VARIANT, VT_DATE};
use windows::core::{PCWSTR, Result, w};

use crate::finding::Step;

use super::{FirewallProfiles, ProductState, Readings, SecurityProduct, UpdateStatus};

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

    fn text(name: PCWSTR) -> Option<String> {
        let mut buffer = [0u16; 64];
        let mut size = std::mem::size_of_val(&buffer) as u32;
        unsafe {
            RegGetValueW(
                HKEY_LOCAL_MACHINE,
                KEY,
                name,
                RRF_RT_REG_SZ,
                None,
                Some(buffer.as_mut_ptr().cast()),
                Some(&mut size),
            )
        }
        .ok()
        .ok()?;
        let length = buffer.iter().position(|&unit| unit == 0)?;
        Some(String::from_utf16_lossy(&buffer[..length]))
    }

    fn number(name: PCWSTR) -> Option<u32> {
        let mut value = 0u32;
        let mut size = std::mem::size_of::<u32>() as u32;
        unsafe {
            RegGetValueW(
                HKEY_LOCAL_MACHINE,
                KEY,
                name,
                RRF_RT_REG_DWORD,
                None,
                Some((&mut value as *mut u32).cast()),
                Some(&mut size),
            )
        }
        .ok()
        .ok()?;
        Some(value)
    }

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
