// Turns raw readings into findings: the state at a glance, what Tenax checked,
// why it checked, and what to do.
// There is no Windows code here, so every case can be tested with made-up readings.

use super::{
    Account, FirewallProfiles, ProductState, Readings, RemoteAccess, SecureBoot, SecurityProduct,
    ServiceState, Uac, UpdateStatus,
};
use crate::finding::{Detail, Finding, Status, detail, join_names, switch};

// A longer gap than this since the last update check is reported.
const STALE_CHECK_DAYS: f64 = 7.0;

pub fn build(readings: &Readings) -> Vec<Finding> {
    let mut findings = vec![
        antivirus(&readings.antivirus),
        firewall(&readings.firewall, &readings.other_firewalls),
        updates(&readings.updates),
        startup(&readings.secure_boot, &readings.tpm),
        uac(&readings.uac),
        remote_access(&readings.remote_access),
        sign_in(&readings.auto_sign_in),
    ];

    // Most serious first.
    findings.sort_by_key(|finding| finding.status);
    findings
}

// What each check reads and why. These stay the same whatever the result is.
struct Check {
    id: &'static str,
    title: &'static str,
    checked: &'static str,
    why: &'static str,
}

const ANTIVIRUS: Check = Check {
    id: "antivirus",
    title: "Antivirus",
    checked: "I asked Windows Security Center which antivirus products are registered on \
              this PC, and whether each reports itself as on and up to date.",
    why: "An active antivirus blocks known malware when files and programs are opened.",
};

const FIREWALL: Check = Check {
    id: "firewall",
    title: "Firewall",
    checked: "I read whether Windows Firewall is on for the Domain, Private and Public \
              network profiles, and asked Windows Security Center about other firewall products.",
    why: "A firewall stops other devices on the network from reaching this PC uninvited.",
};

const UPDATES: Check = Check {
    id: "updates",
    title: "Windows Update",
    checked: "I asked Windows Update when it last checked for and installed updates, and \
              whether a restart is pending.",
    why: "Updates fix security flaws that attackers actively use.",
};

impl Check {
    fn finding(
        &self,
        status: Status,
        summary: impl Into<String>,
        action: Option<String>,
        details: Vec<Detail>,
    ) -> Finding {
        Finding {
            id: self.id.to_string(),
            status,
            title: self.title.to_string(),
            summary: summary.into(),
            checked: self.checked.to_string(),
            why: self.why.to_string(),
            action,
            details,
            steps: Vec::new(),
            urls: Vec::new(),
            note: None,
        }
    }

    // A failed check must never look like a pass, so it gets its own status.
    fn could_not_check(&self, action: &str, error: &str) -> Finding {
        self.finding(
            Status::Unknown,
            "Could not read this setting",
            Some(action.to_string()),
            vec![detail("Error", error)],
        )
    }
}

fn names_where<'a>(
    products: &[&'a SecurityProduct],
    wanted: impl Fn(&SecurityProduct) -> bool,
) -> Vec<&'a str> {
    products
        .iter()
        .filter(|product| wanted(product))
        .map(|product| product.name.as_str())
        .collect()
}

// =========================
// Antivirus
// =========================

fn antivirus(reading: &Result<Vec<SecurityProduct>, String>) -> Finding {
    let products: Vec<&SecurityProduct> = match reading {
        Ok(products) => products.iter().collect(),
        Err(error) => {
            return ANTIVIRUS.could_not_check(
                "Open Windows Security and look under Virus & threat protection.",
                error,
            );
        }
    };

    let mut details: Vec<Detail> = products
        .iter()
        .map(|product| {
            // Definitions only matter for a product that is actually running.
            let value = match (product.state, product.definitions_up_to_date) {
                (ProductState::On, true) => "On · definitions up to date",
                (ProductState::On, false) => "On · definitions out of date",
                (ProductState::Off, _) => "Off",
                (ProductState::Snoozed, _) => "Snoozed",
                (ProductState::Expired, _) => "Expired",
            };
            switch(&product.name, value, product.state == ProductState::On)
        })
        .collect();
    // The product that is protecting the PC is listed first.
    details.sort_by_key(|item| item.active != Some(true));

    let turn_on = "Open Windows Security, choose Virus & threat protection, and turn on \
                   real-time protection.";

    if products.is_empty() {
        return ANTIVIRUS.finding(
            Status::Risk,
            "None found",
            Some(turn_on.to_string()),
            details,
        );
    }

    let all = join_names(&names_where(&products, |_| true), "and");
    let active = names_where(&products, |product| product.state == ProductState::On);

    if active.is_empty() {
        let snoozed = names_where(&products, |product| product.state == ProductState::Snoozed);
        let expired = names_where(&products, |product| product.state == ProductState::Expired);

        return if !snoozed.is_empty() {
            ANTIVIRUS.finding(
                Status::Warning,
                format!("Snoozed · {}", join_names(&snoozed, "and")),
                Some("Open your antivirus and resume protection.".to_string()),
                details,
            )
        } else if !expired.is_empty() {
            ANTIVIRUS.finding(
                Status::Risk,
                format!("Expired · {}", join_names(&expired, "and")),
                Some(
                    "Renew it, or uninstall it. Windows turns Microsoft Defender back on when \
                     no other antivirus is active. Restart, then check Windows Security to \
                     confirm."
                        .to_string(),
                ),
                details,
            )
        } else {
            ANTIVIRUS.finding(
                Status::Risk,
                format!("Off · {all}"),
                Some(turn_on.to_string()),
                details,
            )
        };
    }

    let current = names_where(&products, |product| {
        product.state == ProductState::On && product.definitions_up_to_date
    });
    if current.is_empty() {
        return ANTIVIRUS.finding(
            Status::Warning,
            format!(
                "On, definitions out of date · {}",
                join_names(&active, "and")
            ),
            Some("Open your antivirus and check for updates.".to_string()),
            details,
        );
    }

    // One active, up-to-date antivirus is enough. The rows below show which product it is.
    ANTIVIRUS.finding(Status::Ok, "Active", None, details)
}

// =========================
// Firewall
// =========================

fn firewall(
    reading: &Result<FirewallProfiles, String>,
    other_firewalls: &Result<Vec<SecurityProduct>, String>,
) -> Finding {
    let profiles = match reading {
        Ok(profiles) => profiles,
        Err(error) => {
            return FIREWALL.could_not_check(
                "Open Windows Security and look under Firewall & network protection.",
                error,
            );
        }
    };

    let on_off = |enabled: bool| if enabled { "On" } else { "Off" };
    let mut details = vec![
        switch("Domain networks", on_off(profiles.domain), profiles.domain),
        switch(
            "Private networks",
            on_off(profiles.private),
            profiles.private,
        ),
        switch("Public networks", on_off(profiles.public), profiles.public),
    ];

    // Windows lists its own firewall here too, which the profiles above already cover.
    let others: Vec<&SecurityProduct> = other_firewalls
        .iter()
        .flatten()
        .filter(|product| !product.name.contains("Windows"))
        .collect();
    for product in &others {
        let active = product.state == ProductState::On;
        details.push(switch(
            &format!("{} firewall", product.name),
            if active { "On" } else { "Not active" },
            active,
        ));
    }

    let off: Vec<&str> = [
        ("Domain", profiles.domain),
        ("Private", profiles.private),
        ("Public", profiles.public),
    ]
    .iter()
    .filter(|(_, enabled)| !enabled)
    .map(|(name, _)| *name)
    .collect();

    if off.is_empty() {
        return FIREWALL.finding(Status::Ok, "On · all networks", None, details);
    }

    // Another product says its firewall is on. This is usually deliberate, so it is a note
    // with a prompt to confirm, not a warning.
    let active_others = names_where(&others, |product| product.state == ProductState::On);
    if !active_others.is_empty() {
        let suite = join_names(&active_others, "and");
        return FIREWALL.finding(
            Status::Info,
            format!("Windows Firewall off · {suite} firewall on"),
            Some(format!(
                "Security suites usually switch Windows Firewall off when their own takes \
                 over. Open {suite} and confirm its firewall is on. Tenax only sees what \
                 {suite} reports to Windows."
            )),
            details,
        );
    }

    let mut action = "Open Windows Security, choose Firewall & network protection, and turn \
                      the firewall on for each network."
        .to_string();
    if other_firewalls.is_err() {
        action.push_str(
            " Tenax could not read the list of other firewall products, so one of them may \
             be covering for Windows Firewall.",
        );
    }

    let summary = if off.len() == 3 {
        "Off · all networks".to_string()
    } else {
        format!(
            "Off · {} network{}",
            join_names(&off, "and"),
            if off.len() == 1 { "" } else { "s" }
        )
    };

    FIREWALL.finding(
        // Every profile off is more serious than one.
        if off.len() == 3 {
            Status::Risk
        } else {
            Status::Warning
        },
        summary,
        Some(action),
        details,
    )
}

// =========================
// Windows Update
// =========================

fn days_ago(days: Option<f64>) -> String {
    match days {
        None => "No record".to_string(),
        Some(days) if days < 1.0 => "Less than a day ago".to_string(),
        Some(days) if days < 2.0 => "1 day ago".to_string(),
        Some(days) => format!("{} days ago", days.floor()),
    }
}

fn updates(reading: &Result<UpdateStatus, String>) -> Finding {
    let status = match reading {
        Ok(status) => status,
        Err(error) => {
            return UPDATES.could_not_check("Open Settings and look under Windows Update.", error);
        }
    };

    let mut details = Vec::new();
    if let Some(version) = &status.windows_version {
        details.push(detail("Windows version", version));
    }
    details.extend([
        detail("Last check", days_ago(status.days_since_check)),
        detail("Last install", days_ago(status.days_since_install)),
        detail(
            "Restart",
            if status.restart_pending {
                "Needed"
            } else {
                "Not needed"
            },
        ),
    ]);
    if !status.service_enabled {
        details.push(detail("Update components", "Not available"));
    }

    let check_now =
        Some("Open Settings, choose Windows Update, and select Check for updates.".to_string());

    if !status.service_enabled {
        return UPDATES.finding(
            Status::Warning,
            "May not be working · components unavailable",
            check_now,
            details,
        );
    }
    if status.restart_pending {
        return UPDATES.finding(
            Status::Warning,
            "Restart needed to finish updates",
            Some("Save your work and restart the PC.".to_string()),
            details,
        );
    }

    match status.days_since_check {
        None => UPDATES.finding(
            Status::Info,
            "No update check on record",
            check_now,
            details,
        ),
        Some(days) if days > STALE_CHECK_DAYS => UPDATES.finding(
            Status::Warning,
            format!("Last checked {}", days_ago(Some(days)).to_lowercase()),
            check_now,
            details,
        ),
        Some(days) => UPDATES.finding(
            Status::Ok,
            format!("Checked {}", days_ago(Some(days)).to_lowercase()),
            None,
            details,
        ),
    }
}

// =========================
// Startup protection
// =========================

const STARTUP: Check = Check {
    id: "startup",
    title: "Startup protection",
    checked: "I asked Windows whether this PC starts with Secure Boot, and whether it has a \
              TPM security chip.",
    why: "Secure Boot stops tampered startup software from loading before Windows. A TPM keeps \
          encryption keys safe, and BitLocker and Windows Hello can use it.",
};

fn startup(
    secure_boot: &Result<SecureBoot, String>,
    tpm: &Result<Option<String>, String>,
) -> Finding {
    if let (Err(first), Err(second)) = (secure_boot, tpm) {
        return STARTUP.could_not_check(
            "Open Windows Security and look under Device security.",
            &format!("{first} {second}"),
        );
    }

    let mut details = Vec::new();
    // What is missing, in the order it is shown.
    let mut gaps: Vec<&str> = Vec::new();
    let mut actions: Vec<&str> = Vec::new();
    let mut unreadable = false;

    match secure_boot {
        Ok(SecureBoot::On) => details.push(switch("Secure Boot", "On", true)),
        Ok(SecureBoot::Off) => {
            details.push(switch("Secure Boot", "Off", false));
            gaps.push("Secure Boot off");
            actions.push(
                "If you did not turn Secure Boot off on purpose, turn it on in your PC's \
                 firmware (UEFI) settings. Some dual-boot setups need it off.",
            );
        }
        Ok(SecureBoot::LegacyBios) => {
            details.push(switch(
                "Secure Boot",
                "Not available · starts in legacy BIOS mode",
                false,
            ));
            gaps.push("Secure Boot not available");
            actions.push(
                "Secure Boot needs UEFI mode. Switching from legacy BIOS means converting the \
                 disk, so back up first.",
            );
        }
        Err(_) => {
            details.push(detail("Secure Boot", "Could not read"));
            unreadable = true;
        }
    }

    match tpm {
        Ok(Some(version)) => {
            details.push(switch("TPM", format!("Present · version {version}"), true));
            if version == "1.2" {
                gaps.push("older TPM");
                actions.push("TPM 1.2 is older. Windows 11 needs version 2.0.");
            }
        }
        Ok(None) => {
            details.push(switch("TPM", "Not found", false));
            gaps.push("no TPM");
            actions.push(
                "Without a TPM, Windows cannot keep keys in hardware. Some PCs offer a \
                 firmware TPM in their settings.",
            );
        }
        Err(_) => {
            details.push(detail("TPM", "Could not read"));
            unreadable = true;
        }
    }

    let action = (!actions.is_empty()).then(|| actions.join(" "));

    if unreadable {
        return STARTUP.finding(
            Status::Limited,
            "Only part of this could be read",
            action.or(Some(
                "Open Windows Security and look under Device security.".to_string(),
            )),
            details,
        );
    }
    if gaps.is_empty() {
        let version = tpm.as_ref().ok().and_then(|found| found.as_deref());
        return STARTUP.finding(
            Status::Ok,
            format!("Secure Boot on · TPM {}", version.unwrap_or("present")),
            None,
            details,
        );
    }

    // A PC without these is not necessarily at risk, so they are notes and not warnings.
    let summary = gaps.join(" · ");
    let summary = format!("{}{}", &summary[..1].to_uppercase(), &summary[1..]);
    STARTUP.finding(Status::Info, summary, action, details)
}

// =========================
// User Account Control
// =========================

const UAC: Check = Check {
    id: "uac",
    title: "User Account Control",
    checked: "I read whether User Account Control is on and how it asks, and what kind of \
              account is running Tenax.",
    why: "User Account Control asks before a program makes changes that need administrator \
          rights, so malware cannot make them silently.",
};

fn uac(reading: &Result<Uac, String>) -> Finding {
    let uac = match reading {
        Ok(uac) => uac,
        Err(error) => {
            return UAC.could_not_check(
                "Open Settings and search for Change User Account Control settings.",
                error,
            );
        }
    };

    let account = match uac.account {
        Account::Standard => "Standard user",
        Account::Administrator | Account::AdministratorUacOff => "Administrator account",
        Account::Elevated => "Administrator, running elevated",
    };
    let asks = match uac.prompt {
        0 => "Never asks",
        1 | 3 => "Asks for a password",
        2 | 4 => "Always asks",
        5 => "Asks when programs make changes",
        _ => "Custom setting",
    };

    let mut details = vec![switch(
        "User Account Control",
        if uac.enabled { "On" } else { "Off" },
        uac.enabled,
    )];
    if uac.enabled {
        details.push(detail(
            "When it asks",
            if uac.secure_desktop {
                asks.to_string()
            } else {
                format!("{asks} · screen not dimmed")
            },
        ));
    }
    details.push(detail("This account", account));

    let raise = Some(
        "Open Settings, search for Change User Account Control settings, and move the slider \
         up from Never notify."
            .to_string(),
    );

    if !uac.enabled {
        return UAC.finding(Status::Warning, "Off", raise, details);
    }
    if uac.prompt == 0 {
        return UAC.finding(Status::Warning, "On · never asks", raise, details);
    }
    if uac.account == Account::AdministratorUacOff {
        return UAC.finding(
            Status::Warning,
            "Not applied to this administrator account",
            raise,
            details,
        );
    }
    if !uac.secure_desktop {
        return UAC.finding(
            Status::Info,
            "On · does not dim the screen",
            Some(
                "Dimming the screen stops other programs from clicking the question for you. \
                 Open Settings, search for Change User Account Control settings, and choose \
                 the default level."
                    .to_string(),
            ),
            details,
        );
    }
    if uac.account == Account::Elevated {
        return UAC.finding(
            Status::Info,
            "On · Tenax is running as administrator",
            Some(
                "Close Tenax and open it normally. It does not need administrator rights."
                    .to_string(),
            ),
            details,
        );
    }
    UAC.finding(Status::Ok, format!("On · {account}"), None, details)
}

// =========================
// Remote access
// =========================

const REMOTE: Check = Check {
    id: "remote",
    title: "Remote access",
    checked: "I read whether Remote Desktop and Remote Assistance are switched on, whether \
              anything is listening for Remote Desktop, and whether the Windows Remote \
              Management and OpenSSH services are running.",
    why: "Remote access lets someone else control this PC. It is useful when you set it up \
          yourself, and a way in when you did not.",
};

fn service_text(state: ServiceState) -> &'static str {
    match state {
        ServiceState::Running => "Running",
        ServiceState::Stopped => "Stopped",
        ServiceState::NotInstalled => "Not installed",
    }
}

fn remote_access(reading: &Result<RemoteAccess, String>) -> Finding {
    let remote = match reading {
        Ok(remote) => remote,
        Err(error) => {
            return REMOTE
                .could_not_check("Open Settings, choose System, then Remote Desktop.", error);
        }
    };
    let desktop = &remote.desktop;

    // A listener counts as on whatever the setting says, since a policy can turn it on elsewhere.
    let desktop_text = match (desktop.enabled, desktop.listening) {
        (_, true) => format!("On · listening on port {}", desktop.port),
        (true, false) => "Allowed · nothing is listening".to_string(),
        (false, false) => "Off".to_string(),
    };
    let mut details = vec![switch(
        "Remote Desktop",
        desktop_text,
        desktop.enabled || desktop.listening,
    )];
    if desktop.enabled || desktop.listening {
        details.push(
            detail(
                "Network Level Authentication",
                if desktop.nla { "On" } else { "Off" },
            )
            .because(
                "With it on, a person has to sign in before a session starts, which stops \
                 many attacks that rely on reaching the sign-in screen.",
            ),
        );
    }
    details.extend([
        switch(
            "Remote Assistance",
            if remote.assistance { "On" } else { "Off" },
            remote.assistance,
        ),
        switch(
            "Windows Remote Management",
            service_text(remote.winrm),
            remote.winrm == ServiceState::Running,
        ),
        switch(
            "OpenSSH server",
            service_text(remote.ssh),
            remote.ssh == ServiceState::Running,
        ),
    ]);

    let mut on: Vec<&str> = Vec::new();
    if desktop.listening {
        on.push("Remote Desktop");
    }
    if remote.winrm == ServiceState::Running {
        on.push("Windows Remote Management");
    }
    if remote.ssh == ServiceState::Running {
        on.push("OpenSSH server");
    }

    let turn_off = "If you do not use it, turn it off. For Remote Desktop, open Settings, \
                    choose System, then Remote Desktop.";
    let mut finding = if desktop.listening && !desktop.nla {
        REMOTE.finding(
            Status::Warning,
            "Remote Desktop on · Network Level Authentication off",
            Some(
                "Open Settings, choose System, then Remote Desktop, and turn on Require \
                 devices to use Network Level Authentication. Turn Remote Desktop off if you \
                 do not use it."
                    .to_string(),
            ),
            details,
        )
    } else if !on.is_empty() {
        REMOTE.finding(
            Status::Info,
            format!("On · {}", join_names(&on, "and")),
            Some(turn_off.to_string()),
            details,
        )
    } else if desktop.enabled {
        REMOTE.finding(
            Status::Info,
            "Remote Desktop allowed · nothing is listening",
            Some(
                "The setting is on, but Windows is not accepting connections. That is normal \
                 on Windows Home, which cannot host Remote Desktop."
                    .to_string(),
            ),
            details,
        )
    } else {
        REMOTE.finding(
            Status::Ok,
            if remote.assistance {
                "Remote Assistance allowed"
            } else {
                "Off"
            },
            None,
            details,
        )
    };

    if !on.is_empty() {
        finding.note = Some(
            "Tenax only sees this PC. It cannot tell whether your router lets the internet \
             reach it."
                .to_string(),
        );
    }
    finding
}

// =========================
// Automatic sign-in
// =========================

const SIGN_IN: Check = Check {
    id: "signin",
    title: "Automatic sign-in",
    checked: "I read whether Windows is set to sign in without asking for a password. I did \
              not read any saved password.",
    why: "With automatic sign-in, anyone who turns this PC on gets into your account and \
          files.",
};

fn sign_in(reading: &Result<bool, String>) -> Finding {
    match reading {
        Err(error) => SIGN_IN.could_not_check(
            "Press Windows + R, type netplwiz and look at the sign-in setting there.",
            error,
        ),
        Ok(true) => SIGN_IN.finding(
            Status::Warning,
            "On · no password at start-up",
            Some(
                "Press Windows + R, type netplwiz, select your account and tick Users must \
                 enter a user name and password to use this computer."
                    .to_string(),
            ),
            vec![switch("Automatic sign-in", "On", true)],
        ),
        Ok(false) => SIGN_IN.finding(
            Status::Ok,
            "Off",
            None,
            vec![switch("Automatic sign-in", "Off", false)],
        ),
    }
}

// =========================
// Tests
// =========================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::windows_security::RemoteDesktop;

    fn product(name: &str, state: ProductState) -> SecurityProduct {
        SecurityProduct {
            name: name.to_string(),
            state,
            definitions_up_to_date: true,
        }
    }

    fn healthy() -> Readings {
        Readings {
            antivirus: Ok(vec![product("Windows Defender", ProductState::On)]),
            firewall: Ok(FirewallProfiles {
                domain: true,
                private: true,
                public: true,
            }),
            other_firewalls: Ok(vec![]),
            updates: Ok(UpdateStatus {
                service_enabled: true,
                days_since_check: Some(0.5),
                days_since_install: Some(0.5),
                restart_pending: false,
                windows_version: None,
            }),
            secure_boot: Ok(SecureBoot::On),
            tpm: Ok(Some("2.0".to_string())),
            uac: Ok(uac_with(5, true, Account::Administrator)),
            remote_access: Ok(remote_off()),
            auto_sign_in: Ok(false),
        }
    }

    fn all_off() -> Result<FirewallProfiles, String> {
        Ok(FirewallProfiles {
            domain: false,
            private: false,
            public: false,
        })
    }

    fn status_of(findings: &[Finding], id: &str) -> Status {
        findings
            .iter()
            .find(|finding| finding.id == id)
            .unwrap()
            .status
    }

    #[test]
    fn healthy_pc_has_no_issues() {
        let findings = build(&healthy());
        assert_eq!(findings.len(), 7);
        assert!(findings.iter().all(|finding| finding.status == Status::Ok));
        assert!(findings.iter().all(|finding| finding.action.is_none()));
    }

    #[test]
    fn every_finding_says_what_was_checked_and_why() {
        for finding in build(&healthy()) {
            assert!(finding.checked.starts_with("I "));
            assert!(!finding.why.is_empty());
        }
    }

    #[test]
    fn second_inactive_antivirus_is_not_a_problem() {
        let finding = antivirus(&Ok(vec![
            product("Norton 360", ProductState::Off),
            product("Windows Defender", ProductState::On),
        ]));
        assert_eq!(finding.status, Status::Ok);
        assert_eq!(finding.summary, "Active");

        // Both products are listed, with the running one first.
        let listed: Vec<(&str, Option<bool>)> = finding
            .details
            .iter()
            .map(|item| (item.label.as_str(), item.active))
            .collect();
        assert_eq!(
            listed,
            vec![
                ("Windows Defender", Some(true)),
                ("Norton 360", Some(false))
            ]
        );
    }

    #[test]
    fn no_active_antivirus_is_a_risk() {
        assert_eq!(antivirus(&Ok(vec![])).status, Status::Risk);

        let off = antivirus(&Ok(vec![product("Windows Defender", ProductState::Off)]));
        assert_eq!(off.status, Status::Risk);
        assert_eq!(off.summary, "Off · Windows Defender");

        let expired = antivirus(&Ok(vec![product("Norton 360", ProductState::Expired)]));
        assert_eq!(expired.status, Status::Risk);

        let snoozed = antivirus(&Ok(vec![product("Norton 360", ProductState::Snoozed)]));
        assert_eq!(snoozed.status, Status::Warning);
    }

    #[test]
    fn out_of_date_definitions_are_a_warning() {
        let outdated = || {
            let mut defender = product("Windows Defender", ProductState::On);
            defender.definitions_up_to_date = false;
            defender
        };

        // Another active product is current, so the PC is still covered.
        let finding = antivirus(&Ok(vec![
            outdated(),
            product("Norton 360", ProductState::On),
        ]));
        assert_eq!(finding.status, Status::Ok);
        assert_eq!(finding.summary, "Active");

        assert_eq!(antivirus(&Ok(vec![outdated()])).status, Status::Warning);
    }

    #[test]
    fn firewall_off_is_reported_by_profile() {
        let none = Ok(vec![]);
        let public_off = firewall(
            &Ok(FirewallProfiles {
                domain: true,
                private: true,
                public: false,
            }),
            &none,
        );
        assert_eq!(public_off.status, Status::Warning);
        assert_eq!(public_off.summary, "Off · Public network");

        let finding = firewall(&all_off(), &none);
        assert_eq!(finding.status, Status::Risk);
        assert_eq!(finding.summary, "Off · all networks");
    }

    #[test]
    fn suite_firewall_explains_windows_firewall_being_off() {
        // The suite's firewall is on: a note that explains why and asks the user to confirm.
        let suite_on = Ok(vec![
            product("Windows Firewall", ProductState::Off),
            product("Norton 360", ProductState::On),
        ]);
        let finding = firewall(&all_off(), &suite_on);
        assert_eq!(finding.status, Status::Info);
        assert_eq!(
            finding.summary,
            "Windows Firewall off · Norton 360 firewall on"
        );
        assert!(
            finding
                .action
                .unwrap()
                .contains("Open Norton 360 and confirm")
        );

        // The suite is installed but its firewall is not active: still a real problem.
        let suite_off = Ok(vec![product("Norton 360", ProductState::Off)]);
        let finding = firewall(&all_off(), &suite_off);
        assert_eq!(finding.status, Status::Risk);
        assert!(
            finding
                .details
                .iter()
                .any(|item| item.value == "Not active")
        );

        // The list could not be read: say so, and do not assume a suite is covering.
        let unreadable = Err("Access is denied.".to_string());
        let finding = firewall(&all_off(), &unreadable);
        assert_eq!(finding.status, Status::Risk);
        assert!(finding.action.unwrap().contains("could not read the list"));
    }

    #[test]
    fn update_problems_are_warnings() {
        let base = || UpdateStatus {
            service_enabled: true,
            days_since_check: Some(0.5),
            days_since_install: Some(3.0),
            restart_pending: false,
            windows_version: None,
        };

        let stale = UpdateStatus {
            days_since_check: Some(9.4),
            ..base()
        };
        let finding = updates(&Ok(stale));
        assert_eq!(finding.status, Status::Warning);
        assert_eq!(finding.summary, "Last checked 9 days ago");

        let restart = UpdateStatus {
            restart_pending: true,
            ..base()
        };
        assert_eq!(updates(&Ok(restart)).status, Status::Warning);

        let unavailable = UpdateStatus {
            service_enabled: false,
            ..base()
        };
        assert_eq!(updates(&Ok(unavailable)).status, Status::Warning);

        let never = UpdateStatus {
            days_since_check: None,
            ..base()
        };
        assert_eq!(updates(&Ok(never)).status, Status::Info);
    }

    #[test]
    fn failed_check_is_never_reported_as_ok() {
        let readings = Readings {
            antivirus: Err("Access is denied.".to_string()),
            firewall: Err("Access is denied.".to_string()),
            other_firewalls: Err("Access is denied.".to_string()),
            updates: Err("Access is denied.".to_string()),
            secure_boot: Err("Access is denied.".to_string()),
            tpm: Err("Access is denied.".to_string()),
            uac: Err("Access is denied.".to_string()),
            remote_access: Err("Access is denied.".to_string()),
            auto_sign_in: Err("Access is denied.".to_string()),
        };
        let findings = build(&readings);
        assert!(
            findings
                .iter()
                .all(|finding| finding.status == Status::Unknown)
        );
    }

    #[test]
    fn one_failed_check_does_not_hide_the_others() {
        let mut readings = healthy();
        readings.firewall = Err("Access is denied.".to_string());
        let findings = build(&readings);
        assert_eq!(status_of(&findings, "firewall"), Status::Unknown);
        assert_eq!(status_of(&findings, "antivirus"), Status::Ok);
        assert_eq!(status_of(&findings, "updates"), Status::Ok);
    }

    #[test]
    fn most_serious_finding_comes_first() {
        let mut readings = healthy();
        readings.antivirus = Ok(vec![]);
        readings.firewall = Ok(FirewallProfiles {
            domain: true,
            private: true,
            public: false,
        });
        let findings = build(&readings);
        let order: Vec<Status> = findings.iter().map(|finding| finding.status).collect();
        assert_eq!(
            order,
            vec![
                Status::Risk,
                Status::Warning,
                Status::Ok,
                Status::Ok,
                Status::Ok,
                Status::Ok,
                Status::Ok
            ]
        );
    }

    fn uac_with(prompt: u32, secure_desktop: bool, account: Account) -> Uac {
        Uac {
            enabled: true,
            prompt,
            secure_desktop,
            account,
        }
    }

    fn remote_off() -> RemoteAccess {
        RemoteAccess {
            desktop: RemoteDesktop {
                enabled: false,
                nla: true,
                port: 3389,
                listening: false,
            },
            assistance: false,
            winrm: ServiceState::NotInstalled,
            ssh: ServiceState::NotInstalled,
        }
    }

    fn remote_desktop(enabled: bool, listening: bool, nla: bool) -> RemoteAccess {
        RemoteAccess {
            desktop: RemoteDesktop {
                enabled,
                nla,
                port: 3389,
                listening,
            },
            ..remote_off()
        }
    }

    fn unreadable() -> String {
        "Access is denied.".to_string()
    }

    #[test]
    fn secure_boot_off_or_unavailable_is_a_note() {
        let off = startup(&Ok(SecureBoot::Off), &Ok(Some("2.0".to_string())));
        assert_eq!(off.status, Status::Info);
        assert!(off.summary.starts_with("Secure Boot off"));

        let legacy = startup(&Ok(SecureBoot::LegacyBios), &Ok(Some("2.0".to_string())));
        assert_eq!(legacy.status, Status::Info);
        assert!(legacy.action.unwrap().contains("UEFI"));
    }

    #[test]
    fn missing_or_old_tpm_is_a_note() {
        let none = startup(&Ok(SecureBoot::On), &Ok(None));
        assert_eq!(none.status, Status::Info);
        assert_eq!(none.summary, "No TPM");

        let old = startup(&Ok(SecureBoot::On), &Ok(Some("1.2".to_string())));
        assert_eq!(old.status, Status::Info);
    }

    #[test]
    fn startup_protection_says_what_it_found_when_all_is_well() {
        let finding = startup(&Ok(SecureBoot::On), &Ok(Some("2.0".to_string())));
        assert_eq!(finding.status, Status::Ok);
        assert_eq!(finding.summary, "Secure Boot on · TPM 2.0");
    }

    #[test]
    fn startup_protection_is_limited_when_only_one_part_could_be_read() {
        let finding = startup(&Err(unreadable()), &Ok(Some("2.0".to_string())));
        assert_eq!(finding.status, Status::Limited);

        let both = startup(&Err(unreadable()), &Err(unreadable()));
        assert_eq!(both.status, Status::Unknown);
    }

    #[test]
    fn uac_off_or_never_asking_is_a_warning() {
        let off = Uac {
            enabled: false,
            ..uac_with(5, true, Account::Administrator)
        };
        assert_eq!(uac(&Ok(off)).status, Status::Warning);
        assert_eq!(
            uac(&Ok(uac_with(0, true, Account::Administrator))).status,
            Status::Warning
        );
    }

    #[test]
    fn an_administrator_without_the_split_is_a_warning_even_if_the_screen_is_not_dimmed() {
        let finding = uac(&Ok(uac_with(5, false, Account::AdministratorUacOff)));
        assert_eq!(finding.status, Status::Warning);
    }

    #[test]
    fn uac_that_does_not_dim_the_screen_is_a_note() {
        let finding = uac(&Ok(uac_with(5, false, Account::Administrator)));
        assert_eq!(finding.status, Status::Info);
    }

    #[test]
    fn running_tenax_as_administrator_is_a_note() {
        let finding = uac(&Ok(uac_with(5, true, Account::Elevated)));
        assert_eq!(finding.status, Status::Info);
        assert!(
            finding
                .action
                .unwrap()
                .contains("does not need administrator")
        );
    }

    #[test]
    fn uac_on_with_default_settings_is_fine_for_either_account() {
        for account in [Account::Standard, Account::Administrator] {
            assert_eq!(uac(&Ok(uac_with(5, true, account))).status, Status::Ok);
        }
    }

    #[test]
    fn remote_desktop_without_network_level_authentication_is_a_warning() {
        let finding = remote_access(&Ok(remote_desktop(true, true, false)));
        assert_eq!(finding.status, Status::Warning);
        assert!(finding.note.is_some());
    }

    #[test]
    fn a_listener_counts_even_when_the_setting_says_off() {
        // A Group Policy can allow Remote Desktop without the setting changing.
        let finding = remote_access(&Ok(remote_desktop(false, true, true)));
        assert_eq!(finding.status, Status::Info);
        assert_eq!(finding.summary, "On · Remote Desktop");
        let weak = remote_access(&Ok(remote_desktop(false, true, false)));
        assert_eq!(weak.status, Status::Warning);
    }

    #[test]
    fn remote_desktop_that_is_listening_is_a_note() {
        let finding = remote_access(&Ok(remote_desktop(true, true, true)));
        assert_eq!(finding.status, Status::Info);
        assert_eq!(finding.summary, "On · Remote Desktop");
    }

    #[test]
    fn remote_desktop_allowed_but_not_listening_is_a_note() {
        let finding = remote_access(&Ok(remote_desktop(true, false, true)));
        assert_eq!(finding.status, Status::Info);
        assert!(finding.note.is_none());
    }

    #[test]
    fn running_remote_services_are_a_note() {
        let remote = RemoteAccess {
            winrm: ServiceState::Running,
            ssh: ServiceState::Running,
            ..remote_off()
        };
        let finding = remote_access(&Ok(remote));
        assert_eq!(finding.status, Status::Info);
        assert_eq!(
            finding.summary,
            "On · Windows Remote Management and OpenSSH server"
        );
    }

    #[test]
    fn a_stopped_or_missing_remote_service_is_not_a_problem() {
        let remote = RemoteAccess {
            winrm: ServiceState::Stopped,
            ..remote_off()
        };
        assert_eq!(remote_access(&Ok(remote)).status, Status::Ok);
        assert_eq!(remote_access(&Ok(remote_off())).status, Status::Ok);
    }

    #[test]
    fn automatic_sign_in_is_a_warning_only_when_it_is_on() {
        assert_eq!(sign_in(&Ok(true)).status, Status::Warning);
        assert_eq!(sign_in(&Ok(false)).status, Status::Ok);
        assert_eq!(sign_in(&Err(unreadable())).status, Status::Unknown);
    }

    #[test]
    fn every_step_belongs_to_a_finding_that_exists() {
        // The step ids the reader uses must match finding ids, or the activity log loses the step.
        let ids: Vec<String> = build(&healthy())
            .into_iter()
            .map(|finding| finding.id)
            .collect();
        for step_id in [
            "antivirus",
            "firewall",
            "updates",
            "startup",
            "uac",
            "remote",
            "signin",
        ] {
            assert!(ids.iter().any(|id| id == step_id), "{step_id}");
        }
    }

    // Reads this PC's real settings. Run with: cargo test -- --ignored --nocapture
    #[cfg(windows)]
    #[test]
    #[ignore]
    fn print_real_findings() {
        let readings = super::super::reader::read().0;
        println!("secure_boot: {:?}", readings.secure_boot);
        println!("tpm: {:?}", readings.tpm);
        println!("uac: {:?}", readings.uac);
        println!("remote_access: {:?}", readings.remote_access);
        println!("auto_sign_in: {:?}", readings.auto_sign_in);
        // Ports 135 and 445 normally listen on Windows, so seeing them shows the table is read correctly.
        println!(
            "listening v4: {:?}",
            super::super::reader::listening_ports(2)
        );
        println!(
            "listening v6: {:?}",
            super::super::reader::listening_ports(23)
        );
        for finding in build(&readings) {
            println!(
                "{:?} | {} | {}",
                finding.status, finding.title, finding.summary
            );
            for item in &finding.details {
                println!("    {}: {}", item.label, item.value);
            }
        }
    }
}
