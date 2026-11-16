// Turns raw readings into findings: the state at a glance, what Tenax checked,
// why it checked, and what to do.
// There is no Windows code here, so every case can be tested with made-up readings.

use super::{FirewallProfiles, ProductState, Readings, SecurityProduct, UpdateStatus};
use crate::finding::{Detail, Finding, Status, detail, switch};

// A longer gap than this since the last update check is reported.
const STALE_CHECK_DAYS: f64 = 7.0;

pub fn build(readings: &Readings) -> Vec<Finding> {
    let mut findings = vec![
        antivirus(&readings.antivirus),
        firewall(&readings.firewall, &readings.other_firewalls),
        updates(&readings.updates),
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

fn join_names(names: &[&str]) -> String {
    match names {
        [] => String::new(),
        [only] => only.to_string(),
        [rest @ .., last] => format!("{} and {}", rest.join(", "), last),
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

    let all = join_names(&names_where(&products, |_| true));
    let active = names_where(&products, |product| product.state == ProductState::On);

    if active.is_empty() {
        let snoozed = names_where(&products, |product| product.state == ProductState::Snoozed);
        let expired = names_where(&products, |product| product.state == ProductState::Expired);

        return if !snoozed.is_empty() {
            ANTIVIRUS.finding(
                Status::Warning,
                format!("Snoozed · {}", join_names(&snoozed)),
                Some("Open your antivirus and resume protection.".to_string()),
                details,
            )
        } else if !expired.is_empty() {
            ANTIVIRUS.finding(
                Status::Risk,
                format!("Expired · {}", join_names(&expired)),
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
            format!("On, definitions out of date · {}", join_names(&active)),
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
        let suite = join_names(&active_others);
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
            join_names(&off),
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
// Tests
// =========================

#[cfg(test)]
mod tests {
    use super::*;

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
        assert_eq!(findings.len(), 3);
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
        assert_eq!(order, vec![Status::Risk, Status::Warning, Status::Ok]);
    }

    // Reads this PC's real settings. Run with: cargo test -- --ignored --nocapture
    #[cfg(windows)]
    #[test]
    #[ignore]
    fn print_real_findings() {
        for finding in build(&super::super::reader::read().0) {
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
