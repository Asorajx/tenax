// The global network-access switch. It is off every time Tenax starts, and it only turns on
// when the user turns it on in the sidebar. Every command that connects to something outside
// this PC goes through it, so a tool cannot go online while it is off, whatever the interface does.
//
// Turning it off also stops work that is already running:
//   - A web request in progress is dropped, which closes its connection.
//   - A command that is waiting on Windows (a DNS question or a handshake) stops waiting at once and
//     reports that it was cancelled. Windows cannot be told to abandon the step it is in, so that step
//     finishes on its own and its result is thrown away, but no further step is started.
//
// The offline checks never look at it.

use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, Weak};
use std::task::{Context, Poll, Waker};

// One switch for the whole app, since Tenax has one window and one user.
static ENABLED: AtomicBool = AtomicBool::new(false);

// Counts how many times the switch has been turned off. A command that began before the switch was
// turned off and on again is still cancelled, because the number has moved on.
static TURNED_OFF: AtomicU64 = AtomicU64::new(0);

// Commands waiting on something, so turning the switch off can wake them to notice.
static WAITING: Mutex<Vec<Weak<Mutex<Option<Waker>>>>> = Mutex::new(Vec::new());

// What a tool says when it is asked to go online while the switch is off.
const OFF_MESSAGE: &str =
    "Network access is off. Turn it on in the sidebar to use connected analysis.";

// What a tool says when the switch is turned off while it is working.
const CANCELLED_MESSAGE: &str = "Cancelled: network access was turned off.";

// Called first by every command that uses the network, and again before each step that connects
// to something. It also stops work that is already running when the switch has been turned off.
pub fn require() -> Result<(), String> {
    if ENABLED.load(Ordering::SeqCst) {
        Ok(())
    } else {
        Err(OFF_MESSAGE.to_string())
    }
}

// Runs a task that uses the network, but only while the switch stays on. If it is turned off first,
// the task is dropped where it stands and this returns an error.
pub async fn run<T>(task: impl Future<Output = T>) -> Result<T, String> {
    require()?;
    Cancellable {
        task: Box::pin(task),
        began: TURNED_OFF.load(Ordering::SeqCst),
        slot: Arc::new(Mutex::new(None)),
    }
    .await
}

struct Cancellable<F> {
    task: Pin<Box<F>>,
    // How many times the switch had been turned off when the task began.
    began: u64,
    // Where this task leaves its waker, so turning the switch off can wake it.
    slot: Arc<Mutex<Option<Waker>>>,
}

impl<F> Cancellable<F> {
    fn cancelled(&self) -> bool {
        !ENABLED.load(Ordering::SeqCst) || TURNED_OFF.load(Ordering::SeqCst) != self.began
    }
}

impl<F: Future> Future for Cancellable<F> {
    type Output = Result<F::Output, String>;

    fn poll(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Self::Output> {
        // The waker is left first and the switch checked after, so a switch turned off in between
        // cannot be missed.
        {
            let mut waiting = WAITING
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            let mut slot = self
                .slot
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            if slot.is_none() {
                waiting.retain(|other| other.strong_count() > 0);
                waiting.push(Arc::downgrade(&self.slot));
            }
            *slot = Some(context.waker().clone());
        }
        if self.cancelled() {
            return Poll::Ready(Err(CANCELLED_MESSAGE.to_string()));
        }
        match self.task.as_mut().poll(context) {
            Poll::Ready(value) => Poll::Ready(Ok(value)),
            Poll::Pending => Poll::Pending,
        }
    }
}

// Turns the switch on or off, and wakes everything that is waiting so it can notice.
fn set(enabled: bool) {
    if !enabled {
        TURNED_OFF.fetch_add(1, Ordering::SeqCst);
    }
    ENABLED.store(enabled, Ordering::SeqCst);
    if !enabled {
        let waiting = WAITING
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        for slot in waiting.iter().filter_map(Weak::upgrade) {
            if let Some(waker) = slot
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .take()
            {
                waker.wake();
            }
        }
    }
}

// Called from the interface with invoke("set_network_access", { enabled }).
#[tauri::command]
pub fn set_network_access(enabled: bool) {
    set(enabled);
}

// Called from the interface with invoke("network_access"), so the sidebar shows the real state
// if the window is reloaded while the app keeps running.
#[tauri::command]
pub fn network_access() -> bool {
    ENABLED.load(Ordering::SeqCst)
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;
    use std::thread;
    use std::time::{Duration, Instant};

    use super::*;

    // The switch is shared by the whole process, so the tests that change it take turns.
    static ONE_AT_A_TIME: Mutex<()> = Mutex::new(());

    fn turn(enabled: bool) {
        set(enabled);
    }

    // A task that never finishes by itself, and says if it was dropped.
    struct Forever(Arc<AtomicBool>);

    impl Future for Forever {
        type Output = ();

        fn poll(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<()> {
            Poll::Pending
        }
    }

    impl Drop for Forever {
        fn drop(&mut self) {
            self.0.store(true, Ordering::SeqCst);
        }
    }

    #[test]
    fn it_starts_off_refuses_while_off_and_allows_once_on() {
        let _turn = ONE_AT_A_TIME.lock().unwrap_or_else(|p| p.into_inner());
        turn(false);
        assert!(!network_access());
        assert_eq!(require().unwrap_err(), OFF_MESSAGE);

        set_network_access(true);
        assert!(network_access());
        assert!(require().is_ok());

        set_network_access(false);
        assert!(require().is_err());
    }

    #[test]
    fn a_task_is_refused_while_off_and_runs_to_its_result_while_on() {
        let _turn = ONE_AT_A_TIME.lock().unwrap_or_else(|p| p.into_inner());
        turn(false);
        let refused = tauri::async_runtime::block_on(run(async { 1 }));
        assert_eq!(refused.unwrap_err(), OFF_MESSAGE);

        turn(true);
        let done = tauri::async_runtime::block_on(run(async { 7 }));
        assert_eq!(done, Ok(7));
        turn(false);
    }

    #[test]
    fn turning_it_off_cancels_a_task_that_is_running_and_drops_it() {
        let _turn = ONE_AT_A_TIME.lock().unwrap_or_else(|p| p.into_inner());
        turn(true);
        let dropped = Arc::new(AtomicBool::new(false));

        let flipper = thread::spawn(|| {
            thread::sleep(Duration::from_millis(150));
            set_network_access(false);
        });
        let started = Instant::now();
        let outcome = tauri::async_runtime::block_on(run(Forever(dropped.clone())));
        flipper.join().unwrap();

        assert_eq!(outcome.unwrap_err(), CANCELLED_MESSAGE);
        // It stopped as soon as the switch went off, and did not wait for anything else.
        assert!(started.elapsed() < Duration::from_secs(3));
        assert!(dropped.load(Ordering::SeqCst), "the task was not dropped");
    }

    #[test]
    fn turning_it_off_and_straight_back_on_still_cancels() {
        let _turn = ONE_AT_A_TIME.lock().unwrap_or_else(|p| p.into_inner());
        turn(true);
        let flipper = thread::spawn(|| {
            thread::sleep(Duration::from_millis(150));
            set_network_access(false);
            set_network_access(true);
        });
        let outcome =
            tauri::async_runtime::block_on(run(Forever(Arc::new(AtomicBool::new(false)))));
        flipper.join().unwrap();
        assert_eq!(outcome.unwrap_err(), CANCELLED_MESSAGE);
        turn(false);
    }

    #[test]
    fn several_tasks_are_all_cancelled_and_leave_nothing_waiting() {
        let _turn = ONE_AT_A_TIME.lock().unwrap_or_else(|p| p.into_inner());
        turn(true);
        let tasks: Vec<_> = (0..4)
            .map(|_| {
                thread::spawn(|| {
                    tauri::async_runtime::block_on(run(Forever(Arc::new(AtomicBool::new(false)))))
                })
            })
            .collect();
        thread::sleep(Duration::from_millis(200));
        set_network_access(false);
        for task in tasks {
            assert_eq!(task.join().unwrap().unwrap_err(), CANCELLED_MESSAGE);
        }
        // The next task that waits tidies away the finished ones.
        turn(true);
        let _ = tauri::async_runtime::block_on(run(async {}));
        let live = WAITING
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .iter()
            .filter(|slot| slot.strong_count() > 0)
            .count();
        assert_eq!(live, 0);
        turn(false);
    }

    // =========================
    // No way around the switch
    // =========================

    use std::fs;
    use std::path::{Path, PathBuf};

    fn sources(directory: &Path, found: &mut Vec<PathBuf>) {
        for entry in fs::read_dir(directory).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                sources(&path, found);
            } else if path.extension().is_some_and(|extension| extension == "rs") {
                found.push(path);
            }
        }
    }

    fn all_sources() -> Vec<(String, String)> {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
        let mut files = Vec::new();
        sources(&root, &mut files);
        files
            .into_iter()
            .map(|path| {
                let name = path
                    .strip_prefix(&root)
                    .unwrap()
                    .to_string_lossy()
                    .replace('\\', "/");
                (name, fs::read_to_string(&path).unwrap())
            })
            .collect()
    }

    // The only files that may contain code that reaches outside this PC. If a new file needs to,
    // it must be added here on purpose, and be put behind the switch.
    const NETWORK_FILES: [&str; 5] = [
        "breached_passwords/lookup.rs",
        "dns_lookup/resolver.rs",
        "ip_info/external.rs",
        "tls_check/mod.rs",
        "tls_check/session.rs",
    ];

    // What reaches outside this PC: web requests, sockets, name lookups and Windows DNS.
    const NETWORK_CALLS: [&str; 9] = [
        "reqwest",
        "TcpStream",
        "UdpSocket",
        "ToSocketAddrs",
        "to_socket_addrs",
        "TlsConnector",
        "native_tls",
        "DnsQuery_",
        "WinHttp",
    ];

    #[test]
    fn only_the_gated_files_contain_network_code() {
        for (name, text) in all_sources() {
            // This file lists the calls above, so it would always match.
            if name == "network.rs" {
                continue;
            }
            let uses = NETWORK_CALLS.iter().find(|call| text.contains(**call));
            if let Some(call) = uses {
                assert!(
                    NETWORK_FILES.contains(&name.as_str()),
                    "{name} uses {call}, but is not one of the files that are behind the network switch"
                );
            }
        }
    }

    // The commands the interface can call that never go online.
    const OFFLINE_COMMANDS: [&str; 7] = [
        "analyse_email_headers",
        "check_email_scam",
        "check_url",
        "check_windows_security",
        "inspect_ip",
        "network_access",
        "set_network_access",
    ];

    #[test]
    fn every_command_is_either_offline_on_purpose_or_behind_the_switch() {
        let mut seen = Vec::new();
        for (name, text) in all_sources() {
            for part in text.split("#[tauri::command]").skip(1) {
                let body = part.split("\n}\n").next().unwrap_or(part);
                let command = body
                    .split("fn ")
                    .nth(1)
                    .and_then(|rest| rest.split('(').next())
                    .unwrap()
                    .trim();
                seen.push(command.to_string());

                // A stub for other systems only returns an error, so it goes nowhere.
                if body.contains("only runs on Windows") {
                    continue;
                }
                let gated = body.contains("network::require()");
                let offline = OFFLINE_COMMANDS.contains(&command);
                assert!(
                    gated != offline,
                    "{command} in {name} must either call network::require() or be listed as offline, not both and not neither"
                );
            }
        }
        // Every offline command listed really exists, so the list cannot go stale.
        for command in OFFLINE_COMMANDS {
            assert!(
                seen.iter().any(|seen| seen == command),
                "{command} is listed but not found"
            );
        }
    }

    #[test]
    fn the_connecting_steps_check_the_switch_themselves() {
        let files = all_sources();
        let text = |wanted: &str| {
            files
                .iter()
                .find(|(name, _)| name == wanted)
                .map(|(_, text)| text.clone())
                .unwrap()
        };
        // Web requests are wrapped so they are dropped when the switch goes off.
        assert!(text("breached_passwords/mod.rs").contains("network::run(lookup::run("));
        assert!(text("ip_info/mod.rs").contains("network::run(external::fetch("));
        // Windows' DNS client, handshakes and name lookups refuse to start a new step.
        assert!(text("dns_lookup/resolver.rs").contains("network::require()"));
        assert!(
            text("tls_check/mod.rs")
                .matches("network::require()")
                .count()
                >= 3
        );
        // And the commands that wait on a worker thread stop waiting.
        for file in ["dns_lookup/mod.rs", "ip_info/mod.rs", "tls_check/mod.rs"] {
            assert!(text(file).contains("network::run(task)"), "{file}");
        }
    }
}
