mod app;
mod ca;
mod claude_client;
mod crawler;
mod gui;
mod mcp;
mod proxy;
mod rapport;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

fn main() {
    unsafe {
        let v = std::env::var("LIBGL_ALWAYS_SOFTWARE").unwrap_or_default();
        if v.is_empty() || v == "0" {
            std::env::set_var("LIBGL_ALWAYS_SOFTWARE", "1");
        }
    }

    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("failed to install ring crypto provider");

    let ca = Arc::new(ca::Ca::new());
    match ca.save_pem() {
        Ok(ref path) => {
            eprintln!("[rustman] CA cert: {}", path.display());
            auto_install_cert(path);
        }
        Err(e) => eprintln!("[rustman] Warning: could not save CA cert: {e}"),
    }

    let state: app::Shared = Arc::new(Mutex::new(app::AppState::new()));

    let (restart_tx, restart_rx) = std::sync::mpsc::sync_channel::<(String, u16)>(1);
    state.lock().unwrap().proxy_restart_tx = Some(restart_tx.clone());

    let (ready_tx, ready_rx) = std::sync::mpsc::sync_channel::<Result<(String, u16), String>>(0);
    let initial_stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
    {
        let stop = initial_stop.clone();
        let s = state.clone();
        let c = ca.clone();
        let ready = ready_tx;
        std::thread::spawn(move || {
            tokio::runtime::Runtime::new()
                .expect("tokio runtime")
                .block_on(proxy::run(s, c, "127.0.0.1".to_string(), 8080, ready, stop));
        });
    }

    match ready_rx
        .recv()
        .unwrap_or_else(|_| Err("proxy thread died".into()))
    {
        Ok((addr, port)) => {
            eprintln!("[rustman] proxy listening on {addr}:{port}");
            let mut s = state.lock().unwrap();
            s.settings.proxy_addr = addr;
            s.settings.proxy_port = port;
        }
        Err(e) => {
            eprintln!("[rustman] ERROR: {e}");
            std::process::exit(1);
        }
    }

    {
        let mgr_state = state.clone();
        let mgr_ca = ca.clone();
        let mut cur_stop = initial_stop;
        std::thread::spawn(move || {
            for (new_addr, new_port) in restart_rx {
                // Stop the current proxy.
                cur_stop.store(true, std::sync::atomic::Ordering::Relaxed);
                // Give it up to 300 ms to stop (accept loop checks every 100 ms).
                std::thread::sleep(std::time::Duration::from_millis(300));

                let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
                cur_stop = stop.clone();

                let (ready_tx, ready_rx) =
                    std::sync::mpsc::sync_channel::<Result<(String, u16), String>>(0);
                {
                    let s = mgr_state.clone();
                    let c = mgr_ca.clone();
                    let f = stop;
                    std::thread::spawn(move || {
                        tokio::runtime::Runtime::new()
                            .expect("tokio runtime")
                            .block_on(proxy::run(s, c, new_addr, new_port, ready_tx, f));
                    });
                }

                let result = ready_rx.recv().unwrap_or_else(|_| Err("proxy died".into()));
                let mut st = mgr_state.lock().unwrap();
                st.proxy_restarting = false;
                match result {
                    Ok((addr, port)) => {
                        eprintln!("[rustman] proxy restarted on {addr}:{port}");
                        st.settings.proxy_addr = addr;
                        st.settings.proxy_port = port;
                    }
                    Err(e) => eprintln!("[rustman] proxy restart failed: {e}"),
                }
            }
        });
    }

    let bg_rt = std::sync::Arc::new(tokio::runtime::Runtime::new().expect("bg runtime"));

    let mcp_state = state.clone();
    bg_rt.spawn(async move {
        mcp::serve(mcp_state, 8099).await;
    });

    if let Err(e) = gui::run(state, bg_rt) {
        eprintln!("GUI: {e}");
    }
}

// ── Automatic certificate installation ───────────────────────────────────────

fn auto_install_cert(cert_path: &Path) {
    let profiles = find_firefox_profiles();

    if profiles.is_empty() {
        eprintln!("[cert] No Firefox profile found (looked in ~/.mozilla and /mnt/c/Users/*/AppData/Roaming/Mozilla/Firefox)");
        eprintln!("[cert] Import manually: {}", cert_path.display());
        return;
    }

    // certutil comes from the `libnss3-tools` package on Debian/Ubuntu.
    let has_certutil = std::process::Command::new("certutil")
        .arg("--help")
        .output()
        .map(|o| o.status.success() || !o.stdout.is_empty() || !o.stderr.is_empty())
        .unwrap_or(false);

    if !has_certutil {
        eprintln!("[cert] 'certutil' not found — install it with:");
        eprintln!("       sudo apt install libnss3-tools");
        eprintln!("[cert] Then restart rustman and the cert will be auto-installed.");
        return;
    }

    let mut any_installed = false;

    for profile in &profiles {
        let db_prefix = if profile.join("cert9.db").exists() {
            "sql:"
        } else {
            "dbm:"
        };
        let db_arg = format!("{}{}", db_prefix, profile.display());
        let cert_str = cert_path.display().to_string();

        // Always delete the old entry first (ignore errors — might not exist).
        let _ = std::process::Command::new("certutil")
            .args(["-d", &db_arg, "-D", "-n", "rustman Proxy CA"])
            .output();

        // Install the current cert (same DER every run if key hasn't changed).
        let out = std::process::Command::new("certutil")
            .args([
                "-d",
                &db_arg,
                "-A",
                "-t",
                "CT,,",
                "-n",
                "rustman Proxy CA",
                "-i",
                &cert_str,
            ])
            .output();

        match out {
            Ok(o) if o.status.success() => {
                eprintln!("[cert] ✓ Installed in {}", profile.display());
                any_installed = true;
            }
            Ok(o) => {
                let err = String::from_utf8_lossy(&o.stderr);
                eprintln!("[cert] ✗ Failed for {} — {}", profile.display(), err.trim());
            }
            Err(e) => eprintln!("[cert] ✗ certutil error: {e}"),
        }
    }

    if any_installed {
        eprintln!("[cert] Restart Firefox for the certificate to take effect.");
    }
}

fn find_firefox_profiles() -> Vec<PathBuf> {
    let mut out = Vec::new();

    // Linux / native WSL Firefox
    if let Ok(home) = std::env::var("HOME") {
        collect_profiles(&PathBuf::from(home).join(".mozilla/firefox"), &mut out);
    }

    // Windows Firefox accessed from WSL2 (/mnt/c/Users/<user>/AppData/...)
    if let Ok(entries) = std::fs::read_dir("/mnt/c/Users") {
        for entry in entries.flatten() {
            let p = entry
                .path()
                .join("AppData/Roaming/Mozilla/Firefox/Profiles");
            collect_profiles(&p, &mut out);
        }
    }

    out
}

/// Walk `dir` and collect any subdirectory that contains cert9.db or cert8.db.
fn collect_profiles(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(rd) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in rd.flatten() {
        let p = entry.path();
        if p.is_dir() && (p.join("cert9.db").exists() || p.join("cert8.db").exists()) {
            out.push(p);
        }
    }
}
