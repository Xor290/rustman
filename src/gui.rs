use crate::app::{Shared, Status};
use eframe::egui::{self, Color32, RichText, ScrollArea, TextEdit, Vec2};
use std::sync::Arc;

fn load_window_icon() -> std::sync::Arc<egui::IconData> {
    let bytes = include_bytes!("../logo.png");
    let img = image::load_from_memory(bytes)
        .expect("logo.png embedded")
        .resize_exact(256, 256, image::imageops::FilterType::Lanczos3)
        .to_rgba8();
    let (w, h) = img.dimensions();
    std::sync::Arc::new(egui::IconData {
        rgba: img.into_raw(),
        width: w,
        height: h,
    })
}

pub fn run(state: Shared, rt: Arc<tokio::runtime::Runtime>) -> Result<(), eframe::Error> {
    let icon = load_window_icon();

    let opts = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_title("RUSTMAN")
            .with_inner_size([1300.0, 760.0])
            .with_min_inner_size([900.0, 500.0])
            .with_icon(icon),
        ..Default::default()
    };

    eframe::run_native(
        "rustman",
        opts,
        Box::new(|cc| {
            cc.egui_ctx.set_visuals(dark_theme());
            Ok(Box::new(RustmanApp::new(state, rt)))
        }),
    )
}

// ── Tab ───────────────────────────────────────────────────────────────────────

#[derive(PartialEq)]
enum ActiveTab {
    Proxy,
    Repeater,
    Crawler,
    OpenAPI,
    Settings,
    Exploit,
}

// ── Repeater session ─────────────────────────────────────────────────────────

struct RepeaterSession {
    id: usize,
    label: String,
    host: String,
    port: u16,
    tls: bool,
    req_buf: String,
    response: Option<String>,
    pending: Option<std::sync::mpsc::Receiver<Vec<u8>>>,
}

// ── Exploit message ───────────────────────────────────────────────────────────

struct ExploitMessage {
    from_user: bool,
    text: String,
}

// ── App state (GUI-local) ─────────────────────────────────────────────────────

struct RustmanApp {
    state: Shared,
    logo_texture: Option<egui::TextureHandle>,
    // Proxy tab
    selected: Option<usize>,
    edit_buf: String,
    dirty: bool,
    // Navigation
    tab: ActiveTab,
    // Repeater tab
    repeater: Vec<RepeaterSession>,
    rep_next_id: usize,
    rep_selected: Option<usize>,
    rt: Arc<tokio::runtime::Runtime>,
    // Settings tab
    settings_ignore_input: String,
    settings_proxy_addr: String,
    settings_proxy_port: u16,
    // Claude floating window
    claude_window_open: bool,
    claude_selected_req: Option<usize>,
    claude_req_picker_open: bool,
    claude_input: String,
    claude_rx: Option<std::sync::mpsc::Receiver<Result<String, String>>>,
    claude_thinking: bool,
    claude_mode: crate::claude_client::AssistantMode,
    // Crawler tab
    crawler_url: String,
    crawler_max_depth: usize,
    crawler_entries: Vec<crate::crawler::CrawlerEntry>,
    crawler_rx: Option<std::sync::mpsc::Receiver<crate::crawler::CrawlMsg>>,
    crawler_stop: Option<Arc<std::sync::atomic::AtomicBool>>,
    crawler_running: bool,
    crawler_selected: Option<usize>,
    // O(1) lookup: URL → crawler_entries index (kept in sync with crawler_entries).
    crawler_entry_index: std::collections::HashMap<String, usize>,
    // Cached per-frame values (avoids repeated mutex locks).
    cached_light_mode: bool,
    cached_pending_prompt: bool,
    // Version from AppState — lets sync_selection skip when nothing changed.
    cached_req_version: u64,
    // Exploit Dev tab
    exploit_selected: Option<usize>,
    exploit_messages: Vec<ExploitMessage>,
    exploit_input: String,
    exploit_rx: Option<std::sync::mpsc::Receiver<Result<String, String>>>,
    exploit_thinking: bool,
    exploit_code: String,
    // Crawler auth credentials (submitted automatically on login pages).
    crawler_auth_user: String,
    crawler_auth_pass: String,
    crawler_auth_user_field: String,
    crawler_auth_pass_field: String,
    crawler_session_cookie: String,
    crawler_auth_bearer: String,
    crawler_show_auth: bool,
    // ── Onglet OpenAPI ────────────────────────────────────────────────────────
    openapi_file_path:    String,
    openapi_target_url:   String,
    openapi_endpoints:    Vec<crate::openapi::ApiEndpoint>,
    openapi_creds:        crate::openapi::Credentials,
    openapi_parse_status: Option<String>,
    openapi_selected:     Option<usize>,
    openapi_selected_res: Option<usize>,
    openapi_results:      Vec<crate::openapi::ScanResult>,
    openapi_rx:           Option<std::sync::mpsc::Receiver<crate::openapi::ScanMsg>>,
    openapi_stop:         Option<std::sync::Arc<std::sync::atomic::AtomicBool>>,
    openapi_jobs_total:   usize,  // total (ep, param, cat) triples
    openapi_jobs_done:    usize,  // triples terminés (via TripleDone)
    openapi_jobs_skipped: usize,
    openapi_scanning:     bool,
    openapi_md_status:    Option<String>,
}

impl RustmanApp {
    fn new(state: Shared, rt: Arc<tokio::runtime::Runtime>) -> Self {
        Self {
            state,
            logo_texture: None,
            selected: None,
            edit_buf: String::new(),
            dirty: false,
            tab: ActiveTab::Proxy,
            repeater: Vec::new(),
            rep_next_id: 0,
            rep_selected: None,
            rt,
            settings_ignore_input: String::new(),
            settings_proxy_addr: "127.0.0.1".to_string(),
            settings_proxy_port: 8080,
            claude_window_open: false,
            claude_selected_req: None,
            claude_req_picker_open: false,
            claude_input: String::new(),
            claude_rx: None,
            claude_thinking: false,
            claude_mode: crate::claude_client::AssistantMode::General,
            crawler_url: String::new(),
            crawler_max_depth: 3,
            crawler_entries: Vec::new(),
            crawler_rx: None,
            crawler_stop: None,
            crawler_running: false,
            crawler_selected: None,
            crawler_entry_index: std::collections::HashMap::new(),
            cached_light_mode: false,
            cached_pending_prompt: false,
            cached_req_version: 0,
            exploit_selected: None,
            exploit_messages: Vec::new(),
            exploit_input: String::new(),
            exploit_rx: None,
            exploit_thinking: false,
            exploit_code: String::new(),
            crawler_auth_user: String::new(),
            crawler_auth_pass: String::new(),
            crawler_auth_user_field: String::new(),
            crawler_auth_pass_field: String::new(),
            crawler_session_cookie: String::new(),
            crawler_auth_bearer: String::new(),
            crawler_show_auth: false,
            openapi_file_path:    String::new(),
            openapi_target_url:   String::new(),
            openapi_endpoints:    Vec::new(),
            openapi_creds:        crate::openapi::Credentials::default(),
            openapi_parse_status: None,
            openapi_selected:     None,
            openapi_selected_res: None,
            openapi_results:      Vec::new(),
            openapi_rx:           None,
            openapi_stop:         None,
            openapi_jobs_total:   0,
            openapi_jobs_done:    0,
            openapi_jobs_skipped: 0,
            openapi_scanning:     false,
            openapi_md_status:    None,
        }
    }

    fn sync_selection(&mut self) {
        let s = self.state.lock().unwrap();

        // Skip all work if nothing in AppState changed and the user hasn't edited.
        if s.version == self.cached_req_version && !self.dirty {
            return;
        }
        self.cached_req_version = s.version;

        let total = s.requests.len();

        if let Some(sel) = self.selected {
            if sel >= total {
                self.selected = if total > 0 { Some(total - 1) } else { None };
                self.dirty = false;
            }
        }

        let cur_is_pending = self
            .selected
            .and_then(|i| s.requests.get(i))
            .map(|r| r.status == Status::Pending)
            .unwrap_or(false);

        if !cur_is_pending {
            if let Some(i) = s.requests.iter().rposition(|r| r.status == Status::Pending) {
                self.selected = Some(i);
                self.edit_buf = s.requests[i].display_text();
                self.dirty = false;
            }
        }

        if !self.dirty {
            if let Some(i) = self.selected {
                if let Some(r) = s.requests.get(i) {
                    let fresh = r.display_text();
                    if self.edit_buf != fresh {
                        self.edit_buf = fresh;
                    }
                }
            }
        }
    }

    fn poll_repeater(&mut self) -> bool {
        let mut changed = false;
        for sess in &mut self.repeater {
            if let Some(rx) = &sess.pending {
                if let Ok(bytes) = rx.try_recv() {
                    sess.response = Some(String::from_utf8_lossy(&bytes).into_owned());
                    sess.pending = None;
                    changed = true;
                }
            }
        }
        changed
    }

    fn poll_crawler(&mut self, _ctx: &egui::Context) -> bool {
        use crate::crawler::{CrawlMsg, EntryStatus};
        if self.crawler_rx.is_none() {
            return false;
        }

        let mut changed = false;
        // Cap at 32 messages per frame to keep the UI responsive.
        for _ in 0..32 {
            let msg = match &self.crawler_rx {
                Some(rx) => match rx.try_recv() {
                    Ok(m) => m,
                    Err(_) => break,
                },
                None => break,
            };
            changed = true;
            match msg {
                CrawlMsg::Visiting {
                    url,
                    depth,
                    request,
                } => {
                    let idx = self.crawler_entries.len();
                    self.crawler_entry_index.insert(url.clone(), idx);
                    self.crawler_entries.push(crate::crawler::CrawlerEntry {
                        url,
                        depth,
                        status: EntryStatus::Fetching,
                        request,
                        response: Vec::new(),
                    });
                }
                CrawlMsg::Done {
                    url,
                    status,
                    new_links,
                    response,
                } => {
                    if let Some(&i) = self.crawler_entry_index.get(&url) {
                        if let Some(e) = self.crawler_entries.get_mut(i) {
                            e.status = EntryStatus::Done(status, new_links);
                            e.response = response;
                        }
                    }
                }
                CrawlMsg::Failed { url, reason } => {
                    if let Some(&i) = self.crawler_entry_index.get(&url) {
                        if let Some(e) = self.crawler_entries.get_mut(i) {
                            e.status = EntryStatus::Failed(reason);
                        }
                    } else {
                        let idx = self.crawler_entries.len();
                        self.crawler_entry_index.insert(url.clone(), idx);
                        self.crawler_entries.push(crate::crawler::CrawlerEntry {
                            url,
                            depth: 0,
                            status: EntryStatus::Failed(reason),
                            request: Vec::new(),
                            response: Vec::new(),
                        });
                    }
                }
                CrawlMsg::LoggedIn { cookie, bearer } => {
                    self.crawler_session_cookie = cookie;
                    if let Some(b) = bearer {
                        self.crawler_auth_bearer = b;
                    }
                }
                CrawlMsg::FormSubmit { action_url, request, status, response } => {
                    let idx = self.crawler_entries.len();
                    self.crawler_entry_index.insert(action_url.clone(), idx);
                    self.crawler_entries.push(crate::crawler::CrawlerEntry {
                        url:    action_url,
                        depth:  0,
                        status: crate::crawler::EntryStatus::Done(status, 0),
                        request,
                        response,
                    });
                }
                CrawlMsg::Attack { .. } => {}
                CrawlMsg::Finished => {
                    self.crawler_running = false;
                    self.crawler_rx = None;
                    break;
                }
            }
        }
        changed
    }

    fn poll_claude(&mut self) -> bool {
        if let Some(rx) = &self.claude_rx {
            if let Ok(result) = rx.try_recv() {
                let text = match result {
                    Ok(t) => t,
                    Err(e) => format!("Error: {e}"),
                };
                self.state
                    .lock()
                    .unwrap()
                    .chat_messages
                    .push(crate::app::ChatMessage {
                        from_user: false,
                        text,
                    });
                self.claude_thinking = false;
                self.claude_rx = None;
                return true;
            }
        }
        false
    }

    fn poll_exploit(&mut self) -> bool {
        if let Some(rx) = &self.exploit_rx {
            if let Ok(result) = rx.try_recv() {
                let text = match result {
                    Ok(t) => t,
                    Err(e) => format!("Error: {e}"),
                };
                self.exploit_messages.push(ExploitMessage {
                    from_user: false,
                    text,
                });
                self.exploit_thinking = false;
                self.exploit_rx = None;
                return true;
            }
        }
        false
    }

    fn send_selected_to_repeater(&mut self) {
        let idx = match self.selected {
            Some(i) => i,
            None => return,
        };
        let (method, host, port, tls) = {
            let s = self.state.lock().unwrap();
            match s.requests.get(idx) {
                Some(r) => (r.method.clone(), r.host.clone(), r.port, r.tls),
                None => return,
            }
        };
        let proto = if tls { "HTTPS" } else { "HTTP" };
        let id = self.rep_next_id;
        self.rep_next_id += 1;
        self.repeater.push(RepeaterSession {
            id,
            label: format!("{proto}  {method}  {host}:{port}"),
            host,
            port,
            tls,
            req_buf: self.edit_buf.clone(),
            response: None,
            pending: None,
        });
        self.rep_selected = Some(self.repeater.len() - 1);
        self.tab = ActiveTab::Repeater;
    }
}

// ── Main render loop ──────────────────────────────────────────────────────────

impl eframe::App for RustmanApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        // Adaptive repaint: fast when something is in-flight (spinner), slow when idle.
        let has_inflight = self.crawler_running
            || self.claude_thinking
            || self.exploit_thinking
            || self.openapi_scanning;
        ctx.request_repaint_after(std::time::Duration::from_millis(if has_inflight {
            80
        } else {
            500
        }));

        // Single mutex lock per frame for all cached values.
        {
            let s = self.state.lock().unwrap();
            let light = s.settings.light_mode;
            let pending = s.pending_prompt.is_some();
            if light != self.cached_light_mode {
                self.cached_light_mode = light;
                ctx.set_visuals(if light { light_theme() } else { dark_theme() });
            }
            self.cached_pending_prompt = pending;
        }

        // sync_selection is only needed on the Proxy tab (locks mutex internally).
        if self.tab == ActiveTab::Proxy {
            self.sync_selection();
        }

        let repaint = self.poll_repeater()
            | self.poll_crawler(ctx)
            | self.poll_claude()
            | self.poll_exploit()
            | self.poll_openapi();
        if repaint {
            ctx.request_repaint();
        }

        if self.tab == ActiveTab::Proxy
            && ctx.input(|i| i.key_pressed(egui::Key::R) && i.modifiers.ctrl)
        {
            self.send_selected_to_repeater();
        }

        self.draw_topbar(ctx);
        self.draw_statusbar(ctx);

        match self.tab {
            ActiveTab::Proxy => {
                self.draw_list(ctx);
                self.draw_detail(ctx);
            }
            ActiveTab::Repeater => {
                self.draw_repeater(ctx);
            }
            ActiveTab::Crawler => {
                self.draw_crawler(ctx);
            }
            ActiveTab::Settings => {
                self.draw_settings(ctx);
            }
            ActiveTab::OpenAPI => {
                self.draw_openapi(ctx);
            }
            ActiveTab::Exploit => {
                self.draw_exploit(ctx);
            }
        }

        // Floating Claude window — shown over any tab
        self.draw_claude_window(ctx);
    }
}

impl RustmanApp {
    // ── Top toolbar ───────────────────────────────────────────────────────────
    fn draw_topbar(&mut self, ctx: &egui::Context) {
        egui::TopBottomPanel::top("topbar")
            .exact_height(42.0)
            .show(ctx, |ui| {
                ui.horizontal_centered(|ui| {
                    // Logo — loaded once, displayed at 32×32 px.
                    let tex = self.logo_texture.get_or_insert_with(|| {
                        let bytes = include_bytes!("../logo.png");
                        let img = image::load_from_memory(bytes)
                            .expect("logo.png embedded")
                            .resize(64, 64, image::imageops::FilterType::Lanczos3)
                            .to_rgba8();
                        let (w, h) = img.dimensions();
                        let color_img = egui::ColorImage::from_rgba_unmultiplied(
                            [w as usize, h as usize],
                            img.as_flat_samples().as_slice(),
                        );
                        ctx.load_texture("rustman_logo", color_img, egui::TextureOptions::LINEAR)
                    });
                    ui.add(egui::Image::new(egui::load::SizedTexture::new(
                        tex.id(),
                        egui::vec2(32.0, 32.0),
                    )));
                    ui.add_space(4.0);
                    {
                        let s = self.state.lock().unwrap();
                        let addr = &s.settings.proxy_addr;
                        let port = s.settings.proxy_port;
                        let label = format!("{addr}:{port}");
                        drop(s);
                        ui.label(RichText::new(label).size(12.0).color(Color32::GRAY));
                    }

                    ui.separator();

                    // Tab buttons — active = orange, inactive = gray
                    let tab_color = |active: bool| -> Color32 {
                        if active {
                            Color32::from_rgb(255, 160, 60)
                        } else {
                            Color32::GRAY
                        }
                    };

                    let proxy_btn = egui::SelectableLabel::new(
                        self.tab == ActiveTab::Proxy,
                        RichText::new("Proxy")
                            .size(13.0)
                            .color(tab_color(self.tab == ActiveTab::Proxy)),
                    );
                    if ui.add(proxy_btn).clicked() {
                        self.tab = ActiveTab::Proxy;
                    }

                    let rep_count = self.repeater.len();
                    let rep_label = if rep_count > 0 {
                        format!("Repeater ({})", rep_count)
                    } else {
                        "Repeater".into()
                    };
                    let rep_btn = egui::SelectableLabel::new(
                        self.tab == ActiveTab::Repeater,
                        RichText::new(rep_label)
                            .size(13.0)
                            .color(tab_color(self.tab == ActiveTab::Repeater)),
                    );
                    if ui.add(rep_btn).clicked() {
                        self.tab = ActiveTab::Repeater;
                    }

                    let crawl_label = if self.crawler_running {
                        format!("Crawler ({} found)", self.crawler_entries.len())
                    } else if !self.crawler_entries.is_empty() {
                        format!("Crawler ({})", self.crawler_entries.len())
                    } else {
                        "Crawler".into()
                    };
                    let crawl_btn = egui::SelectableLabel::new(
                        self.tab == ActiveTab::Crawler,
                        RichText::new(crawl_label)
                            .size(13.0)
                            .color(tab_color(self.tab == ActiveTab::Crawler)),
                    );
                    if ui.add(crawl_btn).clicked() {
                        self.tab = ActiveTab::Crawler;
                    }

                    let openapi_label = if !self.openapi_endpoints.is_empty() {
                        format!("OpenAPI ({})", self.openapi_endpoints.len())
                    } else {
                        "OpenAPI".into()
                    };
                    let openapi_btn = egui::SelectableLabel::new(
                        self.tab == ActiveTab::OpenAPI,
                        RichText::new(openapi_label)
                            .size(13.0)
                            .color(tab_color(self.tab == ActiveTab::OpenAPI)),
                    );
                    if ui.add(openapi_btn).clicked() {
                        self.tab = ActiveTab::OpenAPI;
                    }

                    let settings_btn = egui::SelectableLabel::new(
                        self.tab == ActiveTab::Settings,
                        RichText::new("Settings")
                            .size(13.0)
                            .color(tab_color(self.tab == ActiveTab::Settings)),
                    );
                    if ui.add(settings_btn).clicked() {
                        self.tab = ActiveTab::Settings;
                    }

                    let has_pending = self.cached_pending_prompt;
                    let claude_label = if has_pending { "Claude ●" } else { "Claude" };
                    let claude_btn = egui::SelectableLabel::new(
                        self.claude_window_open,
                        RichText::new(claude_label)
                            .size(13.0)
                            .color(tab_color(self.claude_window_open || has_pending)),
                    );
                    if ui.add(claude_btn).clicked() {
                        self.claude_window_open = !self.claude_window_open;
                    }

                    let exploit_btn = egui::SelectableLabel::new(
                        self.tab == ActiveTab::Exploit,
                        RichText::new("⚡ Exploit Dev")
                            .size(13.0)
                            .color(tab_color(self.tab == ActiveTab::Exploit)),
                    );
                    if ui.add(exploit_btn).clicked() {
                        self.tab = ActiveTab::Exploit;
                    }

                    ui.separator();

                    // Proxy-specific info
                    if self.tab == ActiveTab::Proxy {
                        let focused = self.state.lock().unwrap().focused_host.clone();
                        match focused {
                            None => {
                                ui.colored_label(
                                    Color32::DARK_GRAY,
                                    "Navigate to a page — requests from that tab will appear here",
                                );
                            }
                            Some(ref host) => {
                                ui.colored_label(Color32::DARK_GRAY, "Capturing: ");
                                ui.colored_label(Color32::from_rgb(80, 210, 120), host);
                                ui.colored_label(Color32::DARK_GRAY, " + subdomains");
                                if ui.small_button("✕ reset").clicked() {
                                    self.state.lock().unwrap().focused_host = None;
                                }
                            }
                        }

                        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                            if ui
                                .button(
                                    RichText::new("Clear done")
                                        .color(Color32::from_rgb(150, 150, 150)),
                                )
                                .clicked()
                            {
                                self.state.lock().unwrap().clear_done();
                                self.selected = None;
                                self.edit_buf.clear();
                                self.dirty = false;
                            }
                            ui.add_space(8.0);
                            if ui
                                .button(
                                    RichText::new("▶ Forward All")
                                        .color(Color32::from_rgb(100, 220, 100)),
                                )
                                .clicked()
                            {
                                self.state.lock().unwrap().forward_all_pending();
                            }
                        });
                    }
                });
            });
    }

    // ── Status bar ────────────────────────────────────────────────────────────
    fn draw_statusbar(&mut self, ctx: &egui::Context) {
        egui::TopBottomPanel::bottom("statusbar")
            .exact_height(22.0)
            .show(ctx, |ui| {
                let text = match self.tab {
                    ActiveTab::Proxy => {
                        let s = self.state.lock().unwrap();
                        let pending = s.pending_count();
                        let total   = s.requests.len();
                        let focus_info = match &s.focused_host {
                            None => "waiting for navigation  ·  other-tab requests auto-forwarded".into(),
                            Some(h) => format!("capturing {h} and subdomains  ·  other hosts auto-forwarded"),
                        };
                        format!("  {pending} pending  ·  {total} in list  ·  {focus_info}")
                    }
                    ActiveTab::Repeater => {
                        let sending = self.repeater.iter().filter(|s| s.pending.is_some()).count();
                        let n = self.repeater.len();
                        if sending > 0 {
                            format!("  Repeater  ·  {n} session(s)  ·  {sending} sending…")
                        } else {
                            format!("  Repeater  ·  {n} session(s)")
                        }
                    }
                    ActiveTab::Crawler => {
                        let total   = self.crawler_entries.len();
                        let done    = self.crawler_entries.iter().filter(|e| matches!(e.status, crate::crawler::EntryStatus::Done(..))).count();
                        let errors  = self.crawler_entries.iter().filter(|e| matches!(e.status, crate::crawler::EntryStatus::Failed(_))).count();
                        let running = if self.crawler_running { "  ↻ running" } else { "" };
                        format!("  Crawler  ·  {total} visited  ·  {done} OK  ·  {errors} errors{running}")
                    }
                    ActiveTab::Settings => {
                        let s = self.state.lock().unwrap();
                        let addr = s.settings.proxy_addr.clone();
                        let port = s.settings.proxy_port;
                        let n = s.settings.ignore_hosts.len();
                        format!("  Settings  ·  proxy {addr}:{port}  ·  {n} ignore rule(s)")
                    }
                    ActiveTab::OpenAPI => {
                        let n       = self.openapi_endpoints.len();
                        let done  = self.openapi_results.len();
                        let total = self.openapi_jobs_total;
                        let spin  = if self.openapi_scanning { "  ↻" } else { "" };
                        if n == 0 {
                            "  OpenAPI Scanner  ·  aucun spec chargé".into()
                        } else if total > 0 {
                            format!("  OpenAPI  ·  {n} ep  ·  {done}/{total} requêtes{spin}")
                        } else {
                            format!("  OpenAPI  ·  {n} endpoint(s) chargés")
                        }
                    }
                    ActiveTab::Exploit => {
                        let n = self.exploit_messages.len();
                        let thinking = if self.exploit_thinking { "  ·  thinking…" } else { "" };
                        let sel = match self.exploit_selected {
                            Some(i) => format!("  ·  req #{i} selected"),
                            None => "  ·  no request selected".into(),
                        };
                        format!("  Exploit Dev  ·  {n} message(s){sel}{thinking}")
                    }
                };
                ui.label(RichText::new(text).size(11.0).color(Color32::DARK_GRAY));
            });
    }

    // ── Request list (left panel) ─────────────────────────────────────────────
    fn draw_list(&mut self, ctx: &egui::Context) {
        egui::SidePanel::left("req_list")
            .resizable(true)
            .default_width(420.0)
            .min_width(200.0)
            .show(ctx, |ui| {
                let rows: Vec<_> = {
                    let s = self.state.lock().unwrap();
                    s.requests
                        .iter()
                        .enumerate()
                        .map(|(i, r)| (
                            i,
                            r.status.clone(),
                            r.method.clone(),
                            r.host.clone(),
                            r.port,
                            r.url.clone(),
                            r.edited.is_some(),
                        ))
                        .collect()
                };

                let pending = rows.iter().filter(|(_, s, ..)| *s == Status::Pending).count();

                ui.horizontal(|ui| {
                    ui.add_space(4.0);
                    ui.label(
                        RichText::new(format!("{} request(s)  ·  {} pending", rows.len(), pending))
                            .size(11.0)
                            .color(Color32::DARK_GRAY),
                    );
                });
                ui.separator();

                if rows.is_empty() {
                    ui.add_space(20.0);
                    ui.centered_and_justified(|ui| {
                        ui.label(
                            RichText::new("No requests yet.\nBrowse an HTTP site with\nthe proxy set to 127.0.0.1:8080")
                                .size(12.0)
                                .color(Color32::from_rgb(70, 70, 80)),
                        );
                    });
                    return;
                }

                ScrollArea::vertical()
                    .id_salt("list_scroll")
                    .show(ui, |ui| {
                        for (idx, status, method, host, port, url, edited) in &rows {
                            let is_sel = self.selected == Some(*idx);
                            let (sc, sym) = status_indicator(status);
                            let mc = method_color(method);
                            let mark = if *edited { "* " } else { "  " };
                            let host_str = format!("{host}:{port}");
                            let path_str = trunc(url, 34);

                            let row_h   = 24.0;
                            let avail_w = ui.available_width();
                            let (rect, response) = ui.allocate_exact_size(
                                Vec2::new(avail_w, row_h),
                                egui::Sense::click(),
                            );

                            let bg = if is_sel {
                                Color32::from_rgb(65, 42, 12)
                            } else if response.hovered() {
                                Color32::from_rgb(34, 37, 52)
                            } else if idx % 2 == 0 {
                                Color32::from_rgb(21, 21, 25)
                            } else {
                                Color32::from_rgb(25, 25, 30)
                            };
                            ui.painter().rect_filled(rect, 0.0, bg);

                            ui.allocate_new_ui(egui::UiBuilder::new().max_rect(rect), |ui| {
                                ui.horizontal(|ui| {
                                    ui.add_space(8.0);
                                    ui.colored_label(sc, sym);
                                    ui.colored_label(Color32::GOLD, mark);
                                    ui.colored_label(
                                        mc,
                                        RichText::new(format!("{method:<7}")).monospace(),
                                    );
                                    ui.add_space(4.0);
                                    ui.colored_label(Color32::from_rgb(195, 200, 220), &host_str);
                                    ui.add_space(4.0);
                                    ui.colored_label(Color32::from_rgb(130, 135, 155), &path_str);
                                });
                            });

                            if response.clicked() && self.selected != Some(*idx) {
                                self.selected = Some(*idx);
                                let s = self.state.lock().unwrap();
                                if let Some(r) = s.requests.get(*idx) {
                                    self.edit_buf = r.display_text();
                                    self.dirty = false;
                                }
                            }
                        }
                    });
            });
    }

    // ── Detail panel (right / central) ───────────────────────────────────────
    fn draw_detail(&mut self, ctx: &egui::Context) {
        egui::CentralPanel::default().show(ctx, |ui| {
            let idx = match self.selected {
                Some(i) => i,
                None => {
                    ui.centered_and_justified(|ui| {
                        ui.label(
                            RichText::new(
                                "No request selected\n\n\
                                 Point FoxyProxy (or any browser proxy) at  127.0.0.1:8080\n\
                                 HTTP traffic will be intercepted here.\n\
                                 HTTPS tunnels pass through automatically — no certificate needed.",
                            )
                            .size(14.0)
                            .color(Color32::from_rgb(80, 80, 90)),
                        );
                    });
                    return;
                }
            };

            let (id, status, method, host, port, resp_text) = {
                let s = self.state.lock().unwrap();
                match s.requests.get(idx) {
                    Some(r) => (
                        r.id,
                        r.status.clone(),
                        r.method.clone(),
                        r.host.clone(),
                        r.port,
                        r.response_text(),
                    ),
                    None => return,
                }
            };

            let is_pending = status == Status::Pending;

            // ── Header row ────────────────────────────────────────────────
            ui.horizontal(|ui| {
                let (sc, sl) = status_indicator(&status);
                ui.label(RichText::new(sl).color(sc).size(14.0).strong());
                ui.add_space(6.0);
                ui.label(
                    RichText::new(format!("{method}  {host}:{port}"))
                        .size(14.0)
                        .strong()
                        .color(Color32::WHITE),
                );
                if self.dirty {
                    ui.colored_label(Color32::GOLD, "  ✎ edited");
                }
            });
            ui.add(egui::Separator::default().spacing(4.0));

            // ── Action buttons ────────────────────────────────────────────
            if is_pending {
                ui.horizontal(|ui| {
                    let fwd_btn = egui::Button::new(
                        RichText::new("  ▶  Forward  ")
                            .size(13.0)
                            .color(Color32::BLACK),
                    )
                    .fill(Color32::from_rgb(60, 180, 80));

                    if ui.add(fwd_btn).clicked() {
                        let bytes = self.edit_buf.as_bytes().to_vec();
                        self.state.lock().unwrap().forward_at(idx, bytes);
                        self.dirty = false;
                    }

                    ui.add_space(8.0);

                    let drop_btn = egui::Button::new(
                        RichText::new("  ✗  Drop  ")
                            .size(13.0)
                            .color(Color32::WHITE),
                    )
                    .fill(Color32::from_rgb(180, 50, 50));

                    if ui.add(drop_btn).clicked() {
                        self.state.lock().unwrap().drop_at(idx);
                        self.dirty = false;
                    }

                    ui.add_space(16.0);
                    ui.colored_label(Color32::DARK_GRAY, "Edit request below then Forward");
                });
                ui.add(egui::Separator::default().spacing(4.0));
            }

            // ── Send to Repeater button ───────────────────────────────────
            ui.horizontal(|ui| {
                let rep_btn = egui::Button::new(
                    RichText::new("  → Repeater  ")
                        .size(12.0)
                        .color(Color32::from_rgb(180, 220, 255)),
                )
                .fill(Color32::from_rgb(35, 55, 90));

                if ui.add(rep_btn).clicked() {
                    self.send_selected_to_repeater();
                }

                ui.colored_label(
                    Color32::DARK_GRAY,
                    RichText::new("Ctrl+R").size(10.0).monospace(),
                );
            });

            if is_pending {
                // separator already drawn above; skip extra space
            } else {
                ui.add(egui::Separator::default().spacing(4.0));
            }

            // ── Request / response vertical split ─────────────────────────
            let available_h = ui.available_height();
            let has_response = !resp_text.is_empty();
            let req_h = if has_response {
                available_h * 0.52
            } else {
                available_h
            };

            let req_frame = egui::Frame::none()
                .fill(Color32::from_rgb(20, 22, 28))
                .rounding(4.0)
                .inner_margin(egui::Margin::symmetric(8.0, 6.0));

            req_frame.show(ui, |ui| {
                ui.set_min_height(req_h - 16.0);
                ui.set_max_height(req_h - 16.0);
                ui.horizontal(|ui| {
                    ui.colored_label(Color32::DARK_GRAY, "REQUEST");
                    if is_pending {
                        ui.colored_label(
                            Color32::from_rgb(80, 80, 100),
                            "  (editable — modify before forwarding)",
                        );
                    }
                });
                ui.add_space(4.0);
                ScrollArea::vertical()
                    .id_salt("req_text_scroll")
                    .max_height(req_h - 48.0)
                    .show(ui, |ui| {
                        let te = TextEdit::multiline(&mut self.edit_buf)
                            .font(egui::TextStyle::Monospace)
                            .desired_width(f32::INFINITY)
                            .interactive(is_pending)
                            .frame(false)
                            .text_color(Color32::from_rgb(210, 210, 220));
                        let resp = ui.add(te);
                        if resp.changed() {
                            self.dirty = true;
                            self.state
                                .lock()
                                .unwrap()
                                .set_edited(id, self.edit_buf.as_bytes().to_vec());
                        }
                    });
            });

            if has_response {
                ui.add_space(4.0);
                let resp_frame = egui::Frame::none()
                    .fill(Color32::from_rgb(18, 22, 26))
                    .rounding(4.0)
                    .inner_margin(egui::Margin::symmetric(8.0, 6.0));

                resp_frame.show(ui, |ui| {
                    ui.colored_label(Color32::DARK_GRAY, "RESPONSE");
                    ui.add_space(4.0);
                    ScrollArea::vertical()
                        .id_salt("resp_text_scroll")
                        .max_height(available_h * 0.42)
                        .show(ui, |ui| {
                            let mut resp_clone = resp_text.clone();
                            let te = TextEdit::multiline(&mut resp_clone)
                                .font(egui::TextStyle::Monospace)
                                .desired_width(f32::INFINITY)
                                .interactive(false)
                                .frame(false)
                                .text_color(Color32::from_rgb(180, 210, 180));
                            ui.add(te);
                        });
                });
            }
        });
    }

    // ── Repeater tab ─────────────────────────────────────────────────────────
    fn draw_repeater(&mut self, ctx: &egui::Context) {
        if self.repeater.is_empty() {
            egui::CentralPanel::default().show(ctx, |ui| {
                ui.centered_and_justified(|ui| {
                    ui.label(
                        RichText::new(
                            "No repeater sessions yet.\n\n\
                             Select a request in the Proxy tab\n\
                             and click  → Repeater  to send it here.",
                        )
                        .size(14.0)
                        .color(Color32::from_rgb(80, 80, 90)),
                    );
                });
            });
            return;
        }

        // ── Session list (left) ───────────────────────────────────────────
        egui::SidePanel::left("rep_session_list")
            .resizable(true)
            .default_width(260.0)
            .min_width(160.0)
            .show(ctx, |ui| {
                ui.horizontal(|ui| {
                    ui.add_space(4.0);
                    ui.label(
                        RichText::new(format!("{} session(s)", self.repeater.len()))
                            .size(11.0)
                            .color(Color32::DARK_GRAY),
                    );
                });
                ui.separator();

                ScrollArea::vertical()
                    .id_salt("rep_list_scroll")
                    .show(ui, |ui| {
                        for i in 0..self.repeater.len() {
                            let is_sel = self.rep_selected == Some(i);
                            let is_sending = self.repeater[i].pending.is_some();
                            let label = self.repeater[i].label.clone();

                            let row_h = 28.0;
                            let avail_w = ui.available_width();
                            let (rect, response) = ui.allocate_exact_size(
                                Vec2::new(avail_w, row_h),
                                egui::Sense::click(),
                            );

                            let bg = if is_sel {
                                Color32::from_rgb(65, 42, 12)
                            } else if response.hovered() {
                                Color32::from_rgb(34, 37, 52)
                            } else if i % 2 == 0 {
                                Color32::from_rgb(21, 21, 25)
                            } else {
                                Color32::from_rgb(25, 25, 30)
                            };
                            ui.painter().rect_filled(rect, 0.0, bg);

                            ui.allocate_new_ui(egui::UiBuilder::new().max_rect(rect), |ui| {
                                ui.horizontal(|ui| {
                                    ui.add_space(8.0);
                                    if is_sending {
                                        ui.colored_label(Color32::from_rgb(255, 160, 60), "↻");
                                    } else if self.repeater[i].response.is_some() {
                                        ui.colored_label(Color32::from_rgb(80, 200, 100), "✓");
                                    } else {
                                        ui.colored_label(Color32::DARK_GRAY, "·");
                                    }
                                    ui.add_space(4.0);
                                    ui.colored_label(
                                        Color32::from_rgb(195, 200, 220),
                                        RichText::new(trunc(&label, 28)).monospace().size(11.0),
                                    );
                                });
                            });

                            if response.clicked() {
                                self.rep_selected = Some(i);
                            }
                        }
                    });
            });

        // ── Session detail (central) ──────────────────────────────────────
        egui::CentralPanel::default().show(ctx, |ui| {
            let sel = match self.rep_selected {
                Some(i) if i < self.repeater.len() => i,
                _ => {
                    ui.centered_and_justified(|ui| {
                        ui.label(
                            RichText::new("Select a session on the left.")
                                .color(Color32::DARK_GRAY),
                        );
                    });
                    return;
                }
            };

            let (label, host, port, tls, is_sending) = {
                let s = &self.repeater[sel];
                (
                    s.label.clone(),
                    s.host.clone(),
                    s.port,
                    s.tls,
                    s.pending.is_some(),
                )
            };

            // ── Header ────────────────────────────────────────────────────
            ui.horizontal(|ui| {
                let proto_color = if tls {
                    Color32::from_rgb(80, 200, 100)
                } else {
                    Color32::from_rgb(255, 180, 80)
                };
                let proto = if tls { "HTTPS" } else { "HTTP" };
                ui.colored_label(proto_color, proto);
                ui.add_space(6.0);
                ui.label(
                    RichText::new(format!("{host}:{port}"))
                        .size(14.0)
                        .strong()
                        .color(Color32::WHITE),
                );
                ui.add_space(12.0);

                let send_label = if is_sending {
                    "  ↻  Sending…  "
                } else {
                    "  ▶  Send  "
                };
                let send_btn =
                    egui::Button::new(RichText::new(send_label).size(13.0).color(Color32::BLACK))
                        .fill(if is_sending {
                            Color32::from_rgb(150, 80, 15)
                        } else {
                            Color32::from_rgb(60, 180, 80)
                        });

                if ui.add_enabled(!is_sending, send_btn).clicked() {
                    let (tx, rx) = std::sync::mpsc::channel::<Vec<u8>>();
                    let req_bytes = self.repeater[sel].req_buf.as_bytes().to_vec();
                    let host_clone = host.clone();
                    self.rt.spawn(async move {
                        let resp =
                            crate::proxy::repeater_send(&host_clone, port, tls, req_bytes).await;
                        let _ = tx.send(resp);
                    });
                    self.repeater[sel].pending = Some(rx);
                    self.repeater[sel].response = Some("Sending…".into());
                }

                ui.add_space(8.0);
                ui.label(RichText::new(&label).size(11.0).color(Color32::DARK_GRAY));
            });
            ui.add(egui::Separator::default().spacing(4.0));

            let available_h = ui.available_height();
            let has_response = self.repeater[sel]
                .response
                .as_deref()
                .is_some_and(|r| !r.is_empty());
            let req_h = if has_response {
                available_h * 0.50
            } else {
                available_h
            };

            // ── Request editor ────────────────────────────────────────────
            let req_frame = egui::Frame::none()
                .fill(Color32::from_rgb(20, 22, 28))
                .rounding(4.0)
                .inner_margin(egui::Margin::symmetric(8.0, 6.0));

            req_frame.show(ui, |ui| {
                ui.set_min_height(req_h - 16.0);
                ui.set_max_height(req_h - 16.0);
                ui.horizontal(|ui| {
                    ui.colored_label(Color32::DARK_GRAY, "REQUEST");
                    ui.colored_label(Color32::from_rgb(80, 80, 100), "  (edit and Send)");
                });
                ui.add_space(4.0);
                ScrollArea::vertical()
                    .id_salt(format!("rep_req_scroll_{sel}"))
                    .max_height(req_h - 48.0)
                    .show(ui, |ui| {
                        let req_buf = &mut self.repeater[sel].req_buf;
                        let te = TextEdit::multiline(req_buf)
                            .font(egui::TextStyle::Monospace)
                            .desired_width(f32::INFINITY)
                            .frame(false)
                            .text_color(Color32::from_rgb(210, 210, 220));
                        ui.add(te);
                    });
            });

            // ── Response viewer ───────────────────────────────────────────
            if has_response {
                ui.add_space(4.0);
                let resp_text = self.repeater[sel].response.clone().unwrap_or_default();
                let sending = is_sending;
                let resp_frame = egui::Frame::none()
                    .fill(Color32::from_rgb(18, 22, 26))
                    .rounding(4.0)
                    .inner_margin(egui::Margin::symmetric(8.0, 6.0));

                resp_frame.show(ui, |ui| {
                    ui.horizontal(|ui| {
                        ui.colored_label(Color32::DARK_GRAY, "RESPONSE");
                        if sending {
                            ui.colored_label(Color32::from_rgb(255, 160, 60), "  ↻");
                        }
                    });
                    ui.add_space(4.0);
                    ScrollArea::vertical()
                        .id_salt(format!("rep_resp_scroll_{sel}"))
                        .max_height(available_h * 0.44)
                        .show(ui, |ui| {
                            let mut resp_clone = resp_text;
                            let te = TextEdit::multiline(&mut resp_clone)
                                .font(egui::TextStyle::Monospace)
                                .desired_width(f32::INFINITY)
                                .interactive(false)
                                .frame(false)
                                .text_color(Color32::from_rgb(180, 210, 180));
                            ui.add(te);
                        });
                });
            }
        });
    }

    // ── Crawler tab ───────────────────────────────────────────────────────────
    fn draw_crawler(&mut self, ctx: &egui::Context) {
        use crate::crawler::EntryStatus;
        use std::sync::{
            atomic::{AtomicBool, Ordering},
            Arc,
        };

        // ── Left panel: toolbar + list ────────────────────────────────────
        egui::SidePanel::left("crawler_list_panel")
            .resizable(true)
            .default_width(420.0)
            .min_width(220.0)
            .show(ctx, |ui| {
                // Toolbar
                ui.add_space(4.0);
                ui.horizontal(|ui| {
                    ui.label(RichText::new("URL:").color(Color32::DARK_GRAY).size(12.0));
                    ui.add(
                        TextEdit::singleline(&mut self.crawler_url)
                            .hint_text("https://example.com/")
                            .desired_width(f32::INFINITY)
                            .font(egui::TextStyle::Monospace),
                    );
                });
                ui.add_space(4.0);
                ui.horizontal(|ui| {
                    ui.label(RichText::new("Depth:").color(Color32::DARK_GRAY).size(12.0));
                    ui.add(
                        egui::DragValue::new(&mut self.crawler_max_depth)
                            .range(1..=10).speed(1.0),
                    );

                    ui.add_space(8.0);

                    if self.crawler_running {
                        let stop_btn = egui::Button::new(
                            RichText::new("  ■  Stop  ").size(12.0).color(Color32::WHITE),
                        ).fill(Color32::from_rgb(180, 50, 50));
                        if ui.add(stop_btn).clicked() {
                            if let Some(flag) = &self.crawler_stop {
                                flag.store(true, Ordering::Relaxed);
                            }
                        }
                    } else {
                        let start_btn = egui::Button::new(
                            RichText::new("  ▶  Start  ").size(12.0).color(Color32::BLACK),
                        ).fill(Color32::from_rgb(60, 180, 80));
                        if ui.add(start_btn).clicked() && !self.crawler_url.trim().is_empty() {
                            self.crawler_entries.clear();
                            self.crawler_entry_index.clear();
                            self.crawler_selected = None;
                            self.crawler_session_cookie.clear();
                            self.crawler_auth_bearer.clear();
                            self.crawler_running = true;

                            let stop = Arc::new(AtomicBool::new(false));
                            self.crawler_stop = Some(stop.clone());

                            let (tx, rx) = std::sync::mpsc::sync_channel(512);
                            self.crawler_rx = Some(rx);

                            let url   = self.crawler_url.trim().to_string();
                            let depth = self.crawler_max_depth;
                            let config = crate::crawler::CrawlerConfig {
                                auth: if !self.crawler_auth_user.is_empty() {
                                    Some(crate::crawler::CrawlerAuth {
                                        username: self.crawler_auth_user.clone(),
                                        password: self.crawler_auth_pass.clone(),
                                        username_field: self.crawler_auth_user_field.clone(),
                                        password_field: self.crawler_auth_pass_field.clone(),
                                    })
                                } else {
                                    None
                                },
                            };
                            self.rt.spawn(async move {
                                crate::crawler::run(url, depth, stop, tx, config).await;
                            });
                        }

                        if !self.crawler_entries.is_empty() {
                            ui.add_space(4.0);
                            if ui.button(RichText::new("Clear").color(Color32::from_rgb(150, 150, 150))).clicked() {
                                self.crawler_entries.clear();
                                self.crawler_entry_index.clear();
                                self.crawler_selected = None;
                                self.crawler_session_cookie.clear();
                                self.crawler_auth_bearer.clear();
                            }
                        }
                    }
                });

                // Stats
                if !self.crawler_entries.is_empty() {
                    let total  = self.crawler_entries.len();
                    let done   = self.crawler_entries.iter().filter(|e| matches!(e.status, EntryStatus::Done(..))).count();
                    let errors = self.crawler_entries.iter().filter(|e| matches!(e.status, EntryStatus::Failed(_))).count();
                    let active = total - done - errors;
                    ui.add_space(2.0);
                    ui.horizontal(|ui| {
                        ui.add_space(2.0);
                        ui.colored_label(Color32::from_rgb(80, 200, 100),  format!("✓ {done}"));
                        ui.add_space(6.0);
                        ui.colored_label(Color32::from_rgb(220, 70, 70),   format!("✗ {errors}"));
                        if active > 0 {
                            ui.add_space(6.0);
                            ui.colored_label(Color32::from_rgb(255, 160, 60), format!("↻ {active}"));
                        }
                    });
                }

                // ── Auth credentials ──────────────────────────────────────
                ui.horizontal(|ui| {
                    let auth_lbl = if self.crawler_show_auth { "▼ Auth" } else { "▶ Auth" };
                    if ui.small_button(auth_lbl).clicked() {
                        self.crawler_show_auth = !self.crawler_show_auth;
                    }
                    let has_session = !self.crawler_session_cookie.is_empty() || !self.crawler_auth_bearer.is_empty();
                    if has_session {
                        let label = if !self.crawler_auth_bearer.is_empty() {
                            "● JWT"
                        } else {
                            "● cookie"
                        };
                        ui.colored_label(Color32::from_rgb(80, 200, 100), label);
                    }
                });
                if self.crawler_show_auth {
                    egui::Grid::new("crawler_auth_grid")
                        .num_columns(2)
                        .spacing([4.0, 2.0])
                        .show(ui, |ui| {
                            ui.label(RichText::new("User:").size(11.0));
                            ui.add(
                                TextEdit::singleline(&mut self.crawler_auth_user)
                                    .desired_width(130.0)
                                    .hint_text("username / email"),
                            );
                            ui.end_row();
                            ui.label(RichText::new("Pass:").size(11.0));
                            ui.add(
                                TextEdit::singleline(&mut self.crawler_auth_pass)
                                    .password(true)
                                    .desired_width(130.0),
                            );
                            ui.end_row();
                            ui.label(RichText::new("User field:").size(11.0));
                            ui.add(
                                TextEdit::singleline(&mut self.crawler_auth_user_field)
                                    .hint_text("auto-detect")
                                    .desired_width(130.0),
                            );
                            ui.end_row();
                            ui.label(RichText::new("Pass field:").size(11.0));
                            ui.add(
                                TextEdit::singleline(&mut self.crawler_auth_pass_field)
                                    .hint_text("auto-detect")
                                    .desired_width(130.0),
                            );
                            ui.end_row();
                        });
                    if !self.crawler_auth_bearer.is_empty() {
                        let preview = if self.crawler_auth_bearer.len() > 48 {
                            format!("{}…", &self.crawler_auth_bearer[..48])
                        } else {
                            self.crawler_auth_bearer.clone()
                        };
                        ui.label(
                            RichText::new(format!("Bearer: {preview}"))
                                .size(10.0)
                                .monospace()
                                .color(Color32::from_rgb(100, 200, 120)),
                        );
                    } else if !self.crawler_session_cookie.is_empty() {
                        let preview = if self.crawler_session_cookie.len() > 50 {
                            format!("{}…", &self.crawler_session_cookie[..50])
                        } else {
                            self.crawler_session_cookie.clone()
                        };
                        ui.label(
                            RichText::new(format!("Cookie: {preview}"))
                                .size(10.0)
                                .monospace()
                                .color(Color32::from_rgb(100, 200, 120)),
                        );
                    }
                }

                ui.separator();

                if self.crawler_entries.is_empty() {
                    ui.add_space(20.0);
                    ui.centered_and_justified(|ui| {
                        ui.label(
                            RichText::new(
                                "Enter a URL and click Start.\n\nThe crawler follows\ninternal links recursively.",
                            )
                            .size(12.0)
                            .color(Color32::from_rgb(70, 70, 80)),
                        );
                    });
                    return;
                }

                // Column header
                ui.horizontal(|ui| {
                    ui.add_space(8.0);
                    ui.colored_label(Color32::DARK_GRAY, RichText::new(format!("{:<5}", "CODE")).monospace().size(10.0));
                    ui.add_space(2.0);
                    ui.colored_label(Color32::DARK_GRAY, RichText::new("D").monospace().size(10.0));
                    ui.add_space(6.0);
                    ui.colored_label(Color32::DARK_GRAY, RichText::new("URL").size(10.0));
                });
                ui.add(egui::Separator::default().spacing(2.0));

                // Entries
                let selected = self.crawler_selected;
                ScrollArea::vertical()
                    .id_salt("crawler_list_scroll")
                    .auto_shrink([false, false])
                    .show(ui, |ui| {
                        for i in 0..self.crawler_entries.len() {
                            let entry   = &self.crawler_entries[i];
                            let is_sel  = selected == Some(i);
                            let row_h   = 22.0;
                            let avail_w = ui.available_width();
                            let (rect, resp) = ui.allocate_exact_size(
                                Vec2::new(avail_w, row_h),
                                egui::Sense::click(),
                            );

                            let bg = if is_sel {
                                Color32::from_rgb(65, 42, 12)
                            } else if resp.hovered() {
                                Color32::from_rgb(34, 37, 52)
                            } else if i % 2 == 0 {
                                Color32::from_rgb(21, 21, 25)
                            } else {
                                Color32::from_rgb(25, 25, 30)
                            };
                            ui.painter().rect_filled(rect, 0.0, bg);

                            ui.allocate_new_ui(egui::UiBuilder::new().max_rect(rect), |ui| {
                                ui.horizontal(|ui| {
                                    ui.add_space(8.0);
                                    let (color, code_str) = entry_color_code(entry);
                                    ui.colored_label(color, RichText::new(format!("{:<5}", code_str)).monospace().size(11.0));
                                    ui.add_space(2.0);
                                    ui.colored_label(
                                        Color32::from_rgb(100, 100, 120),
                                        RichText::new(entry.depth.to_string()).monospace().size(11.0),
                                    );
                                    ui.add_space(6.0);
                                    let url_color = match &entry.status {
                                        EntryStatus::Fetching     => Color32::from_rgb(255, 160, 60),
                                        EntryStatus::Done(200, _) => Color32::from_rgb(200, 205, 220),
                                        EntryStatus::Done(..)     => Color32::from_rgb(200, 160, 100),
                                        EntryStatus::Failed(_)    => Color32::from_rgb(180, 80, 80),
                                    };
                                    ui.colored_label(url_color, RichText::new(&entry.url).monospace().size(11.0));
                                    if let EntryStatus::Done(_, n) = entry.status {
                                        if n > 0 {
                                            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                                                ui.add_space(8.0);
                                                ui.colored_label(Color32::from_rgb(80, 140, 80), RichText::new(format!("+{n}")).size(10.0));
                                            });
                                        }
                                    }
                                });
                            });

                            if resp.clicked() {
                                self.crawler_selected = Some(i);
                            }
                        }
                    });
            });

        // ── Central panel: detail ─────────────────────────────────────────
        egui::CentralPanel::default().show(ctx, |ui| {
            let idx = match self.crawler_selected {
                Some(i) if i < self.crawler_entries.len() => i,
                _ => {
                    ui.centered_and_justified(|ui| {
                        ui.label(
                            RichText::new(
                                "Select a URL on the left to inspect the request and response.",
                            )
                            .size(13.0)
                            .color(Color32::from_rgb(70, 70, 80)),
                        );
                    });
                    return;
                }
            };

            let entry = &self.crawler_entries[idx];
            let (color, code_str) = entry_color_code(entry);

            // Header
            ui.horizontal(|ui| {
                ui.colored_label(color, RichText::new(&code_str).size(14.0).strong());
                ui.add_space(8.0);
                ui.label(
                    RichText::new(&entry.url)
                        .size(13.0)
                        .strong()
                        .color(Color32::WHITE),
                );
                ui.add_space(8.0);
                ui.colored_label(Color32::DARK_GRAY, format!("depth {}", entry.depth));

                // → Repeater button
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    let rep_btn = egui::Button::new(
                        RichText::new("  → Repeater  ")
                            .size(12.0)
                            .color(Color32::from_rgb(180, 220, 255)),
                    )
                    .fill(Color32::from_rgb(35, 55, 90));

                    if ui.add(rep_btn).clicked() {
                        if let Some(parts) = crate::crawler::parse_url(&entry.url) {
                            let req_text = String::from_utf8_lossy(&entry.request).into_owned();
                            let proto = if parts.tls { "HTTPS" } else { "HTTP" };
                            let id = self.rep_next_id;
                            self.rep_next_id += 1;
                            self.repeater.push(RepeaterSession {
                                id,
                                label: format!("{proto}  GET  {}:{}", parts.host, parts.port),
                                host: parts.host,
                                port: parts.port,
                                tls: parts.tls,
                                req_buf: req_text,
                                response: None,
                                pending: None,
                            });
                            self.rep_selected = Some(self.repeater.len() - 1);
                            self.tab = ActiveTab::Repeater;
                        }
                    }
                });
            });
            ui.add(egui::Separator::default().spacing(4.0));

            let available_h = ui.available_height();
            let has_resp = !entry.response.is_empty();

            let (req_h, resp_h) = if has_resp {
                (available_h * 0.40, available_h * 0.56)
            } else {
                (available_h, 0.0)
            };

            // Request
            let req_text = String::from_utf8_lossy(&entry.request).into_owned();
            let req_frame = egui::Frame::none()
                .fill(Color32::from_rgb(20, 22, 28))
                .rounding(4.0)
                .inner_margin(egui::Margin::symmetric(8.0, 6.0));

            req_frame.show(ui, |ui| {
                ui.set_min_height(req_h - 16.0);
                ui.set_max_height(req_h - 16.0);
                ui.colored_label(Color32::DARK_GRAY, "REQUEST");
                ui.add_space(4.0);
                ScrollArea::vertical()
                    .id_salt(format!("crawl_req_{idx}"))
                    .max_height(req_h - 46.0)
                    .show(ui, |ui| {
                        let mut t = req_text;
                        ui.add(
                            TextEdit::multiline(&mut t)
                                .font(egui::TextStyle::Monospace)
                                .desired_width(f32::INFINITY)
                                .interactive(false)
                                .frame(false)
                                .text_color(Color32::from_rgb(210, 210, 220)),
                        );
                    });
            });

            // Response
            if has_resp {
                ui.add_space(4.0);
                let resp_text = String::from_utf8_lossy(&entry.response).into_owned();
                let resp_frame = egui::Frame::none()
                    .fill(Color32::from_rgb(18, 22, 26))
                    .rounding(4.0)
                    .inner_margin(egui::Margin::symmetric(8.0, 6.0));

                resp_frame.show(ui, |ui| {
                    ui.colored_label(Color32::DARK_GRAY, "RESPONSE");
                    ui.add_space(4.0);
                    ScrollArea::vertical()
                        .id_salt(format!("crawl_resp_{idx}"))
                        .max_height(resp_h - 36.0)
                        .show(ui, |ui| {
                            let mut t = resp_text;
                            ui.add(
                                TextEdit::multiline(&mut t)
                                    .font(egui::TextStyle::Monospace)
                                    .desired_width(f32::INFINITY)
                                    .interactive(false)
                                    .frame(false)
                                    .text_color(Color32::from_rgb(180, 210, 180)),
                            );
                        });
                });
            }
        });
    }

    // ── Claude floating window ────────────────────────────────────────────────
    fn draw_claude_window(&mut self, ctx: &egui::Context) {
        if !self.claude_window_open {
            return;
        }
        let mut open = self.claude_window_open;
        egui::Window::new("Claude")
            .open(&mut open)
            .resizable(true)
            .default_size([520.0, 620.0])
            .min_size([360.0, 300.0])
            .title_bar(true)
            .show(ctx, |ui| {
            ui.vertical(|ui| {
                // ── Header ────────────────────────────────────────────────
                ui.add_space(8.0);
                ui.horizontal(|ui| {
                    ui.add_space(8.0);
                    ui.label(
                        RichText::new("Claude")
                            .size(15.0)
                            .strong()
                            .color(Color32::from_rgb(255, 150, 50)),
                    );
                    ui.add_space(12.0);

                    let is_general = self.claude_mode == crate::claude_client::AssistantMode::General;
                    let is_pentest = self.claude_mode == crate::claude_client::AssistantMode::Pentest;

                    if ui.add(egui::SelectableLabel::new(is_general,
                        RichText::new("General").size(12.0)
                    )).clicked() {
                        self.claude_mode = crate::claude_client::AssistantMode::General;
                    }
                    if ui.add(egui::SelectableLabel::new(is_pentest,
                        RichText::new("Pentest").size(12.0)
                            .color(if is_pentest {
                                Color32::from_rgb(255, 140, 60)
                            } else {
                                Color32::GRAY
                            })
                    )).clicked() {
                        self.claude_mode = crate::claude_client::AssistantMode::Pentest;
                    }

                    ui.add_space(8.0);
                    ui.colored_label(Color32::DARK_GRAY, if is_pentest {
                        "Senior Web Pentester — structured pentest reports"
                    } else {
                        "General security assistant"
                    });
                });
                ui.add_space(4.0);
                ui.add(egui::Separator::default().spacing(2.0));

                // ── Request context picker ────────────────────────────────
                {
                    let rows: Vec<(usize, usize, String, String, u16, String)> = {
                        let s = self.state.lock().unwrap();
                        s.requests.iter().enumerate().map(|(i, r)| {
                            (i, r.id, r.method.clone(), r.host.clone(), r.port, r.url.clone())
                        }).collect()
                    };

                    let sel_label = self.claude_selected_req.and_then(|idx| {
                        rows.iter().find(|(i, ..)| *i == idx)
                            .map(|(_, id, method, host, port, url)| {
                                format!("#{id} {method} {host}:{port}{}", trunc(url, 28))
                            })
                    });

                    ui.horizontal(|ui| {
                        ui.colored_label(Color32::DARK_GRAY, RichText::new("Context:").size(11.0));
                        ui.add_space(4.0);

                        let picker_label = sel_label.as_deref()
                            .unwrap_or("no request attached");
                        let picker_color = if sel_label.is_some() {
                            Color32::from_rgb(255, 160, 60)
                        } else {
                            Color32::DARK_GRAY
                        };

                        let btn = egui::Button::new(
                            RichText::new(picker_label).size(11.0).monospace().color(picker_color)
                        ).frame(true);
                        if ui.add(btn).clicked() {
                            self.claude_req_picker_open = !self.claude_req_picker_open;
                        }

                        if self.claude_selected_req.is_some() {
                            if ui.small_button("×").on_hover_text("Detach request").clicked() {
                                self.claude_selected_req = None;
                                self.claude_req_picker_open = false;
                            }
                        }
                    });

                    if self.claude_req_picker_open && !rows.is_empty() {
                        egui::Frame::none()
                            .fill(Color32::from_rgb(18, 20, 26))
                            .rounding(4.0)
                            .inner_margin(egui::Margin::symmetric(4.0, 4.0))
                            .show(ui, |ui| {
                                ScrollArea::vertical()
                                    .id_salt("claude_req_picker_scroll")
                                    .max_height(130.0)
                                    .show(ui, |ui| {
                                        for (idx, id, method, host, port, url) in &rows {
                                            let is_sel = self.claude_selected_req == Some(*idx);
                                            let mc = method_color(method);
                                            let row_h = 20.0;
                                            let avail_w = ui.available_width();
                                            let (rect, resp) = ui.allocate_exact_size(
                                                Vec2::new(avail_w, row_h), egui::Sense::click(),
                                            );
                                            let bg = if is_sel {
                                                Color32::from_rgb(65, 42, 12)
                                            } else if resp.hovered() {
                                                Color32::from_rgb(38, 30, 18)
                                            } else {
                                                Color32::TRANSPARENT
                                            };
                                            ui.painter().rect_filled(rect, 0.0, bg);
                                            ui.allocate_new_ui(egui::UiBuilder::new().max_rect(rect), |ui| {
                                                ui.horizontal(|ui| {
                                                    ui.add_space(4.0);
                                                    ui.colored_label(Color32::DARK_GRAY,
                                                        RichText::new(format!("#{id:<4}")).monospace().size(10.0));
                                                    ui.colored_label(mc,
                                                        RichText::new(format!("{method:<7}")).monospace().size(10.0));
                                                    ui.colored_label(Color32::from_rgb(180, 185, 210),
                                                        RichText::new(format!("{host}:{port}")).size(10.0));
                                                    ui.add_space(4.0);
                                                    ui.colored_label(Color32::from_rgb(110, 115, 135),
                                                        RichText::new(trunc(url, 30)).size(10.0));
                                                });
                                            });
                                            if resp.clicked() {
                                                self.claude_selected_req = Some(*idx);
                                                self.claude_req_picker_open = false;
                                            }
                                        }
                                    });
                            });
                    }
                }
                ui.add(egui::Separator::default().spacing(2.0));

                // ── Message history ───────────────────────────────────────
                let messages: Vec<crate::app::ChatMessage> = {
                    self.state.lock().unwrap().chat_messages.clone()
                };
                let waiting = self.claude_thinking;

                let history_h = ui.available_height() - 72.0;
                ScrollArea::vertical()
                    .id_salt("claude_history")
                    .max_height(history_h)
                    .stick_to_bottom(true)
                    .show(ui, |ui| {
                        ui.add_space(4.0);
                        for msg in &messages {
                            ui.add_space(6.0);
                            if msg.from_user {
                                // User bubble — right aligned
                                ui.with_layout(egui::Layout::right_to_left(egui::Align::TOP), |ui| {
                                    ui.add_space(8.0);
                                    egui::Frame::none()
                                        .fill(Color32::from_rgb(60, 35, 12))
                                        .rounding(8.0)
                                        .inner_margin(egui::Margin::symmetric(10.0, 6.0))
                                        .show(ui, |ui| {
                                            ui.set_max_width(ui.available_width() * 0.75);
                                            ui.label(
                                                RichText::new(&msg.text)
                                                    .size(13.0)
                                                    .color(Color32::from_rgb(210, 225, 255)),
                                            );
                                        });
                                });
                            } else {
                                // Claude bubble — left aligned
                                ui.with_layout(egui::Layout::left_to_right(egui::Align::TOP), |ui| {
                                    ui.add_space(8.0);
                                    egui::Frame::none()
                                        .fill(Color32::from_rgb(28, 32, 42))
                                        .rounding(8.0)
                                        .inner_margin(egui::Margin::symmetric(10.0, 6.0))
                                        .show(ui, |ui| {
                                            ui.set_max_width(ui.available_width() * 0.85);
                                            ui.label(
                                                RichText::new(&msg.text)
                                                    .size(13.0)
                                                    .color(Color32::from_rgb(200, 210, 200)),
                                            );
                                        });
                                });
                            }
                        }

                        if waiting {
                            ui.add_space(6.0);
                            ui.with_layout(egui::Layout::left_to_right(egui::Align::TOP), |ui| {
                                ui.add_space(8.0);
                                ui.colored_label(
                                    Color32::from_rgb(255, 160, 60),
                                    RichText::new("↻  Waiting for Claude Code…").size(12.0).italics(),
                                );
                            });
                        }

                        if messages.is_empty() && !waiting {
                            ui.add_space(40.0);
                            ui.centered_and_justified(|ui| {
                                ui.label(
                                    RichText::new(
                                        "Type a message below.\n\n\
                                         Claude Code will read it via get_user_prompt()\n\
                                         and reply here via reply_to_user().",
                                    )
                                    .size(13.0)
                                    .color(Color32::from_rgb(60, 65, 80)),
                                );
                            });
                        }
                    });

                // ── Input bar ─────────────────────────────────────────────
                ui.add(egui::Separator::default().spacing(4.0));
                ui.horizontal(|ui| {
                    let te = TextEdit::singleline(&mut self.claude_input)
                        .hint_text("Ask Claude Code… (Enter to send)")
                        .desired_width(ui.available_width() - 70.0)
                        .font(egui::TextStyle::Body);
                    let resp = ui.add(te);

                    let send_label = if self.claude_thinking { "  …  " } else { "  Send  " };
                    let send = ui.add_enabled(
                        !self.claude_thinking,
                        egui::Button::new(RichText::new(send_label).color(Color32::BLACK))
                            .fill(if self.claude_thinking {
                                Color32::from_rgb(70, 45, 15)
                            } else {
                                Color32::from_rgb(200, 110, 25)
                            }),
                    );
                    let send_clicked = !self.claude_thinking
                        && (send.clicked()
                            || (resp.lost_focus()
                                && ctx.input(|i| i.key_pressed(egui::Key::Enter))));

                    if send_clicked {
                        let text = self.claude_input.trim().to_string();
                        if !text.is_empty() {
                            let api_key = self.state.lock().unwrap().settings.api_key.clone();
                            if api_key.is_empty() {
                                self.state.lock().unwrap().chat_messages.push(crate::app::ChatMessage {
                                    from_user: false,
                                    text: "No API key set. Add your Anthropic API key in the Settings tab.".into(),
                                });
                            } else {
                                {
                                    let mut s = self.state.lock().unwrap();
                                    s.chat_messages.push(crate::app::ChatMessage {
                                        from_user: true,
                                        text: text.clone(),
                                    });
                                }
                                // Build conversation history, prepending selected request as context.
                                let req_context = self.claude_selected_req.and_then(|idx| {
                                    let s = self.state.lock().unwrap();
                                    s.requests.get(idx).map(|r| {
                                        let raw = r.edited.as_deref().unwrap_or(&r.raw);
                                        format!(
                                            "Intercepted HTTP request (ID {}):\n\n```\n{}\n```",
                                            r.id,
                                            String::from_utf8_lossy(raw)
                                        )
                                    })
                                });
                                let mut history: Vec<serde_json::Value> = Vec::new();
                                if let Some(ctx) = req_context {
                                    history.push(serde_json::json!({ "role": "user", "content": ctx }));
                                    history.push(serde_json::json!({
                                        "role": "assistant",
                                        "content": "I have the intercepted request. How can I help you analyze it?"
                                    }));
                                }
                                let msgs = self.state.lock().unwrap().chat_messages.clone();
                                history.extend(msgs.iter().map(|m| serde_json::json!({
                                    "role": if m.from_user { "user" } else { "assistant" },
                                    "content": m.text,
                                })));

                                let (tx, rx) = std::sync::mpsc::sync_channel(1);
                                let state_clone = self.state.clone();
                                let mode = self.claude_mode;
                                self.rt.spawn(async move {
                                    crate::claude_client::chat(api_key, mode, state_clone, history, tx).await;
                                });
                                self.claude_rx = Some(rx);
                                self.claude_thinking = true;
                            }
                            self.claude_input.clear();
                        }
                        resp.request_focus();
                    }
                });
            });
        });
        self.claude_window_open = open;
    }

    // ── Exploit Dev tab ───────────────────────────────────────────────────────
    fn draw_exploit(&mut self, ctx: &egui::Context) {
        // Left panel: request list
        egui::SidePanel::left("exploit_req_list")
            .resizable(true)
            .default_width(340.0)
            .min_width(200.0)
            .show(ctx, |ui| {
                ui.add_space(4.0);
                ui.horizontal(|ui| {
                    ui.add_space(4.0);
                    ui.label(
                        RichText::new("SELECT TARGET REQUEST")
                            .size(11.0)
                            .color(Color32::DARK_GRAY),
                    );
                });
                ui.separator();

                let rows: Vec<_> = {
                    let s = self.state.lock().unwrap();
                    s.requests
                        .iter()
                        .enumerate()
                        .map(|(i, r)| {
                            (
                                i,
                                r.id,
                                r.method.clone(),
                                r.host.clone(),
                                r.port,
                                r.url.clone(),
                            )
                        })
                        .collect()
                };

                if rows.is_empty() {
                    ui.add_space(20.0);
                    ui.centered_and_justified(|ui| {
                        ui.label(
                            RichText::new(
                                "No requests intercepted yet.\nBrowse with the proxy active.",
                            )
                            .size(12.0)
                            .color(Color32::from_rgb(70, 70, 80)),
                        );
                    });
                } else {
                    ScrollArea::vertical()
                        .id_salt("exploit_req_scroll")
                        .show(ui, |ui| {
                            for (idx, id, method, host, port, url) in &rows {
                                let is_sel = self.exploit_selected == Some(*idx);
                                let mc = method_color(method);
                                let path_str = trunc(url, 30);

                                let row_h = 24.0;
                                let avail_w = ui.available_width();
                                let (rect, resp) = ui.allocate_exact_size(
                                    Vec2::new(avail_w, row_h),
                                    egui::Sense::click(),
                                );

                                let bg = if is_sel {
                                    Color32::from_rgb(60, 35, 15)
                                } else if resp.hovered() {
                                    Color32::from_rgb(38, 30, 18)
                                } else if idx % 2 == 0 {
                                    Color32::from_rgb(21, 21, 25)
                                } else {
                                    Color32::from_rgb(25, 25, 30)
                                };
                                ui.painter().rect_filled(rect, 0.0, bg);

                                ui.allocate_new_ui(egui::UiBuilder::new().max_rect(rect), |ui| {
                                    ui.horizontal(|ui| {
                                        ui.add_space(8.0);
                                        ui.colored_label(
                                            Color32::DARK_GRAY,
                                            RichText::new(format!("#{id:<4}"))
                                                .monospace()
                                                .size(10.0),
                                        );
                                        ui.colored_label(
                                            mc,
                                            RichText::new(format!("{method:<7}")).monospace(),
                                        );
                                        ui.add_space(4.0);
                                        ui.colored_label(
                                            Color32::from_rgb(195, 200, 220),
                                            RichText::new(format!("{host}:{port}")).size(11.0),
                                        );
                                        ui.add_space(4.0);
                                        ui.colored_label(
                                            Color32::from_rgb(130, 135, 155),
                                            RichText::new(&path_str).size(10.0),
                                        );
                                    });
                                });

                                if resp.clicked() {
                                    self.exploit_selected = Some(*idx);
                                }
                            }
                        });
                }
            });

        // Right panel: code editor
        egui::SidePanel::right("exploit_code_editor")
            .resizable(true)
            .default_width(420.0)
            .min_width(200.0)
            .show(ctx, |ui| {
                ui.add_space(4.0);
                ui.horizontal(|ui| {
                    ui.add_space(4.0);
                    ui.label(
                        RichText::new("CODE EDITOR")
                            .size(11.0)
                            .color(Color32::from_rgb(255, 160, 60)),
                    );
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        ui.add_space(4.0);
                        if ui.small_button("Clear").clicked() {
                            self.exploit_code.clear();
                        }
                        ui.add_space(4.0);
                        if ui.small_button("Copy").clicked() {
                            ui.output_mut(|o| o.copied_text = self.exploit_code.clone());
                        }
                    });
                });
                ui.separator();

                let avail_h = ui.available_height();
                ScrollArea::vertical()
                    .id_salt("exploit_code_scroll")
                    .max_height(avail_h)
                    .show(ui, |ui| {
                        let te = TextEdit::multiline(&mut self.exploit_code)
                            .font(egui::TextStyle::Monospace)
                            .desired_width(f32::INFINITY)
                            .desired_rows(40)
                            .frame(false)
                            .hint_text("# Paste or write your exploit here…\n# curl, Python, raw HTTP, etc.")
                            .text_color(Color32::from_rgb(180, 230, 180));
                        ui.add(te);
                    });
            });

        // Main panel: request preview + chat
        egui::CentralPanel::default().show(ctx, |ui| {
            ui.vertical(|ui| {
                // ── Header ────────────────────────────────────────────────
                ui.add_space(6.0);
                ui.horizontal(|ui| {
                    ui.add_space(8.0);
                    ui.label(
                        RichText::new("⚡ Exploit Dev")
                            .size(15.0)
                            .strong()
                            .color(Color32::from_rgb(255, 160, 60)),
                    );
                    ui.add_space(12.0);
                    ui.colored_label(Color32::DARK_GRAY, "AI-assisted PoC exploit development");

                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        ui.add_space(8.0);
                        if ui.small_button("Clear chat").clicked() {
                            self.exploit_messages.clear();
                        }
                    });
                });
                ui.add(egui::Separator::default().spacing(2.0));

                // ── Request preview (collapsible) ─────────────────────────
                let req_preview: Option<String> = self.exploit_selected.and_then(|idx| {
                    let s = self.state.lock().unwrap();
                    s.requests.get(idx).map(|r| {
                        let raw = r.edited.as_deref().unwrap_or(&r.raw);
                        String::from_utf8_lossy(raw).into_owned()
                    })
                });

                if let Some(ref raw_text) = req_preview {
                    let preview_h = (ui.available_height() * 0.22).max(80.0).min(160.0);
                    egui::Frame::none()
                        .fill(Color32::from_rgb(20, 22, 28))
                        .rounding(4.0)
                        .inner_margin(egui::Margin::symmetric(8.0, 5.0))
                        .show(ui, |ui| {
                            ui.set_max_height(preview_h);
                            ui.horizontal(|ui| {
                                ui.colored_label(
                                    Color32::from_rgb(255, 160, 60),
                                    RichText::new("TARGET REQUEST").size(10.0),
                                );
                                ui.add_space(8.0);

                                // "⚡ Analyze" quick button
                                let analyze_btn = egui::Button::new(
                                    RichText::new("  ⚡ Analyze  ")
                                        .size(11.0)
                                        .color(Color32::BLACK),
                                )
                                .fill(Color32::from_rgb(200, 120, 30));

                                if ui
                                    .add_enabled(!self.exploit_thinking, analyze_btn)
                                    .clicked()
                                {
                                    self.exploit_send_analyze(ctx);
                                }
                            });
                            ui.add_space(2.0);
                            ScrollArea::vertical()
                                .id_salt("exploit_req_preview")
                                .max_height(preview_h - 32.0)
                                .show(ui, |ui| {
                                    let mut t = raw_text.clone();
                                    ui.add(
                                        TextEdit::multiline(&mut t)
                                            .font(egui::TextStyle::Monospace)
                                            .desired_width(f32::INFINITY)
                                            .interactive(false)
                                            .frame(false)
                                            .text_color(Color32::from_rgb(180, 200, 220)),
                                    );
                                });
                        });
                    ui.add_space(4.0);
                } else {
                    ui.add_space(4.0);
                    egui::Frame::none()
                        .fill(Color32::from_rgb(22, 22, 26))
                        .rounding(4.0)
                        .inner_margin(egui::Margin::symmetric(8.0, 8.0))
                        .show(ui, |ui| {
                            ui.colored_label(
                                Color32::from_rgb(70, 70, 80),
                                "← Select a request from the list to start exploit development",
                            );
                        });
                    ui.add_space(4.0);
                }

                // ── Message history ───────────────────────────────────────
                let history_h = ui.available_height() - 56.0;
                ScrollArea::vertical()
                    .id_salt("exploit_history")
                    .max_height(history_h)
                    .stick_to_bottom(true)
                    .show(ui, |ui| {
                        ui.add_space(4.0);
                        let mut send_to_editor: Option<String> = None;
                        for (i, msg) in self.exploit_messages.iter().enumerate() {
                            ui.add_space(6.0);
                            if msg.from_user {
                                ui.with_layout(
                                    egui::Layout::right_to_left(egui::Align::TOP),
                                    |ui| {
                                        ui.add_space(8.0);
                                        egui::Frame::none()
                                            .fill(Color32::from_rgb(55, 35, 15))
                                            .rounding(8.0)
                                            .inner_margin(egui::Margin::symmetric(10.0, 6.0))
                                            .show(ui, |ui| {
                                                ui.set_max_width(ui.available_width() * 0.75);
                                                ui.label(
                                                    RichText::new(&msg.text)
                                                        .size(13.0)
                                                        .color(Color32::from_rgb(255, 220, 180)),
                                                );
                                            });
                                    },
                                );
                            } else {
                                ui.add_space(2.0);
                                ui.with_layout(
                                    egui::Layout::left_to_right(egui::Align::TOP),
                                    |ui| {
                                        ui.add_space(8.0);
                                        ui.vertical(|ui| {
                                            // Render message with code blocks highlighted
                                            egui::Frame::none()
                                                .fill(Color32::from_rgb(26, 28, 38))
                                                .rounding(8.0)
                                                .inner_margin(egui::Margin::symmetric(10.0, 8.0))
                                                .show(ui, |ui| {
                                                    ui.set_max_width(ui.available_width() * 0.9);
                                                    render_message_with_code(ui, &msg.text, i);
                                                });

                                            // "→ Editor" button if the message contains code
                                            let code = extract_code_blocks(&msg.text);
                                            if !code.is_empty() {
                                                ui.add_space(3.0);
                                                ui.horizontal(|ui| {
                                                    ui.add_space(2.0);
                                                    let btn = egui::Button::new(
                                                        RichText::new("  → Editor  ")
                                                            .size(11.0)
                                                            .color(Color32::BLACK),
                                                    )
                                                    .fill(Color32::from_rgb(180, 110, 20));
                                                    if ui
                                                        .add(btn)
                                                        .on_hover_text(
                                                            "Send code to the editor panel",
                                                        )
                                                        .clicked()
                                                    {
                                                        send_to_editor = Some(code);
                                                    }
                                                });
                                            }
                                        });
                                    },
                                );
                            }
                        }
                        if let Some(code) = send_to_editor {
                            self.exploit_code = code;
                        }

                        if self.exploit_thinking {
                            ui.add_space(6.0);
                            ui.with_layout(egui::Layout::left_to_right(egui::Align::TOP), |ui| {
                                ui.add_space(8.0);
                                ui.colored_label(
                                    Color32::from_rgb(255, 160, 60),
                                    RichText::new("↻  Generating exploit…").size(12.0).italics(),
                                );
                            });
                        }

                        if self.exploit_messages.is_empty() && !self.exploit_thinking {
                            ui.add_space(30.0);
                            ui.centered_and_justified(|ui| {
                                ui.label(
                                    RichText::new(
                                        "Select a request and click ⚡ Analyze,\n\
                                         or type a question about the target request below.",
                                    )
                                    .size(13.0)
                                    .color(Color32::from_rgb(60, 65, 80)),
                                );
                            });
                        }
                    });

                // ── Input bar ─────────────────────────────────────────────
                ui.add(egui::Separator::default().spacing(4.0));
                ui.horizontal(|ui| {
                    let te = TextEdit::singleline(&mut self.exploit_input)
                        .hint_text(
                            "Ask about the request, request a PoC, suggest a payload… (Enter)",
                        )
                        .desired_width(ui.available_width() - 80.0)
                        .font(egui::TextStyle::Body);
                    let resp = ui.add(te);

                    let send_label = if self.exploit_thinking {
                        "  …  "
                    } else {
                        "  Send  "
                    };
                    let send_btn = ui.add_enabled(
                        !self.exploit_thinking,
                        egui::Button::new(RichText::new(send_label).color(Color32::BLACK)).fill(
                            if self.exploit_thinking {
                                Color32::from_rgb(60, 50, 30)
                            } else {
                                Color32::from_rgb(200, 120, 30)
                            },
                        ),
                    );

                    let send_clicked = !self.exploit_thinking
                        && (send_btn.clicked()
                            || (resp.lost_focus()
                                && ctx.input(|i| i.key_pressed(egui::Key::Enter))));

                    if send_clicked {
                        let text = self.exploit_input.trim().to_string();
                        if !text.is_empty() {
                            self.exploit_input.clear();
                            self.exploit_send_message(text);
                        }
                        resp.request_focus();
                    }
                });
            });
        });
    }

    fn exploit_build_history(&self) -> Vec<serde_json::Value> {
        let mut history: Vec<serde_json::Value> = Vec::new();

        // Prepend the selected request as the first user message if present.
        let req_context = self.exploit_selected.and_then(|idx| {
            let s = self.state.lock().unwrap();
            s.requests.get(idx).map(|r| {
                let raw = r.edited.as_deref().unwrap_or(&r.raw);
                format!(
                    "Target request (ID {}):\n\n```\n{}\n```",
                    r.id,
                    String::from_utf8_lossy(raw)
                )
            })
        });

        if let Some(ctx_msg) = req_context {
            history.push(serde_json::json!({ "role": "user", "content": ctx_msg }));
            history.push(serde_json::json!({
                "role": "assistant",
                "content": "I have the intercepted request. I'll analyze it for vulnerabilities and help you develop a working PoC.",
            }));
        }

        for msg in &self.exploit_messages {
            history.push(serde_json::json!({
                "role": if msg.from_user { "user" } else { "assistant" },
                "content": msg.text,
            }));
        }

        history
    }

    fn exploit_send_message(&mut self, text: String) {
        let api_key = self.state.lock().unwrap().settings.api_key.clone();
        if api_key.is_empty() {
            self.exploit_messages.push(ExploitMessage {
                from_user: false,
                text: "No API key set. Add your Anthropic API key in the Settings tab.".into(),
            });
            return;
        }
        self.exploit_messages.push(ExploitMessage {
            from_user: true,
            text,
        });
        let history = self.exploit_build_history();
        let (tx, rx) = std::sync::mpsc::sync_channel(1);
        let state_clone = self.state.clone();
        self.rt.spawn(async move {
            crate::claude_client::chat(
                api_key,
                crate::claude_client::AssistantMode::Exploit,
                state_clone,
                history,
                tx,
            )
            .await;
        });
        self.exploit_rx = Some(rx);
        self.exploit_thinking = true;
    }

    fn exploit_send_analyze(&mut self, _ctx: &egui::Context) {
        let req_text = match self.exploit_selected {
            Some(idx) => {
                let s = self.state.lock().unwrap();
                s.requests.get(idx).map(|r| {
                    let raw = r.edited.as_deref().unwrap_or(&r.raw);
                    format!(
                        "Analyze this intercepted HTTP request for vulnerabilities and provide a working PoC exploit:\n\n```\n{}\n```",
                        String::from_utf8_lossy(raw)
                    )
                })
            }
            None => None,
        };
        if let Some(text) = req_text {
            self.exploit_send_message(text);
        }
    }

    // ── OpenAPI : background scan task ──────────────────────────────────────

    fn poll_openapi(&mut self) -> bool {
        let Some(rx) = &self.openapi_rx else { return false };
        let mut changed = false;
        for _ in 0..128 {
            match rx.try_recv() {
                Ok(crate::openapi::ScanMsg::Result(r)) => {
                    self.openapi_results.push(r);
                    changed = true;
                }
                Ok(crate::openapi::ScanMsg::TripleDone) => {
                    self.openapi_jobs_done += 1;
                    changed = true;
                }
                Ok(crate::openapi::ScanMsg::Skipped(n)) => {
                    self.openapi_jobs_skipped += n;
                    changed = true;
                }
                Ok(crate::openapi::ScanMsg::Finished) => {
                    self.openapi_scanning = false;
                    self.openapi_rx = None;
                    let reqs  = self.openapi_results.len();
                    let vulns: usize = self.openapi_results.iter()
                        .filter(|r| r.evidence.is_some())
                        .count();
                    self.openapi_parse_status = Some(format!(
                        "✓ Scan terminé — {reqs} requêtes · {vulns} vulnérabilité(s) confirmée(s)"));
                    changed = true;
                    break;
                }
                Err(_) => break,
            }
        }
        changed
    }

    fn draw_openapi(&mut self, ctx: &egui::Context) {
        // ── Panneau gauche ────────────────────────────────────────────────
        egui::SidePanel::left("openapi_left")
            .resizable(true)
            .default_width(400.0)
            .min_width(220.0)
            .show(ctx, |ui| {
                ui.add_space(4.0);

                // Fichier
                ui.horizontal(|ui| {
                    ui.label(RichText::new("Fichier :").size(12.0).color(Color32::DARK_GRAY));
                    ui.add(TextEdit::singleline(&mut self.openapi_file_path)
                        .hint_text("/chemin/vers/openapi.yml")
                        .desired_width(f32::INFINITY)
                        .font(egui::TextStyle::Monospace));
                });
                ui.add_space(2.0);

                // Cible
                ui.horizontal(|ui| {
                    ui.label(RichText::new("Cible   :").size(12.0).color(Color32::DARK_GRAY));
                    ui.add(TextEdit::singleline(&mut self.openapi_target_url)
                        .hint_text("http://localhost:8080")
                        .desired_width(f32::INFINITY)
                        .font(egui::TextStyle::Monospace));
                });
                ui.add_space(4.0);

                // Boutons
                ui.horizontal(|ui| {
                    // ── Charger ───────────────────────────────────────────
                    if ui.add(egui::Button::new(
                        RichText::new("  📂 Charger  ").size(12.0).color(Color32::WHITE)
                    ).fill(Color32::from_rgb(55, 55, 75))).clicked() {
                        let path = self.openapi_file_path.trim().to_string();
                        match std::fs::read_to_string(&path) {
                            Ok(text) => match crate::openapi::parse(&text) {
                                Ok(res) => {
                                    let n = res.endpoints.len();
                                    self.openapi_endpoints    = res.endpoints;
                                    self.openapi_results      = Vec::new();
                                    self.openapi_rx           = None;
                                    self.openapi_stop         = None;
                                    self.openapi_selected     = None;
                                    self.openapi_selected_res = None;
                                    self.openapi_scanning     = false;
                                    self.openapi_jobs_total   = 0;
                                    if let Some(url) = res.server_url {
                                        if self.openapi_target_url.trim().is_empty() {
                                            self.openapi_target_url = url;
                                        }
                                    }
                                    let mut tags: Vec<&'static str> = Vec::new();
                                    if let Some(c) = res.credentials {
                                        if c.bearer.is_some()        { tags.push("bearer") }
                                        if c.cookie.is_some()        { tags.push("cookie") }
                                        if c.username.is_some()      { tags.push("user") }
                                        if c.api_key_value.is_some() { tags.push("api_key") }
                                        self.openapi_creds = c;
                                    } else {
                                        self.openapi_creds = crate::openapi::Credentials::default();
                                    }
                                    let cred_info = if tags.is_empty() { String::new() }
                                        else { format!("  ·  creds: {}", tags.join("+")) };
                                    self.openapi_parse_status =
                                        Some(format!("✓ {n} endpoint(s){cred_info}"));
                                }
                                Err(e) => {
                                    self.openapi_endpoints.clear();
                                    self.openapi_parse_status = Some(format!("✗ Parse : {e}"));
                                }
                            },
                            Err(e) => {
                                self.openapi_parse_status = Some(format!("✗ Lecture : {e}"));
                            }
                        }
                    }

                    ui.add_space(4.0);

                    // ── Scan All ──────────────────────────────────────────
                    let can_scan = !self.openapi_endpoints.is_empty()
                        && !self.openapi_target_url.trim().is_empty()
                        && !self.openapi_scanning;
                    if ui.add_enabled(can_scan,
                        egui::Button::new(
                            RichText::new("  ▶ Scan All  ").size(12.0).color(Color32::BLACK)
                        ).fill(Color32::from_rgb(50, 170, 70))
                    ).clicked() {
                        self.start_openapi_scan(None);
                    }

                    // ── Stop ──────────────────────────────────────────────
                    if self.openapi_scanning {
                        if ui.add(egui::Button::new(
                            RichText::new("  ■ Stop  ").size(12.0).color(Color32::WHITE)
                        ).fill(Color32::from_rgb(180, 50, 50))).clicked() {
                            if let Some(ref flag) = self.openapi_stop {
                                flag.store(true, std::sync::atomic::Ordering::Relaxed);
                            }
                        }
                    }
                });

                // ── Export Markdown (after scan) ──────────────────────────
                let has_results = !self.openapi_results.is_empty() && !self.openapi_scanning;
                if has_results {
                    ui.add_space(3.0);
                    let md_btn = egui::Button::new(
                        RichText::new("  📄 Export Rapport MD  ")
                            .size(12.0)
                            .color(Color32::from_rgb(200, 180, 255)),
                    ).fill(Color32::from_rgb(45, 35, 70));
                    if ui.add(md_btn).clicked() {
                        let report = self.build_markdown_report();
                        let ts = std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .unwrap_or_default()
                            .as_secs();
                        let name = format!("rustman_report_{ts}.md");
                        match std::fs::write(&name, &report) {
                            Ok(_) => {
                                self.openapi_md_status = Some(format!("✓ Rapport sauvegardé : {name}"));
                            }
                            Err(e) => {
                                self.openapi_md_status = Some(format!("✗ Erreur : {e}"));
                            }
                        }
                    }
                    if let Some(ref msg) = self.openapi_md_status.clone() {
                        let col = if msg.starts_with('✓') {
                            Color32::from_rgb(80, 200, 100)
                        } else {
                            Color32::from_rgb(220, 80, 80)
                        };
                        ui.colored_label(col, RichText::new(msg).size(10.0));
                    }
                }

                // Statut parse
                if let Some(ref st) = self.openapi_parse_status.clone() {
                    let color = if st.starts_with('✓') {
                        Color32::from_rgb(80, 200, 100)
                    } else {
                        Color32::from_rgb(220, 80, 80)
                    };
                    ui.add_space(2.0);
                    ui.colored_label(color, RichText::new(st).size(11.0));
                }

                // Credentials (compact)
                {
                    let c = &self.openapi_creds;
                    let parts: Vec<String> = [
                        c.bearer.as_ref().map(|b| {
                            let p = &b[..b.len().min(16)];
                            format!("Bearer {p}…")
                        }),
                        c.cookie.as_ref().map(|ck| {
                            let p = &ck[..ck.len().min(16)];
                            format!("Cookie {p}…")
                        }),
                        c.username.as_ref().map(|u| format!("user={u}")),
                        c.api_key_header.as_ref().zip(c.api_key_value.as_ref())
                            .map(|(h, v)| format!("{h}={v}")),
                    ].into_iter().flatten().collect();
                    if !parts.is_empty() {
                        ui.add_space(2.0);
                        ui.colored_label(Color32::from_rgb(100, 160, 100),
                            RichText::new(format!("🔑 {}", parts.join("  ·  "))).size(10.0));
                    }
                }

                // Barre de progression — largeur fixe pour ne pas comprimer le panneau droit
                if self.openapi_jobs_total > 0 {
                    let done  = self.openapi_results.len() + self.openapi_jobs_skipped;
                    let total = self.openapi_jobs_total;
                    let frac  = (done as f32 / total as f32).min(1.0);
                    ui.add_space(3.0);
                    ui.horizontal(|ui| {
                        ui.add(egui::ProgressBar::new(frac)
                            .desired_width(220.0)
                            .show_percentage());
                        ui.colored_label(Color32::from_rgb(160, 160, 180),
                            RichText::new(format!("{done}/{total}")).size(10.0));
                    });
                }

                ui.add_space(4.0);
                ui.separator();

                if self.openapi_endpoints.is_empty() {
                    ui.add_space(20.0);
                    ui.centered_and_justified(|ui| {
                        ui.label(RichText::new(
                            "Entrez le chemin d'un fichier OpenAPI YAML / JSON\net cliquez 📂 Charger.\n\nLe scan teste les payloads du dossier payload/\nsur chaque body field et query param du spec."
                        ).size(12.0).color(Color32::from_rgb(70, 70, 80)));
                    });
                    return;
                }

                // ── Liste des endpoints ───────────────────────────────────
                ui.horizontal(|ui| {
                    ui.add_space(8.0);
                    ui.colored_label(Color32::DARK_GRAY,
                        RichText::new(format!("{:<7}", "METHOD")).monospace().size(10.0));
                    ui.add_space(4.0);
                    ui.colored_label(Color32::DARK_GRAY, RichText::new("PATH").size(10.0));
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        ui.colored_label(Color32::DARK_GRAY,
                            RichText::new("HIT/REQ").monospace().size(10.0));
                    });
                });
                ui.add(egui::Separator::default().spacing(2.0));

                // Compteurs par endpoint
                let mut ep_done = vec![0usize; self.openapi_endpoints.len()];
                let mut ep_hit  = vec![0usize; self.openapi_endpoints.len()];
                for r in &self.openapi_results {
                    if r.ep_idx < ep_done.len() {
                        ep_done[r.ep_idx] += 1;
                        if matches!(r.status, 200..=299 | 500..=599) {
                            ep_hit[r.ep_idx] += 1;
                        }
                    }
                }

                let selected = self.openapi_selected;
                ScrollArea::vertical()
                    .id_salt("openapi_ep_list")
                    .auto_shrink([false, false])
                    .show(ui, |ui| {
                        for i in 0..self.openapi_endpoints.len() {
                            let ep    = &self.openapi_endpoints[i];
                            let is_sel = selected == Some(i);
                            let row_h = 22.0;
                            let avail_w = ui.available_width();
                            let (rect, resp) = ui.allocate_exact_size(
                                Vec2::new(avail_w, row_h), egui::Sense::click());

                            let bg = if is_sel {
                                Color32::from_rgb(65, 42, 12)
                            } else if resp.hovered() {
                                Color32::from_rgb(34, 37, 52)
                            } else if i % 2 == 0 {
                                Color32::from_rgb(21, 21, 25)
                            } else {
                                Color32::from_rgb(25, 25, 30)
                            };
                            ui.painter().rect_filled(rect, 0.0, bg);

                            let mc = method_color(&ep.method);
                            let done = ep_done[i];
                            let hit  = ep_hit[i];
                            let (badge, badge_col) = if done > 0 {
                                let col = if hit > 0 { Color32::from_rgb(220,160,60) }
                                          else        { Color32::from_rgb(80,200,100) };
                                (format!("{hit}/{done}"), col)
                            } else if self.openapi_scanning {
                                ("↻".into(), Color32::from_rgb(100,140,200))
                            } else {
                                (" — ".into(), Color32::DARK_GRAY)
                            };

                            ui.allocate_new_ui(egui::UiBuilder::new().max_rect(rect), |ui| {
                                ui.horizontal(|ui| {
                                    ui.add_space(8.0);
                                    ui.colored_label(mc,
                                        RichText::new(format!("{:<7}", ep.method))
                                            .monospace().size(11.0));
                                    ui.add_space(4.0);
                                    ui.colored_label(Color32::from_rgb(195,200,220),
                                        RichText::new(&ep.path).monospace().size(11.0));
                                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                                        ui.add_space(6.0);
                                        ui.colored_label(badge_col,
                                            RichText::new(badge).monospace().size(10.0));
                                    });
                                });
                            });

                            if resp.clicked() {
                                self.openapi_selected     = Some(i);
                                self.openapi_selected_res = None;
                            }
                        }
                    });
            });

        // ── Panneau central : résultats ───────────────────────────────────
        egui::CentralPanel::default().show(ctx, |ui| {
            let Some(ep_idx) = self.openapi_selected else {
                ui.centered_and_justified(|ui| {
                    ui.label(RichText::new("Sélectionnez un endpoint dans la liste.")
                        .size(13.0).color(Color32::from_rgb(70,70,80)));
                });
                return;
            };
            if ep_idx >= self.openapi_endpoints.len() { return; }

            let ep_method = self.openapi_endpoints[ep_idx].method.clone();
            let ep_path   = self.openapi_endpoints[ep_idx].path.clone();
            let ep_clone  = self.openapi_endpoints[ep_idx].clone();
            let mc = method_color(&ep_method);

            // Header endpoint
            ui.horizontal(|ui| {
                ui.colored_label(mc, RichText::new(&ep_method).size(14.0).strong());
                ui.add_space(6.0);
                ui.label(RichText::new(&ep_path).size(14.0).strong().color(Color32::WHITE));

                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    // Scan cet endpoint uniquement
                    let ep_running = self.openapi_scanning && self.openapi_results
                        .iter().any(|r| r.ep_idx == ep_idx)
                        || (!self.openapi_scanning && self.openapi_rx.is_some());
                    let btn_label = if ep_running { "  ↻  " } else { "  ▶ Scan ep  " };
                    let btn_col   = if ep_running { Color32::from_rgb(150,80,15) }
                                    else          { Color32::from_rgb(50,170,70) };
                    let can_ep = !ep_running && !self.openapi_target_url.trim().is_empty();
                    if ui.add_enabled(can_ep, egui::Button::new(
                        RichText::new(btn_label).size(12.0)
                            .color(if ep_running { Color32::WHITE } else { Color32::BLACK })
                    ).fill(btn_col)).clicked() {
                        self.openapi_results.retain(|r| r.ep_idx != ep_idx);
                        self.openapi_selected_res = None;
                        self.start_openapi_scan(Some(ep_idx));
                    }
                });
            });
            ui.add(egui::Separator::default().spacing(4.0));

            let available_h = ui.available_height();

            // Résultats de cet endpoint
            let ep_res_indices: Vec<usize> = self.openapi_results
                .iter().enumerate()
                .filter(|(_, r)| r.ep_idx == ep_idx)
                .map(|(i, _)| i)
                .collect();

            if ep_res_indices.is_empty() {
                let np = ep_clone.body_fields.len() + ep_clone.query_params.len();
                ui.add_space(12.0);
                if np == 0 {
                    ui.colored_label(Color32::DARK_GRAY, RichText::new(
                        "Aucun body field ni query param dans le spec.\nLe fuzzing payload ne s'applique pas à cet endpoint."
                    ).size(12.0));
                } else {
                    ui.colored_label(Color32::DARK_GRAY, RichText::new(format!(
                        "{np} paramètre(s) détecté(s).\nLance ▶ Scan ep ou ▶ Scan All pour tester les payloads."
                    )).size(12.0));
                }
                return;
            }

            let selected_res = self.openapi_selected_res;
            let table_h = if selected_res.is_some() { available_h * 0.38 } else { available_h };

            // ── Tableau des résultats ─────────────────────────────────────
            egui::Frame::none()
                .fill(Color32::from_rgb(16,18,24))
                .rounding(4.0)
                .inner_margin(egui::Margin::symmetric(6.0,4.0))
                .show(ui, |ui| {
                    ui.horizontal(|ui| {
                        ui.colored_label(Color32::DARK_GRAY,
                            RichText::new(format!("{:<6}","CODE")).monospace().size(10.0));
                        ui.add_space(4.0);
                        ui.colored_label(Color32::DARK_GRAY,
                            RichText::new(format!("{:<6}","LOC")).monospace().size(10.0));
                        ui.add_space(4.0);
                        ui.colored_label(Color32::DARK_GRAY,
                            RichText::new(format!("{:<13}","PARAM")).monospace().size(10.0));
                        ui.add_space(4.0);
                        ui.colored_label(Color32::DARK_GRAY,
                            RichText::new(format!("{:<10}","CATEGORY")).monospace().size(10.0));
                        ui.add_space(4.0);
                        ui.colored_label(Color32::DARK_GRAY,
                            RichText::new("PAYLOAD").size(10.0));
                        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                            ui.add_space(8.0);
                            ui.colored_label(Color32::DARK_GRAY,
                                RichText::new("STATUS").monospace().size(10.0));
                        });
                    });
                    ui.add(egui::Separator::default().spacing(2.0));

                    ScrollArea::vertical()
                        .id_salt("openapi_res_table")
                        .max_height(table_h - 32.0)
                        .auto_shrink([false,false])
                        .show(ui, |ui| {
                            for &ri in &ep_res_indices {
                                let r = &self.openapi_results[ri];
                                let is_sel = selected_res == Some(ri);
                                let row_h = 20.0;
                                let avail_w = ui.available_width();
                                let (rect, resp) = ui.allocate_exact_size(
                                    Vec2::new(avail_w, row_h), egui::Sense::click());

                                let is_vuln = self.openapi_results[ri].evidence.is_some();
                                let bg = if is_sel && is_vuln {
                                    Color32::from_rgb(90, 18, 18)
                                } else if is_sel {
                                    Color32::from_rgb(50, 38, 10)
                                } else if is_vuln && resp.hovered() {
                                    Color32::from_rgb(80, 20, 20)
                                } else if is_vuln {
                                    Color32::from_rgb(55, 14, 14)
                                } else if resp.hovered() {
                                    Color32::from_rgb(28, 32, 44)
                                } else if ri % 2 == 0 {
                                    Color32::from_rgb(14, 16, 20)
                                } else {
                                    Color32::from_rgb(18, 20, 26)
                                };
                                ui.painter().rect_filled(rect, 0.0, bg);

                                let sc = r.status;
                                let sc_col = match sc {
                                    200..=299 => Color32::from_rgb(80,200,100),
                                    300..=399 => Color32::from_rgb(100,160,255),
                                    400..=499 => Color32::from_rgb(200,140,50),
                                    500..=599 => Color32::from_rgb(220,70,70),
                                    _         => Color32::DARK_GRAY,
                                };
                                let loc_s = match r.loc {
                                    crate::openapi::ParamLoc::Body  => "body",
                                    crate::openapi::ParamLoc::Query => "query",
                                    crate::openapi::ParamLoc::Path  => "path",
                                };
                                let param_s = if r.param.len() > 12 {
                                    format!("{}…", &r.param[..12])
                                } else { r.param.clone() };
                                let cat_s = if r.category.len() > 9 {
                                    format!("{}…", &r.category[..9])
                                } else { r.category.clone() };
                                let pay_s = if r.payload.len() > 32 {
                                    format!("{}…", &r.payload[..32])
                                } else { r.payload.clone() };

                                ui.allocate_new_ui(egui::UiBuilder::new().max_rect(rect), |ui| {
                                    ui.horizontal(|ui| {
                                        ui.colored_label(sc_col,
                                            RichText::new(format!("{:<6}",sc))
                                                .monospace().size(11.0));
                                        ui.add_space(4.0);
                                        ui.colored_label(Color32::from_rgb(150,150,180),
                                            RichText::new(format!("{:<6}",loc_s))
                                                .monospace().size(11.0));
                                        ui.add_space(4.0);
                                        ui.colored_label(Color32::from_rgb(180,200,220),
                                            RichText::new(format!("{:<13}",param_s))
                                                .monospace().size(11.0));
                                        ui.add_space(4.0);
                                        let cat_color = if is_vuln {
                                            Color32::from_rgb(255, 100, 100)
                                        } else {
                                            Color32::from_rgb(200, 180, 120)
                                        };
                                        ui.colored_label(cat_color,
                                            RichText::new(format!("{:<10}",cat_s))
                                                .monospace().size(11.0));
                                        ui.add_space(4.0);
                                        ui.colored_label(Color32::from_rgb(210,210,225),
                                            RichText::new(&pay_s).monospace().size(11.0));
                                        // VULN badge — right-aligned
                                        if is_vuln {
                                            ui.with_layout(
                                                egui::Layout::right_to_left(egui::Align::Center),
                                                |ui| {
                                                    ui.add_space(6.0);
                                                    ui.colored_label(
                                                        Color32::from_rgb(255, 70, 70),
                                                        RichText::new("⚠ VULN")
                                                            .strong()
                                                            .size(10.0),
                                                    );
                                                },
                                            );
                                        }
                                    });
                                });

                                if resp.clicked() {
                                    self.openapi_selected_res =
                                        if is_sel { None } else { Some(ri) };
                                }
                            }
                        });
                });

            // ── Détail requête / réponse ──────────────────────────────────
            if let Some(ri) = self.openapi_selected_res {
                if let Some(r) = self.openapi_results.get(ri).cloned() {
                    ui.add_space(4.0);
                    let avail = ui.available_height();

                    let req_display = if let Some(parts) =
                        crate::crawler::parse_url(self.openapi_target_url.trim())
                    {
                        let raw = ep_clone.build_request_fuzzed(
                            &parts.host, parts.port, parts.tls,
                            self.openapi_creds.cookie.as_deref().unwrap_or(""),
                            self.openapi_creds.bearer.as_deref().unwrap_or(""),
                            self.openapi_creds.api_key_header.as_deref().unwrap_or(""),
                            self.openapi_creds.api_key_value.as_deref().unwrap_or(""),
                            &r.param, &r.loc, &r.payload,
                        );
                        String::from_utf8_lossy(&raw).into_owned()
                    } else {
                        format!("{} {} [URL cible invalide]", ep_method, ep_path)
                    };

                    let sc_col = match r.status {
                        200..=299 => Color32::from_rgb(80,200,100),
                        300..=399 => Color32::from_rgb(100,160,255),
                        400..=499 => Color32::from_rgb(200,140,50),
                        500..=599 => Color32::from_rgb(220,70,70),
                        _         => Color32::DARK_GRAY,
                    };
                    let resp_text = String::from_utf8_lossy(&r.response).into_owned();

                    // ── Evidence banner (only when vulnerability confirmed) ──
                    if let Some(ref ev) = r.evidence {
                        ui.add_space(4.0);
                        egui::Frame::none()
                            .fill(Color32::from_rgb(60, 14, 14))
                            .rounding(4.0)
                            .inner_margin(egui::Margin::symmetric(10.0, 6.0))
                            .show(ui, |ui| {
                                ui.horizontal(|ui| {
                                    ui.colored_label(
                                        Color32::from_rgb(255, 70, 70),
                                        RichText::new("⚠  VULNÉRABILITÉ CONFIRMÉE")
                                            .strong()
                                            .size(12.0),
                                    );
                                    ui.add_space(10.0);
                                    ui.colored_label(
                                        Color32::from_rgb(255, 140, 60),
                                        RichText::new(&r.category).strong().size(12.0),
                                    );
                                    ui.add_space(10.0);
                                    ui.colored_label(
                                        Color32::from_rgb(200, 200, 120),
                                        RichText::new(format!("param: {}", r.param))
                                            .monospace()
                                            .size(11.0),
                                    );
                                });
                                ui.add_space(2.0);
                                ui.colored_label(
                                    Color32::from_rgb(255, 200, 120),
                                    RichText::new(format!("Preuve : {ev}"))
                                        .monospace()
                                        .size(11.0),
                                );
                            });
                        ui.add_space(4.0);
                    }

                    ui.columns(2, |cols| {
                        cols[0].colored_label(Color32::DARK_GRAY, "REQUEST");
                        egui::Frame::none()
                            .fill(Color32::from_rgb(16,18,24))
                            .rounding(3.0)
                            .inner_margin(egui::Margin::symmetric(6.0,4.0))
                            .show(&mut cols[0], |ui| {
                                if ui.add(egui::Button::new(
                                    RichText::new("→ Repeater").size(11.0)
                                        .color(Color32::from_rgb(180,220,255))
                                ).fill(Color32::from_rgb(28,48,78)).small()).clicked() {
                                    if let Some(parts) =
                                        crate::crawler::parse_url(self.openapi_target_url.trim())
                                    {
                                        let raw2 = ep_clone.build_request_fuzzed(
                                            &parts.host, parts.port, parts.tls,
                                            self.openapi_creds.cookie.as_deref().unwrap_or(""),
                                            self.openapi_creds.bearer.as_deref().unwrap_or(""),
                                            self.openapi_creds.api_key_header.as_deref().unwrap_or(""),
                                            self.openapi_creds.api_key_value.as_deref().unwrap_or(""),
                                            &r.param, &r.loc, &r.payload,
                                        );
                                        let req_text2 = String::from_utf8_lossy(&raw2).into_owned();
                                        let proto = if parts.tls { "HTTPS" } else { "HTTP" };
                                        let id2 = self.rep_next_id;
                                        self.rep_next_id += 1;
                                        self.repeater.push(crate::gui::RepeaterSession {
                                            id: id2,
                                            label: format!("{proto}  {ep_method}  {}:{}", parts.host, parts.port),
                                            host: parts.host, port: parts.port, tls: parts.tls,
                                            req_buf: req_text2,
                                            response: None, pending: None,
                                        });
                                        self.rep_selected = Some(self.repeater.len() - 1);
                                        self.tab = ActiveTab::Repeater;
                                    }
                                }
                                ScrollArea::vertical()
                                    .id_salt(format!("oa_req_{ri}"))
                                    .max_height(avail - 30.0)
                                    .show(ui, |ui| {
                                        let mut t = req_display;
                                        ui.add(TextEdit::multiline(&mut t)
                                            .font(egui::TextStyle::Monospace)
                                            .desired_width(f32::INFINITY)
                                            .interactive(false).frame(false)
                                            .text_color(Color32::from_rgb(210,210,220)));
                                    });
                            });

                        cols[1].horizontal(|ui| {
                            ui.colored_label(Color32::DARK_GRAY, "RESPONSE");
                            ui.add_space(6.0);
                            ui.colored_label(sc_col,
                                RichText::new(r.status.to_string()).strong().size(13.0));
                        });
                        egui::Frame::none()
                            .fill(Color32::from_rgb(14,18,20))
                            .rounding(3.0)
                            .inner_margin(egui::Margin::symmetric(6.0,4.0))
                            .show(&mut cols[1], |ui| {
                                ScrollArea::vertical()
                                    .id_salt(format!("oa_resp_{ri}"))
                                    .max_height(avail - 30.0)
                                    .show(ui, |ui| {
                                        let mut t = resp_text;
                                        ui.add(TextEdit::multiline(&mut t)
                                            .font(egui::TextStyle::Monospace)
                                            .desired_width(f32::INFINITY)
                                            .interactive(false).frame(false)
                                            .text_color(Color32::from_rgb(180,210,180)));
                                    });
                            });
                    });
                }
            }
        });
    }

    /// Démarre le scan OpenAPI en background (comme le crawler).
    /// `ep_filter` = None → tous les endpoints, Some(i) → seulement l'endpoint i.
    fn start_openapi_scan(&mut self, ep_filter: Option<usize>) {
        use std::sync::{Arc, atomic::{AtomicBool, Ordering}};
        use crate::openapi::{ApiEndpoint, ParamLoc, ScanMsg, ScanResult};

        // ── Cherche le dossier payload/ (plusieurs emplacements possibles) ──
        let payload_dir: std::path::PathBuf = {
            // 1. Répertoire courant (cargo run depuis la racine du projet)
            let from_cwd = std::env::current_dir().ok().map(|d| d.join("payload"));
            // 2. À côté du binaire (installation)
            let from_exe = std::env::current_exe().ok()
                .and_then(|p| p.parent().map(|d| d.join("payload")));
            from_cwd.iter().chain(from_exe.iter())
                .find(|p| p.exists())
                .cloned()
                .unwrap_or_else(|| std::path::PathBuf::from("payload"))
        };

        let payloads = crate::openapi::load_payloads(
            payload_dir.to_str().unwrap_or("payload"));

        if payloads.is_empty() {
            self.openapi_parse_status = Some(format!(
                "✗ Aucun payload JSON trouvé dans {} — lance depuis la racine du projet",
                payload_dir.display()));
            return;
        }

        // ── Endpoints à scanner ─────────────────────────────────────────────
        let endpoints_to_scan: Vec<(usize, ApiEndpoint)> = match ep_filter {
            None    => self.openapi_endpoints.iter().cloned().enumerate().collect(),
            Some(i) => self.openapi_endpoints.get(i)
                .map(|ep| vec![(i, ep.clone())]).unwrap_or_default(),
        };

        // ── Total de jobs ───────────────────────────────────────────────────
        let total_payloads: usize = payloads.iter().map(|(_, p)| p.len()).sum();
        let total: usize = endpoints_to_scan.iter()
            .map(|(_, ep)| {
                let n = ep.body_fields.len() + ep.query_params.len() + ep.path_params.len();
                // Endpoints sans aucun param détecté reçoivent un param fallback.
                let n = if n == 0 { 1 } else { n };
                n * total_payloads
            })
            .sum();

        // Scan All réinitialise le compteur ; Scan ep s'ajoute au compteur courant.
        self.openapi_jobs_skipped = 0;
        if ep_filter.is_none() {
            self.openapi_results.clear();
            self.openapi_selected_res = None;
            self.openapi_jobs_total = total;
        } else {
            self.openapi_jobs_total = self.openapi_results.len() + total;
        }

        if endpoints_to_scan.is_empty() {
            self.openapi_parse_status = Some("⚠ Aucun endpoint à scanner.".into());
            return;
        }

        self.openapi_scanning = true;
        self.openapi_parse_status = Some(format!(
            "↻ Scan en cours — {} catégories · {} requêtes",
            payloads.len(), total));

        let stop = Arc::new(AtomicBool::new(false));
        self.openapi_stop = Some(stop.clone());

        let (tx, rx) = std::sync::mpsc::sync_channel::<ScanMsg>(1024);
        self.openapi_rx = Some(rx);

        let creds    = self.openapi_creds.clone();
        let target   = self.openapi_target_url.trim().to_string();
        // Wrap in Arc so each endpoint task gets a cheap clone.
        let payloads = std::sync::Arc::new(payloads);

        self.rt.spawn(async move {
            use tokio::sync::Semaphore;

            let Some(parts) = crate::crawler::parse_url(&target) else {
                let _ = tx.send(ScanMsg::Finished);
                return;
            };
            let host = parts.host;
            let port = parts.port;
            let tls  = parts.tls;

            // One task per endpoint; up to 8 endpoints scan concurrently.
            // Within each endpoint task, payloads run sequentially so early-stop
            // is exact (no in-flight requests bypass the check).
            let sem = std::sync::Arc::new(Semaphore::new(8));
            let mut handles = Vec::new();

            for (ep_idx, ep) in endpoints_to_scan {
                if stop.load(Ordering::Relaxed) { break; }

                let permit    = sem.clone().acquire_owned().await.unwrap();
                let tx2       = tx.clone();
                let ep2       = ep.clone();
                let creds2    = creds.clone();
                let host2     = host.clone();
                let stop2     = stop.clone();
                let payloads2 = payloads.clone();

                handles.push(tokio::spawn(async move {
                    let _permit = permit;

                    let mut params: Vec<(String, ParamLoc)> = ep2.body_fields.iter()
                        .map(|f| (f.clone(), ParamLoc::Body))
                        .chain(ep2.query_params.iter().map(|q| (q.clone(), ParamLoc::Query)))
                        .chain(ep2.path_params.iter().map(|p| (p.clone(), ParamLoc::Path)))
                        .collect();
                    // Endpoint sans aucun paramètre détecté : on injecte via un
                    // query param générique pour ne jamais laisser un endpoint non testé.
                    if params.is_empty() {
                        let fallback = if matches!(ep2.method.to_uppercase().as_str(),
                            "POST" | "PUT" | "PATCH")
                        {
                            ("data".to_string(), ParamLoc::Body)
                        } else {
                            ("id".to_string(), ParamLoc::Query)
                        };
                        params.push(fallback);
                    }

                    // Test every payload on every parameter — no early stop.
                    'ep_loop: for (param, loc) in &params {
                        for (cat, plist) in payloads2.as_ref() {
                            if stop2.load(Ordering::Relaxed) { break 'ep_loop; }

                            let display_cat = crate::openapi::payload_cat_name(cat).to_string();

                            for payload in plist {
                                if stop2.load(Ordering::Relaxed) { break 'ep_loop; }

                                let raw = ep2.build_request_fuzzed(
                                    &host2, port, tls,
                                    creds2.cookie.as_deref().unwrap_or(""),
                                    creds2.bearer.as_deref().unwrap_or(""),
                                    creds2.api_key_header.as_deref().unwrap_or(""),
                                    creds2.api_key_value.as_deref().unwrap_or(""),
                                    param, loc, payload,
                                );
                                let raw_request = raw.clone();
                                let resp_bytes = crate::proxy::repeater_send(
                                    &host2, port, tls, raw).await;
                                let status: u16 = std::str::from_utf8(&resp_bytes)
                                    .unwrap_or("")
                                    .lines().next()
                                    .and_then(|l| l.split_whitespace().nth(1))
                                    .and_then(|s| s.parse().ok())
                                    .unwrap_or(0);

                                let evidence = {
                                    let ev = crate::rapport::check_reflected(
                                        &display_cat, payload, &resp_bytes, None);
                                    if crate::rapport::is_false_positive(&display_cat, status) {
                                        None
                                    } else {
                                        ev
                                    }
                                };

                                let _ = tx2.send(ScanMsg::Result(ScanResult {
                                    ep_idx,
                                    param:    param.clone(),
                                    loc:      loc.clone(),
                                    category: display_cat.clone(),
                                    payload:  payload.clone(),
                                    status,
                                    response:    resp_bytes,
                                    evidence,
                                    raw_request,
                                }));
                            }
                        }
                    }
                }));
            }

            for h in handles { let _ = h.await; }
            let _ = tx.send(ScanMsg::Finished);
        });
    }


    // ── Markdown report generation ────────────────────────────────────────────
    fn build_markdown_report(&self) -> String {
        use std::fmt::Write;

        let ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let (y, mo, d, h, mi, s) = unix_to_hms(ts);

        let target = &self.openapi_target_url;
        let total_reqs = self.openapi_results.len();
        let vulns: Vec<_> = self.openapi_results.iter()
            .filter(|r| r.evidence.is_some())
            .collect();
        let vuln_count = vulns.len();

        // Category → list of confirmed results
        let mut by_cat: std::collections::BTreeMap<&str, Vec<&crate::openapi::ScanResult>> =
            std::collections::BTreeMap::new();
        for r in &vulns {
            by_cat.entry(r.category.as_str()).or_default().push(r);
        }

        let mut md = String::new();

        // ── Cover ──────────────────────────────────────────────────────────────
        let _ = writeln!(md, "# Rapport de sécurité — Rustman OpenAPI Scanner");
        let _ = writeln!(md);
        let _ = writeln!(md, "| Champ | Valeur |");
        let _ = writeln!(md, "|---|---|");
        let _ = writeln!(md, "| **Cible** | `{target}` |");
        let _ = writeln!(md, "| **Date** | {y}-{mo:02}-{d:02} {h:02}:{mi:02}:{s:02} UTC |");
        let _ = writeln!(md, "| **Endpoints scannés** | {} |",
            self.openapi_endpoints.len());
        let _ = writeln!(md, "| **Requêtes envoyées** | {total_reqs} |");
        let _ = writeln!(md, "| **Vulnérabilités confirmées** | **{vuln_count}** |");
        let _ = writeln!(md);

        // ── Executive summary ──────────────────────────────────────────────────
        let _ = writeln!(md, "## Résumé des vulnérabilités");
        let _ = writeln!(md);
        if by_cat.is_empty() {
            let _ = writeln!(md, "> Aucune vulnérabilité confirmée lors de ce scan.");
        } else {
            let _ = writeln!(md, "| Catégorie | Occurrences | Sévérité |");
            let _ = writeln!(md, "|---|---|---|");
            for (cat, results) in &by_cat {
                let sev = category_severity(cat);
                let _ = writeln!(md, "| **{cat}** | {} | {sev} |", results.len());
            }
        }
        let _ = writeln!(md);

        // ── Detailed findings ──────────────────────────────────────────────────
        if !by_cat.is_empty() {
            let _ = writeln!(md, "## Détail des vulnérabilités");
            let _ = writeln!(md);

            let mut finding_idx = 1usize;
            for (cat, results) in &by_cat {
                for r in results {
                    // Endpoint path
                    let ep_path = self.openapi_endpoints.get(r.ep_idx)
                        .map(|ep| format!("{} {}", ep.method, ep.path))
                        .unwrap_or_else(|| "Endpoint inconnu".into());

                    let loc_s = match r.loc {
                        crate::openapi::ParamLoc::Body  => "body",
                        crate::openapi::ParamLoc::Query => "query param",
                        crate::openapi::ParamLoc::Path  => "path param",
                    };
                    let sev = category_severity(cat);
                    let ev = r.evidence.as_deref().unwrap_or("—");

                    let _ = writeln!(md, "### Finding #{finding_idx} — {cat} ({sev})");
                    let _ = writeln!(md);
                    let _ = writeln!(md, "| Champ | Valeur |");
                    let _ = writeln!(md, "|---|---|");
                    let _ = writeln!(md, "| **Endpoint** | `{ep_path}` |");
                    let _ = writeln!(md, "| **Paramètre** | `{}` ({loc_s}) |", r.param);
                    let _ = writeln!(md, "| **Payload** | `{}` |", r.payload.replace('|', "\\|"));
                    let _ = writeln!(md, "| **Code HTTP** | {} |", r.status);
                    let _ = writeln!(md, "| **Preuve** | `{}` |", ev.replace('|', "\\|"));
                    let _ = writeln!(md);

                    // Full raw request
                    let _ = writeln!(md, "#### Requête HTTP complète");
                    let _ = writeln!(md);
                    let req_txt = if !r.raw_request.is_empty() {
                        String::from_utf8_lossy(&r.raw_request).into_owned()
                    } else {
                        // Rebuild it from endpoint + payload
                        self.openapi_endpoints.get(r.ep_idx)
                            .and_then(|ep| {
                                crate::crawler::parse_url(target).map(|parts| {
                                    let raw = ep.build_request_fuzzed(
                                        &parts.host, parts.port, parts.tls,
                                        self.openapi_creds.cookie.as_deref().unwrap_or(""),
                                        self.openapi_creds.bearer.as_deref().unwrap_or(""),
                                        self.openapi_creds.api_key_header.as_deref().unwrap_or(""),
                                        self.openapi_creds.api_key_value.as_deref().unwrap_or(""),
                                        &r.param, &r.loc, &r.payload,
                                    );
                                    String::from_utf8_lossy(&raw).into_owned()
                                })
                            })
                            .unwrap_or_else(|| "Requête non disponible".into())
                    };
                    let _ = writeln!(md, "```http");
                    let _ = writeln!(md, "{}", req_txt.trim_end());
                    let _ = writeln!(md, "```");
                    let _ = writeln!(md);

                    // Remediation
                    let _ = writeln!(md, "#### Remédiation");
                    let _ = writeln!(md);
                    let _ = writeln!(md, "{}", category_remediation(cat));
                    let _ = writeln!(md);
                    let _ = writeln!(md, "---");
                    let _ = writeln!(md);

                    finding_idx += 1;
                }
            }
        }

        // ── All endpoints scanned ──────────────────────────────────────────────
        let _ = writeln!(md, "## Endpoints scannés");
        let _ = writeln!(md);
        let _ = writeln!(md, "| Méthode | Chemin | Paramètres | Vulnérabilités |");
        let _ = writeln!(md, "|---|---|---|---|");
        for (i, ep) in self.openapi_endpoints.iter().enumerate() {
            let params: Vec<String> = ep.body_fields.iter()
                .map(|f| format!("`{f}` (body)"))
                .chain(ep.query_params.iter().map(|q| format!("`{q}` (query)")))
                .collect();
            let params_str = if params.is_empty() {
                "—".into()
            } else {
                params.join(", ")
            };
            let ep_vulns: Vec<String> = self.openapi_results.iter()
                .filter(|r| r.ep_idx == i && r.evidence.is_some())
                .map(|r| format!("{} ({})", r.category, r.param))
                .collect();
            let vuln_str = if ep_vulns.is_empty() {
                "—".into()
            } else {
                ep_vulns.join(", ")
            };
            let _ = writeln!(md, "| **{}** | `{}` | {} | {} |",
                ep.method, ep.path, params_str, vuln_str);
        }
        let _ = writeln!(md);
        let _ = writeln!(md, "---");
        let _ = writeln!(md);
        let _ = writeln!(md, "*Rapport généré par **Rustman** — scanner de sécurité OpenAPI*");

        md
    }

    // ── Settings tab ─────────────────────────────────────────────────────────
    fn draw_settings(&mut self, ctx: &egui::Context) {
        egui::CentralPanel::default().show(ctx, |ui| {
            ScrollArea::vertical().show(ui, |ui| {
                ui.add_space(16.0);
                ui.set_max_width(680.0);

                // ── Appearance ───────────────────────────────────────────
                section_header(ui, "APPEARANCE");
                ui.add_space(6.0);
                {
                    let mut s = self.state.lock().unwrap();
                    ui.checkbox(
                        &mut s.settings.light_mode,
                        RichText::new("Light mode").size(13.0),
                    );
                }
                ui.add_space(20.0);

                // ── Interception ──────────────────────────────────────────
                section_header(ui, "INTERCEPTION");
                ui.add_space(6.0);
                {
                    let mut s = self.state.lock().unwrap();
                    ui.checkbox(
                        &mut s.settings.intercept_enabled,
                        RichText::new("Intercept requests").size(13.0),
                    );
                    if !s.settings.intercept_enabled {
                        ui.add_space(2.0);
                        ui.colored_label(
                            Color32::from_rgb(255, 180, 60),
                            "  All requests are forwarded automatically — nothing appears in the list.",
                        );
                    }
                }
                ui.add_space(20.0);

                // ── Ignore list ───────────────────────────────────────────
                section_header(ui, "IGNORE LIST");
                ui.add_space(2.0);
                ui.colored_label(
                    Color32::DARK_GRAY,
                    "Hosts matching any pattern (case-insensitive substring) are silently forwarded.",
                );
                ui.add_space(8.0);

                let ignore_hosts: Vec<String> = {
                    self.state.lock().unwrap().settings.ignore_hosts.clone()
                };

                let mut to_remove: Option<usize> = None;
                for (i, pat) in ignore_hosts.iter().enumerate() {
                    ui.horizontal(|ui| {
                        if ui.small_button("✕")
                            .on_hover_text("Remove")
                            .clicked()
                        {
                            to_remove = Some(i);
                        }
                        ui.add_space(4.0);
                        ui.label(
                            RichText::new(pat).monospace().color(Color32::from_rgb(200, 200, 220)),
                        );
                    });
                }
                if let Some(i) = to_remove {
                    self.state.lock().unwrap().settings.ignore_hosts.remove(i);
                }

                ui.add_space(6.0);
                ui.horizontal(|ui| {
                    let te = TextEdit::singleline(&mut self.settings_ignore_input)
                        .hint_text("hostname or pattern  (e.g. analytics, cdn., telemetry)")
                        .desired_width(320.0)
                        .font(egui::TextStyle::Monospace);
                    let resp = ui.add(te);

                    let commit = ui.button("+ Add").clicked()
                        || (resp.lost_focus()
                            && ui.input(|i| i.key_pressed(egui::Key::Enter)));

                    if commit {
                        let pat = self.settings_ignore_input.trim().to_ascii_lowercase();
                        if !pat.is_empty() {
                            self.state.lock().unwrap().settings.ignore_hosts.push(pat);
                            self.settings_ignore_input.clear();
                        }
                        resp.request_focus();
                    }
                });
                ui.add_space(20.0);

                // ── Proxy ─────────────────────────────────────────────────
                section_header(ui, "PROXY");
                ui.add_space(6.0);

                let (cur_addr, cur_port, restarting) = {
                    let s = self.state.lock().unwrap();
                    (s.settings.proxy_addr.clone(), s.settings.proxy_port, s.proxy_restarting)
                };

                // Sync local fields with actual values on first open / after restart.
                if !restarting {
                    if self.settings_proxy_addr.is_empty() {
                        self.settings_proxy_addr = cur_addr.clone();
                    }
                    if self.settings_proxy_port == 8080 && cur_port != 8080 {
                        self.settings_proxy_port = cur_port;
                    }
                }

                ui.horizontal(|ui| {
                    ui.colored_label(Color32::GRAY, "Address:");
                    ui.add_space(6.0);
                    ui.add(
                        TextEdit::singleline(&mut self.settings_proxy_addr)
                            .hint_text("127.0.0.1  or  0.0.0.0")
                            .desired_width(160.0)
                            .font(egui::TextStyle::Monospace),
                    );
                    ui.add_space(8.0);
                    ui.colored_label(Color32::GRAY, "Port:");
                    ui.add_space(6.0);
                    ui.add(
                        egui::DragValue::new(&mut self.settings_proxy_port)
                            .range(1024..=65535)
                            .speed(1.0),
                    );
                });

                ui.add_space(8.0);
                ui.horizontal(|ui| {
                    let addr_trim = self.settings_proxy_addr.trim().to_string();
                    let changed = addr_trim != cur_addr || self.settings_proxy_port != cur_port;
                    let valid   = !addr_trim.is_empty();

                    let btn_text = if restarting { "↻  Restarting…" } else { "Apply" };
                    let btn = egui::Button::new(
                        RichText::new(btn_text).size(12.0).color(Color32::WHITE),
                    )
                    .fill(if restarting || !changed || !valid {
                        Color32::from_rgb(50, 50, 60)
                    } else {
                        Color32::from_rgb(200, 110, 25)
                    });

                    let enabled = changed && !restarting && valid;
                    if ui.add_enabled(enabled, btn).clicked() {
                        let new_addr = addr_trim;
                        let new_port = self.settings_proxy_port;
                        let mut s = self.state.lock().unwrap();
                        s.proxy_restarting = true;
                        if let Some(tx) = &s.proxy_restart_tx {
                            let _ = tx.try_send((new_addr, new_port));
                        }
                    }

                    ui.add_space(10.0);
                    if restarting {
                        ui.colored_label(Color32::from_rgb(255, 160, 60), "↻ Restarting proxy…");
                    } else {
                        ui.colored_label(
                            Color32::from_rgb(80, 200, 80),
                            format!("Active  {cur_addr}:{cur_port}"),
                        );
                    }
                });

                ui.add_space(4.0);
                ui.colored_label(
                    Color32::DARK_GRAY,
                    "Use 0.0.0.0 to listen on all interfaces. Existing connections are dropped on restart.",
                );
                ui.add_space(20.0);

                // ── Claude API ────────────────────────────────────────────
                section_header(ui, "CLAUDE API");
                ui.add_space(6.0);
                ui.horizontal(|ui| {
                    ui.label("API Key:");
                    ui.add_space(4.0);
                    let mut s = self.state.lock().unwrap();
                    ui.add(
                        TextEdit::singleline(&mut s.settings.api_key)
                            .hint_text("sk-ant-…")
                            .password(true)
                            .desired_width(320.0)
                            .font(egui::TextStyle::Monospace),
                    );
                });
                ui.add_space(2.0);
                ui.colored_label(
                    Color32::DARK_GRAY,
                    "Used by the Claude tab to call the Anthropic API directly.",
                );
                ui.add_space(20.0);

                // ── Requests ──────────────────────────────────────────────
                section_header(ui, "REQUESTS");
                ui.add_space(6.0);
                ui.horizontal(|ui| {
                    ui.label("Max requests in list:");
                    ui.add_space(8.0);
                    let mut s = self.state.lock().unwrap();
                    ui.add(
                        egui::DragValue::new(&mut s.settings.max_requests)
                            .range(10..=5000)
                            .speed(1.0),
                    );
                });
                ui.add_space(2.0);
                ui.colored_label(
                    Color32::DARK_GRAY,
                    "When the limit is reached, the oldest completed request is removed.",
                );
            });
        });
    }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

/// Extract all fenced code blocks (``` ... ```) from a markdown-ish string.
/// Returns the concatenated code. If none found, returns an empty string.
fn extract_code_blocks(text: &str) -> String {
    let mut result = String::new();
    let mut in_block = false;
    let mut block_buf = String::new();

    for line in text.lines() {
        if line.trim_start().starts_with("```") {
            if in_block {
                if !result.is_empty() {
                    result.push_str("\n\n");
                }
                result.push_str(block_buf.trim_end());
                block_buf.clear();
                in_block = false;
            } else {
                in_block = true;
            }
        } else if in_block {
            block_buf.push_str(line);
            block_buf.push('\n');
        }
    }

    result
}

/// Render a message, highlighting fenced code blocks with a dark background.
fn render_message_with_code(ui: &mut egui::Ui, text: &str, msg_idx: usize) {
    let mut in_block = false;
    let mut block_buf = String::new();
    let mut plain_buf = String::new();
    let mut block_count = 0usize;

    let flush_plain = |ui: &mut egui::Ui, buf: &mut String| {
        let t = buf.trim_end();
        if !t.is_empty() {
            ui.label(
                RichText::new(t)
                    .size(13.0)
                    .color(Color32::from_rgb(200, 220, 190)),
            );
        }
        buf.clear();
    };

    for line in text.lines() {
        if line.trim_start().starts_with("```") {
            if in_block {
                flush_plain(ui, &mut plain_buf);
                let code = block_buf.trim_end().to_owned();
                if !code.is_empty() {
                    egui::Frame::none()
                        .fill(Color32::from_rgb(16, 18, 24))
                        .rounding(4.0)
                        .inner_margin(egui::Margin::symmetric(8.0, 6.0))
                        .show(ui, |ui| {
                            let mut c = code.clone();
                            ui.add(
                                TextEdit::multiline(&mut c)
                                    .font(egui::TextStyle::Monospace)
                                    .desired_width(f32::INFINITY)
                                    .interactive(true)
                                    .frame(false)
                                    .text_color(Color32::from_rgb(140, 220, 140))
                                    .id(egui::Id::new((
                                        "exploit_code_block",
                                        msg_idx,
                                        block_count,
                                    ))),
                            );
                        });
                    block_count += 1;
                }
                block_buf.clear();
                in_block = false;
            } else {
                flush_plain(ui, &mut plain_buf);
                in_block = true;
            }
        } else if in_block {
            block_buf.push_str(line);
            block_buf.push('\n');
        } else {
            plain_buf.push_str(line);
            plain_buf.push('\n');
        }
    }

    flush_plain(ui, &mut plain_buf);

    // unclosed block (shouldn't happen but handle gracefully)
    if !block_buf.trim().is_empty() {
        let mut c = block_buf.trim_end().to_owned();
        egui::Frame::none()
            .fill(Color32::from_rgb(16, 18, 24))
            .rounding(4.0)
            .inner_margin(egui::Margin::symmetric(8.0, 6.0))
            .show(ui, |ui| {
                ui.add(
                    TextEdit::multiline(&mut c)
                        .font(egui::TextStyle::Monospace)
                        .desired_width(f32::INFINITY)
                        .interactive(true)
                        .frame(false)
                        .text_color(Color32::from_rgb(140, 220, 140))
                        .id(egui::Id::new(("exploit_code_block_tail", msg_idx))),
                );
            });
    }
}

// ── Report helpers ────────────────────────────────────────────────────────────

fn unix_to_hms(ts: u64) -> (u64, u64, u64, u64, u64, u64) {
    let s  = ts % 60;
    let mi = (ts / 60) % 60;
    let h  = (ts / 3600) % 24;
    let days = ts / 86400;
    // Days since 1970-01-01 → year/month/day
    let (y, rem) = days_since_epoch(days);
    let leap = (y % 4 == 0 && y % 100 != 0) || y % 400 == 0;
    let month_days: &[u64] = if leap {
        &[31,29,31,30,31,30,31,31,30,31,30,31]
    } else {
        &[31,28,31,30,31,30,31,31,30,31,30,31]
    };
    let mut d_rem = rem;
    let mut mo = 1u64;
    for &md in month_days {
        if d_rem < md { break; }
        d_rem -= md;
        mo += 1;
    }
    (y, mo, d_rem + 1, h, mi, s)
}

fn days_since_epoch(mut days: u64) -> (u64, u64) {
    let mut y = 1970u64;
    loop {
        let dy = if (y % 4 == 0 && y % 100 != 0) || y % 400 == 0 { 366 } else { 365 };
        if days < dy { return (y, days); }
        days -= dy;
        y += 1;
    }
}

fn category_severity(cat: &str) -> &'static str {
    match cat {
        "CMDi" | "RCE"          => "🔴 Critique",
        "SQLi" | "PathTraversal" => "🔴 Élevée",
        "SSRF" | "SSTI"         => "🟠 Élevée",
        "XSS"                   => "🟡 Moyenne",
        "OpenRedirect"          => "🟡 Faible",
        _                       => "⚪ Inconnue",
    }
}

fn category_remediation(cat: &str) -> &'static str {
    match cat {
        "CMDi" => "\
Ne jamais passer des entrées utilisateur directement à un interpréteur de commandes shell.\n\
- Utiliser des API natives du langage plutôt que `system()`, `exec()`, `popen()`.\n\
- Si une commande est inévitable, utiliser une liste d'arguments (pas une chaîne) et valider chaque argument contre une allowlist stricte.\n\
- Exécuter le processus avec les privilèges minimaux nécessaires (principe de moindre privilège).",

        "RCE" => "\
L'exécution de code arbitraire côté serveur représente une compromission totale.\n\
- Désérialiser uniquement des données fiables avec des types stricts et sans polymorphisme.\n\
- Mettre à jour immédiatement les dépendances vulnérables.\n\
- Appliquer une sandbox (seccomp, AppArmor) pour limiter les appels système disponibles.\n\
- Auditer les routes qui évaluent dynamiquement du code (`eval`, `exec`, réflexion Java).",

        "SQLi" => "\
Toujours utiliser des requêtes préparées (prepared statements) avec des paramètres liés.\n\
- Ne jamais construire des requêtes SQL par concaténation de chaînes.\n\
- Appliquer le principe de moindre privilège sur le compte de base de données.\n\
- Activer le mode strict de l'ORM si applicable.\n\
- Ne jamais exposer les messages d'erreur SQL à l'utilisateur final.",

        "PathTraversal" => "\
Valider et normaliser tout chemin de fichier avant utilisation.\n\
- Appeler `Path::canonicalize()` / `realpath()` puis vérifier que le chemin résultant commence par le répertoire autorisé.\n\
- Utiliser une allowlist d'extensions de fichiers acceptées.\n\
- Ne jamais construire un chemin à partir d'une entrée brute (`../`).\n\
- Isoler les fichiers sensibles hors de la racine web.",

        "XSS" => "\
Échapper toutes les données insérées dans du HTML, JavaScript, CSS ou des attributs.\n\
- Utiliser un moteur de template qui échappe par défaut (e.g. Jinja2 autoescape, React JSX).\n\
- Définir un Content-Security-Policy (CSP) restrictif (`default-src 'self'`).\n\
- Pour les APIs JSON, forcer `Content-Type: application/json` afin que les navigateurs n'interprètent pas la réponse comme HTML.\n\
- Valider et assainir les entrées utilisateur côté serveur.",

        "SSRF" => "\
Ne jamais effectuer de requêtes HTTP vers des URL fournies par l'utilisateur sans validation stricte.\n\
- Maintenir une allowlist d'hôtes et de ports autorisés.\n\
- Bloquer les plages d'adresses privées (127.0.0.0/8, 10.0.0.0/8, 169.254.0.0/16) au niveau réseau et applicatif.\n\
- Résoudre le DNS après validation et vérifier que l'IP résolue est dans l'allowlist.\n\
- Désactiver les redirections HTTP automatiques ou les limiter à des domaines autorisés.",

        "SSTI" => "\
Ne jamais rendre des templates construits à partir d'entrées utilisateur.\n\
- Utiliser uniquement des templates statiques avec des variables injectées via le contexte.\n\
- Si du contenu dynamique est indispensable, utiliser un moteur sandbox sans accès aux objets système (`SandboxedEnvironment` en Jinja2).\n\
- Valider et rejeter toute entrée contenant des caractères de délimitation de template (`{{`, `{%`, `${`, `<%`).",

        "OpenRedirect" => "\
Ne jamais rediriger vers une URL fournie directement par l'utilisateur.\n\
- Utiliser des identifiants opaques (token, index) mappés côté serveur vers les URLs autorisées.\n\
- Si une URL est nécessaire, valider qu'elle appartient à la liste d'hôtes autorisés.\n\
- Ajouter un avertissement intermédiaire lorsqu'une redirection externe est inévitable.",

        _ => "Valider et assainir toutes les entrées utilisateur. Appliquer le principe de moindre privilège.",
    }
}

fn entry_color_code(entry: &crate::crawler::CrawlerEntry) -> (Color32, String) {
    use crate::crawler::EntryStatus;
    match &entry.status {
        EntryStatus::Fetching => (Color32::from_rgb(255, 160, 60), "↻".into()),
        EntryStatus::Done(code, _) => {
            let color = match code {
                200..=299 => Color32::from_rgb(80, 200, 100),
                300..=399 => Color32::from_rgb(255, 210, 50),
                400..=499 => Color32::from_rgb(255, 140, 50),
                _ => Color32::from_rgb(220, 70, 70),
            };
            (color, code.to_string())
        }
        EntryStatus::Failed(_) => (Color32::from_rgb(180, 50, 50), "ERR".into()),
    }
}

fn section_header(ui: &mut egui::Ui, title: &str) {
    ui.label(
        RichText::new(title)
            .size(10.5)
            .strong()
            .color(Color32::from_rgb(100, 120, 160)),
    );
    ui.add(egui::Separator::default().spacing(4.0));
}

fn status_indicator(s: &Status) -> (Color32, &'static str) {
    match s {
        Status::Pending => (Color32::from_rgb(255, 210, 50), "●"),
        Status::Forwarding => (Color32::from_rgb(255, 160, 60), "→"),
        Status::Forwarded => (Color32::from_rgb(80, 200, 100), "✓"),
        Status::Dropped => (Color32::from_rgb(220, 70, 70), "✗"),
    }
}

fn method_color(m: &str) -> Color32 {
    match m {
        "GET" => Color32::from_rgb(90, 170, 255),
        "POST" => Color32::from_rgb(255, 165, 80),
        "PUT" => Color32::from_rgb(240, 210, 80),
        "DELETE" => Color32::from_rgb(230, 80, 80),
        "PATCH" => Color32::from_rgb(140, 230, 140),
        "OPTIONS" => Color32::from_rgb(170, 170, 255),
        "HEAD" => Color32::from_rgb(170, 230, 230),
        _ => Color32::from_rgb(160, 160, 170),
    }
}

fn trunc(s: &str, max: usize) -> String {
    let s = s.trim();
    if s.len() > max {
        format!("{}…", &s[..max - 1])
    } else {
        s.to_string()
    }
}

fn dark_theme() -> egui::Visuals {
    let mut v = egui::Visuals::dark();
    v.panel_fill = Color32::from_rgb(18, 18, 22);
    v.window_fill = Color32::from_rgb(22, 22, 28);
    v.extreme_bg_color = Color32::from_rgb(12, 12, 16);
    v.widgets.noninteractive.bg_fill = Color32::from_rgb(28, 28, 34);
    v.widgets.inactive.bg_fill = Color32::from_rgb(35, 35, 44);
    v.widgets.hovered.bg_fill = Color32::from_rgb(50, 50, 65);
    v.widgets.active.bg_fill = Color32::from_rgb(60, 60, 80);
    v
}

fn light_theme() -> egui::Visuals {
    let mut v = egui::Visuals::light();
    v.panel_fill = Color32::from_rgb(245, 246, 250);
    v.window_fill = Color32::from_rgb(255, 255, 255);
    v.extreme_bg_color = Color32::from_rgb(230, 232, 240);
    v.widgets.noninteractive.bg_fill = Color32::from_rgb(235, 237, 245);
    v.widgets.inactive.bg_fill = Color32::from_rgb(225, 228, 238);
    v.widgets.hovered.bg_fill = Color32::from_rgb(210, 215, 232);
    v.widgets.active.bg_fill = Color32::from_rgb(195, 202, 225);
    v
}
