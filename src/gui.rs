use crate::app::{Shared, Status};
use eframe::egui::{self, Color32, RichText, ScrollArea, TextEdit, Vec2};
use std::sync::Arc;

pub fn run(state: Shared, rt: Arc<tokio::runtime::Runtime>) -> Result<(), eframe::Error> {
    let opts = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_title("RUSTMAN")
            .with_inner_size([1300.0, 760.0])
            .with_min_inner_size([900.0, 500.0]),
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
    Settings,
    Claude,
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

// ── App state (GUI-local) ─────────────────────────────────────────────────────

struct RustmanApp {
    state: Shared,
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
    // Claude tab
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
    crawler_attacks: Vec<crate::crawler::AttackVariant>,
}

impl RustmanApp {
    fn new(state: Shared, rt: Arc<tokio::runtime::Runtime>) -> Self {
        Self {
            state,
            selected: None,
            edit_buf: String::new(),
            dirty: false,
            tab: ActiveTab::Proxy,
            repeater: Vec::new(),
            rep_next_id: 0,
            rep_selected: None,
            rt,
            settings_ignore_input: String::new(),
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
            crawler_attacks: Vec::new(),
        }
    }

    fn sync_selection(&mut self) {
        let s = self.state.lock().unwrap();
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

    fn poll_repeater(&mut self) {
        for sess in &mut self.repeater {
            if let Some(rx) = &sess.pending {
                if let Ok(bytes) = rx.try_recv() {
                    sess.response = Some(String::from_utf8_lossy(&bytes).into_owned());
                    sess.pending = None;
                }
            }
        }
    }

    fn poll_crawler(&mut self) {
        use crate::crawler::{CrawlMsg, EntryStatus};
        let rx = match &self.crawler_rx {
            Some(r) => r,
            None => return,
        };
        loop {
            match rx.try_recv() {
                Ok(CrawlMsg::Visiting {
                    url,
                    depth,
                    request,
                }) => {
                    self.crawler_entries.push(crate::crawler::CrawlerEntry {
                        url,
                        depth,
                        status: EntryStatus::Fetching,
                        request,
                        response: Vec::new(),
                    });
                }
                Ok(CrawlMsg::Done {
                    url,
                    status,
                    new_links,
                    response,
                }) => {
                    if let Some(e) = self.crawler_entries.iter_mut().rfind(|e| e.url == url) {
                        e.status = EntryStatus::Done(status, new_links);
                        e.response = response;
                    }
                }
                Ok(CrawlMsg::Failed { url, reason }) => {
                    if let Some(e) = self.crawler_entries.iter_mut().rfind(|e| e.url == url) {
                        e.status = EntryStatus::Failed(reason);
                    } else {
                        self.crawler_entries.push(crate::crawler::CrawlerEntry {
                            url,
                            depth: 0,
                            status: EntryStatus::Failed(reason),
                            request: Vec::new(),
                            response: Vec::new(),
                        });
                    }
                }
                Ok(CrawlMsg::Attack { variant }) => {
                    self.crawler_attacks.extend(variant);
                }
                Ok(CrawlMsg::Finished) => {
                    self.crawler_running = false;
                    self.crawler_rx = None;
                    break;
                }
                Err(_) => break,
            }
        }
    }

    fn poll_claude(&mut self) {
        if let Some(rx) = &self.claude_rx {
            if let Ok(result) = rx.try_recv() {
                let text = match result {
                    Ok(t) => t,
                    Err(e) => format!("Error: {e}"),
                };
                self.state.lock().unwrap().chat_messages.push(crate::app::ChatMessage {
                    from_user: false,
                    text,
                });
                self.claude_thinking = false;
                self.claude_rx = None;
            }
        }
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
        ctx.request_repaint_after(std::time::Duration::from_millis(40));
        {
            let light = self.state.lock().unwrap().settings.light_mode;
            ctx.set_visuals(if light { light_theme() } else { dark_theme() });
        }
        self.sync_selection();
        self.poll_repeater();
        self.poll_crawler();
        self.poll_claude();

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
            ActiveTab::Claude => {
                self.draw_claude(ctx);
            }
        }
    }
}

impl RustmanApp {
    // ── Top toolbar ───────────────────────────────────────────────────────────
    fn draw_topbar(&mut self, ctx: &egui::Context) {
        egui::TopBottomPanel::top("topbar")
            .exact_height(38.0)
            .show(ctx, |ui| {
                ui.horizontal_centered(|ui| {
                    ui.label(
                        RichText::new("rustman")
                            .size(17.0)
                            .strong()
                            .color(Color32::from_rgb(64, 192, 255)),
                    );
                    ui.label(
                        RichText::new("127.0.0.1:8080")
                            .size(12.0)
                            .color(Color32::GRAY),
                    );

                    ui.separator();

                    // Tab buttons
                    let proxy_btn = egui::SelectableLabel::new(
                        self.tab == ActiveTab::Proxy,
                        RichText::new("Proxy").size(13.0),
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
                        RichText::new(rep_label).size(13.0),
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
                        RichText::new(crawl_label).size(13.0),
                    );
                    if ui.add(crawl_btn).clicked() {
                        self.tab = ActiveTab::Crawler;
                    }

                    let settings_btn = egui::SelectableLabel::new(
                        self.tab == ActiveTab::Settings,
                        RichText::new("Settings").size(13.0),
                    );
                    if ui.add(settings_btn).clicked() {
                        self.tab = ActiveTab::Settings;
                    }

                    let has_pending = self.state.lock().unwrap().pending_prompt.is_some();
                    let claude_label = if has_pending { "Claude ●" } else { "Claude" };
                    let claude_btn = egui::SelectableLabel::new(
                        self.tab == ActiveTab::Claude,
                        RichText::new(claude_label)
                            .size(13.0)
                            .color(if has_pending {
                                Color32::from_rgb(80, 200, 255)
                            } else {
                                Color32::GRAY
                            }),
                    );
                    if ui.add(claude_btn).clicked() {
                        self.tab = ActiveTab::Claude;
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
                        let port = s.settings.proxy_port;
                        let n = s.settings.ignore_hosts.len();
                        format!("  Settings  ·  proxy 127.0.0.1:{port}  ·  {n} ignore rule(s)")
                    }
                    ActiveTab::Claude => {
                        let s = self.state.lock().unwrap();
                        let n = s.chat_messages.len();
                        let pending = if s.pending_prompt.is_some() { "  ·  waiting for Claude…" } else { "" };
                        format!("  Claude  ·  {n} message(s){pending}")
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
                                Color32::from_rgb(45, 50, 82)
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
                                Color32::from_rgb(45, 50, 82)
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
                                        ui.colored_label(Color32::from_rgb(50, 200, 255), "↻");
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
                            Color32::from_rgb(50, 100, 140)
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
                            ui.colored_label(Color32::from_rgb(50, 200, 255), "  ↻");
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
                            self.crawler_attacks.clear();
                            self.crawler_selected = None;
                            self.crawler_running = true;

                            let stop = Arc::new(AtomicBool::new(false));
                            self.crawler_stop = Some(stop.clone());

                            let (tx, rx) = std::sync::mpsc::sync_channel(512);
                            self.crawler_rx = Some(rx);

                            let url   = self.crawler_url.trim().to_string();
                            let depth = self.crawler_max_depth;
                            self.rt.spawn(async move {
                                crate::crawler::run(url, depth, stop, tx).await;
                            });
                        }

                        if !self.crawler_entries.is_empty() {
                            ui.add_space(4.0);
                            if ui.button(RichText::new("Clear").color(Color32::from_rgb(150, 150, 150))).clicked() {
                                self.crawler_entries.clear();
                                self.crawler_attacks.clear();
                                self.crawler_selected = None;
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
                            ui.colored_label(Color32::from_rgb(50, 200, 255), format!("↻ {active}"));
                        }
                    });
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
                                Color32::from_rgb(45, 50, 82)
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
                                        EntryStatus::Fetching     => Color32::from_rgb(50, 200, 255),
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
            let req_h = if has_resp {
                available_h * 0.40
            } else {
                available_h
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
                        .max_height(available_h * 0.54)
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

    // ── Claude tab ────────────────────────────────────────────────────────────
    fn draw_claude(&mut self, ctx: &egui::Context) {
        egui::CentralPanel::default().show(ctx, |ui| {
            ui.vertical(|ui| {
                // ── Header ────────────────────────────────────────────────
                ui.add_space(8.0);
                ui.horizontal(|ui| {
                    ui.add_space(8.0);
                    ui.label(
                        RichText::new("Claude")
                            .size(15.0)
                            .strong()
                            .color(Color32::from_rgb(80, 180, 255)),
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
                                        .fill(Color32::from_rgb(35, 60, 100))
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
                                    Color32::from_rgb(50, 200, 255),
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
                                Color32::from_rgb(60, 70, 90)
                            } else {
                                Color32::from_rgb(60, 130, 200)
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
                                // Build conversation history for the API
                                let history: Vec<serde_json::Value> = self
                                    .state
                                    .lock()
                                    .unwrap()
                                    .chat_messages
                                    .iter()
                                    .map(|m| serde_json::json!({
                                        "role": if m.from_user { "user" } else { "assistant" },
                                        "content": m.text,
                                    }))
                                    .collect();

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
                let port = self.state.lock().unwrap().settings.proxy_port;
                ui.horizontal(|ui| {
                    ui.colored_label(Color32::GRAY, "Listening on");
                    ui.add_space(4.0);
                    ui.label(
                        RichText::new(format!("127.0.0.1:{port}"))
                            .monospace()
                            .color(Color32::WHITE),
                    );
                });
                ui.add_space(2.0);
                ui.colored_label(
                    Color32::DARK_GRAY,
                    "To change the port, restart rustman with a different value.",
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

fn entry_color_code(entry: &crate::crawler::CrawlerEntry) -> (Color32, String) {
    use crate::crawler::EntryStatus;
    match &entry.status {
        EntryStatus::Fetching => (Color32::from_rgb(50, 200, 255), "↻".into()),
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
        Status::Forwarding => (Color32::from_rgb(50, 200, 255), "→"),
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
