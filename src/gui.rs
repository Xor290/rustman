use eframe::egui::{self, Color32, RichText, ScrollArea, TextEdit, Vec2};
use std::sync::Arc;
use crate::app::{Shared, Status};

pub fn run(state: Shared, rt: Arc<tokio::runtime::Runtime>) -> Result<(), eframe::Error> {
    let opts = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_title("rustman — MITM Proxy")
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
enum ActiveTab { Proxy, Repeater }

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

    fn send_selected_to_repeater(&mut self) {
        let idx = match self.selected { Some(i) => i, None => return };
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
        self.sync_selection();
        self.poll_repeater();

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
                        RichText::new("  MITM Proxy  ·  127.0.0.1:8080")
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
                            if ui.button(RichText::new("Clear done").color(Color32::from_rgb(150, 150, 150))).clicked() {
                                self.state.lock().unwrap().clear_done();
                                self.selected = None;
                                self.edit_buf.clear();
                                self.dirty = false;
                            }
                            ui.add_space(8.0);
                            if ui.button(RichText::new("▶ Forward All").color(Color32::from_rgb(100, 220, 100))).clicked() {
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

            let (id, status, method, host, port, tls, resp_text) = {
                let s = self.state.lock().unwrap();
                match s.requests.get(idx) {
                    Some(r) => (
                        r.id,
                        r.status.clone(),
                        r.method.clone(),
                        r.host.clone(),
                        r.port,
                        r.tls,
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
                        RichText::new("  ▶  Forward  ").size(13.0).color(Color32::BLACK),
                    )
                    .fill(Color32::from_rgb(60, 180, 80));

                    if ui.add(fwd_btn).clicked() {
                        let bytes = self.edit_buf.as_bytes().to_vec();
                        self.state.lock().unwrap().forward_at(idx, bytes);
                        self.dirty = false;
                    }

                    ui.add_space(8.0);

                    let drop_btn = egui::Button::new(
                        RichText::new("  ✗  Drop  ").size(13.0).color(Color32::WHITE),
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
                    RichText::new("  → Repeater  ").size(12.0).color(Color32::from_rgb(180, 220, 255)),
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
            let req_h = if has_response { available_h * 0.52 } else { available_h };

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
                            self.state.lock().unwrap().set_edited(
                                id,
                                self.edit_buf.as_bytes().to_vec(),
                            );
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

                            let row_h   = 28.0;
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
                (s.label.clone(), s.host.clone(), s.port, s.tls, s.pending.is_some())
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

                let send_label = if is_sending { "  ↻  Sending…  " } else { "  ▶  Send  " };
                let send_btn = egui::Button::new(
                    RichText::new(send_label).size(13.0).color(Color32::BLACK),
                )
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
                        let resp = crate::proxy::repeater_send(&host_clone, port, tls, req_bytes).await;
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
            let has_response = self.repeater[sel].response.as_deref().is_some_and(|r| !r.is_empty());
            let req_h = if has_response { available_h * 0.50 } else { available_h };

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
                    ui.colored_label(
                        Color32::from_rgb(80, 80, 100),
                        "  (edit and Send)",
                    );
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
}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn status_indicator(s: &Status) -> (Color32, &'static str) {
    match s {
        Status::Pending    => (Color32::from_rgb(255, 210, 50),  "●"),
        Status::Forwarding => (Color32::from_rgb(50, 200, 255),  "→"),
        Status::Forwarded  => (Color32::from_rgb(80, 200, 100),  "✓"),
        Status::Dropped    => (Color32::from_rgb(220, 70, 70),   "✗"),
    }
}

fn method_color(m: &str) -> Color32 {
    match m {
        "GET"     => Color32::from_rgb(90, 170, 255),
        "POST"    => Color32::from_rgb(255, 165, 80),
        "PUT"     => Color32::from_rgb(240, 210, 80),
        "DELETE"  => Color32::from_rgb(230, 80, 80),
        "PATCH"   => Color32::from_rgb(140, 230, 140),
        "OPTIONS" => Color32::from_rgb(170, 170, 255),
        "HEAD"    => Color32::from_rgb(170, 230, 230),
        _         => Color32::from_rgb(160, 160, 170),
    }
}

fn trunc(s: &str, max: usize) -> String {
    let s = s.trim();
    if s.len() > max { format!("{}…", &s[..max - 1]) } else { s.to_string() }
}

fn dark_theme() -> egui::Visuals {
    let mut v = egui::Visuals::dark();
    v.panel_fill          = Color32::from_rgb(18, 18, 22);
    v.window_fill         = Color32::from_rgb(22, 22, 28);
    v.extreme_bg_color    = Color32::from_rgb(12, 12, 16);
    v.widgets.noninteractive.bg_fill = Color32::from_rgb(28, 28, 34);
    v.widgets.inactive.bg_fill       = Color32::from_rgb(35, 35, 44);
    v.widgets.hovered.bg_fill        = Color32::from_rgb(50, 50, 65);
    v.widgets.active.bg_fill         = Color32::from_rgb(60, 60, 80);
    v
}
