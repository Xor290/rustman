use eframe::egui::{self, Color32, RichText, ScrollArea, TextEdit, Vec2};
use crate::app::{Shared, Status};

pub fn run(state: Shared) -> Result<(), eframe::Error> {
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
            Ok(Box::new(RustmanApp::new(state)))
        }),
    )
}

// ── App state (GUI-local) ─────────────────────────────────────────────────────

struct RustmanApp {
    state: Shared,
    selected: Option<usize>,
    edit_buf: String,
    dirty: bool,
}

impl RustmanApp {
    fn new(state: Shared) -> Self {
        Self { state, selected: None, edit_buf: String::new(), dirty: false }
    }

    fn sync_selection(&mut self) {
        let s = self.state.lock().unwrap();
        let total = s.requests.len();

        // Clamp selection if items were removed
        if let Some(sel) = self.selected {
            if sel >= total {
                self.selected = if total > 0 { Some(total - 1) } else { None };
                self.dirty = false;
            }
        }

        // Auto-select the newest pending request if nothing pending is selected
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

        // Populate edit_buf when selection changes externally (e.g. status update)
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
}

// ── Main render loop ──────────────────────────────────────────────────────────

impl eframe::App for RustmanApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        ctx.request_repaint_after(std::time::Duration::from_millis(40));
        self.sync_selection();

        self.draw_topbar(ctx);
        self.draw_statusbar(ctx);
        self.draw_list(ctx);
        self.draw_detail(ctx);
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

                    // Show the auto-detected focused host
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
                            ui.colored_label(
                                Color32::from_rgb(80, 210, 120),
                                host,
                            );
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
                });
            });
    }

    // ── Status bar ────────────────────────────────────────────────────────────
    fn draw_statusbar(&mut self, ctx: &egui::Context) {
        egui::TopBottomPanel::bottom("statusbar")
            .exact_height(22.0)
            .show(ctx, |ui| {
                let s = self.state.lock().unwrap();
                let pending = s.pending_count();
                let total   = s.requests.len();
                let focus_info = match &s.focused_host {
                    None => "waiting for navigation  ·  other-tab requests auto-forwarded".into(),
                    Some(h) => format!("capturing {h} and subdomains  ·  other hosts auto-forwarded"),
                };
                ui.label(
                    RichText::new(format!("  {pending} pending  ·  {total} in list  ·  {focus_info}"))
                        .size(11.0)
                        .color(Color32::DARK_GRAY),
                );
            });
    }

    // ── Request list (left panel) ─────────────────────────────────────────────
    fn draw_list(&mut self, ctx: &egui::Context) {
        egui::SidePanel::left("req_list")
            .resizable(true)
            .default_width(420.0)
            .min_width(200.0)
            .show(ctx, |ui| {
                // Snapshot – release lock before any rendering
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

                            // ── Selectable row via allocate_exact_size ──
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

                            // Render row content at the pre-allocated rect
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

            // Snapshot data for this request
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
                    ui.colored_label(
                        Color32::DARK_GRAY,
                        "Edit request below then Forward",
                    );
                });
                ui.add(egui::Separator::default().spacing(4.0));
            }

            // ── Request / response vertical split ─────────────────────────
            let available_h = ui.available_height();
            let has_response = !resp_text.is_empty();
            let req_h = if has_response { available_h * 0.52 } else { available_h };

            // Request area
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
                            // Persist edits into AppState so forward_all uses them
                            self.state.lock().unwrap().set_edited(
                                id,
                                self.edit_buf.as_bytes().to_vec(),
                            );
                        }
                    });
            });

            // Response area
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
