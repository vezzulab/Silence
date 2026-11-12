//! Interfaz gráfica (egui). Todo el trabajo pesado corre en hilos; la UI nunca se congela.

use crate::apply::{JournalEntry, Outcome, Scope};
use crate::learn::Learned;
use crate::model::*;
use crate::ops;
use crate::sys::{RealRunner, Runner};
use crate::tools::{self, PlanEnv, ToolRequest};
use eframe::egui::{self, Align, Color32, CornerRadius, Frame, Layout, Margin, RichText, ScrollArea, Sense, Stroke, Vec2};
use std::collections::BTreeSet;
use std::sync::mpsc::{channel, Receiver};
use std::sync::Arc;
use std::time::{Duration, Instant};

// ───────────────────────── Estilo ─────────────────────────

const BG: Color32 = Color32::from_rgb(8, 10, 16);
const PANEL: Color32 = Color32::from_rgb(12, 15, 23);
const CARD: Color32 = Color32::from_rgb(17, 21, 32);
const BORDER: Color32 = Color32::from_rgb(31, 39, 58);
const TEXT: Color32 = Color32::from_rgb(234, 238, 246);
const DIM: Color32 = Color32::from_rgb(128, 140, 165);
const ACCENT: Color32 = Color32::from_rgb(56, 225, 255);
const OK: Color32 = Color32::from_rgb(74, 222, 128);
const WARN: Color32 = Color32::from_rgb(251, 191, 36);
const DANGER: Color32 = Color32::from_rgb(248, 113, 113);
const INFO: Color32 = Color32::from_rgb(96, 165, 250);

fn setup_style(ctx: &egui::Context) {
    let mut v = egui::Visuals::dark();
    v.panel_fill = BG;
    v.window_fill = PANEL;
    v.extreme_bg_color = Color32::from_rgb(6, 8, 13);
    v.override_text_color = Some(TEXT);
    v.window_corner_radius = CornerRadius::same(16);
    v.menu_corner_radius = CornerRadius::same(12);
    let soft = Color32::from_rgb(23, 29, 44);
    let radius = CornerRadius::same(10);
    v.widgets.noninteractive.bg_stroke = Stroke::new(1.0, BORDER);
    v.widgets.noninteractive.corner_radius = radius;
    v.widgets.inactive.bg_fill = soft;
    v.widgets.inactive.weak_bg_fill = soft;
    v.widgets.inactive.bg_stroke = Stroke::new(1.0, BORDER);
    v.widgets.inactive.corner_radius = radius;
    v.widgets.hovered.bg_fill = Color32::from_rgb(30, 38, 58);
    v.widgets.hovered.weak_bg_fill = Color32::from_rgb(30, 38, 58);
    v.widgets.hovered.bg_stroke = Stroke::new(1.0, ACCENT.gamma_multiply(0.7));
    v.widgets.hovered.corner_radius = radius;
    v.widgets.active.bg_stroke = Stroke::new(1.0, ACCENT);
    v.widgets.active.corner_radius = radius;
    v.widgets.open.corner_radius = radius;
    v.selection.bg_fill = ACCENT.gamma_multiply(0.18);
    v.selection.stroke = Stroke::new(1.0, ACCENT);
    ctx.set_visuals(v);
    ctx.all_styles_mut(|s| {
        s.spacing.item_spacing = Vec2::new(12.0, 12.0);
        s.spacing.button_padding = Vec2::new(16.0, 9.0);
        s.spacing.interact_size.y = 32.0;
        s.spacing.icon_spacing = 10.0;
        s.spacing.indent = 26.0;
        s.spacing.scroll = egui::style::ScrollStyle::floating();
    });
}

/// Tarjeta: superficie con borde fino, esquinas amplias y una sombra suave que la separa del fondo.
fn card<R>(ui: &mut egui::Ui, add: impl FnOnce(&mut egui::Ui) -> R) -> R {
    Frame::NONE
        .fill(CARD)
        .stroke(Stroke::new(1.0, BORDER))
        .corner_radius(CornerRadius::same(16))
        .inner_margin(Margin::same(26))
        .shadow(egui::epaint::Shadow { offset: [0, 10], blur: 28, spread: 0, color: Color32::from_black_alpha(110) })
        .show(ui, add)
        .inner
}

/// Línea fina con aire arriba y abajo, para separar un ajuste del siguiente.
fn soft_sep(ui: &mut egui::Ui) {
    ui.add_space(6.0);
    let (rect, _) = ui.allocate_exact_size(Vec2::new(ui.available_width(), 1.0), Sense::hover());
    ui.painter().rect_filled(rect, 0.0, BORDER.gamma_multiply(0.8));
    ui.add_space(6.0);
}

fn pill(ui: &mut egui::Ui, text: &str, color: Color32) {
    Frame::NONE
        .fill(color.gamma_multiply(0.16))
        .stroke(Stroke::new(1.0, color.gamma_multiply(0.55)))
        .corner_radius(CornerRadius::same(10))
        .inner_margin(Margin::symmetric(8, 2))
        .show(ui, |ui| {
            ui.label(RichText::new(text).color(color).size(11.5));
        });
}

fn dim(text: impl Into<String>) -> RichText {
    RichText::new(text.into()).color(DIM)
}

fn title(text: &str) -> RichText {
    RichText::new(text).size(15.5).strong()
}

fn primary_button(text: &str) -> egui::Button<'static> {
    egui::Button::new(RichText::new(text.to_string()).color(Color32::from_rgb(8, 30, 28)).strong()).fill(ACCENT)
}

fn severity_color(s: Severity) -> Color32 {
    match s {
        Severity::High => DANGER,
        Severity::Medium => WARN,
        Severity::Low => DIM,
    }
}

fn safety_color(s: Safety) -> Color32 {
    match s {
        Safety::NoSignsOfUse | Safety::Safe => OK,
        Safety::Minor => INFO,
        Safety::Notable => WARN,
        Safety::InUse => DANGER,
    }
}

fn score_color(score: u32) -> Color32 {
    if score >= 80 {
        OK
    } else if score >= 50 {
        WARN
    } else {
        DANGER
    }
}

fn fmt_ts(ts: i64) -> String {
    chrono::DateTime::from_timestamp(ts, 0)
        .map(|d| d.with_timezone(&chrono::Local).format("%Y-%m-%d %H:%M").to_string())
        .unwrap_or_default()
}

fn gauge(ui: &mut egui::Ui, score: u32) {
    let size = 176.0;
    let (rect, _) = ui.allocate_exact_size(Vec2::splat(size), Sense::hover());
    let p = ui.painter_at(rect);
    let c = rect.center();
    let r = size / 2.0 - 14.0;
    let arc = |frac: f32| -> Vec<egui::Pos2> {
        let start = 135.0_f32.to_radians();
        let sweep = 270.0_f32.to_radians() * frac;
        let n = ((frac * 90.0) as usize).max(2);
        (0..=n)
            .map(|i| {
                let a = start + sweep * (i as f32 / n as f32);
                egui::pos2(c.x + r * a.cos(), c.y + r * a.sin())
            })
            .collect()
    };
    p.add(egui::Shape::line(arc(1.0), Stroke::new(10.0, Color32::from_rgb(24, 30, 45))));
    if score > 0 {
        let col = score_color(score);
        // Resplandor suave bajo el arco, para el aire «futurista».
        p.add(egui::Shape::line(arc(score as f32 / 100.0), Stroke::new(22.0, col.gamma_multiply(0.12))));
        p.add(egui::Shape::line(arc(score as f32 / 100.0), Stroke::new(10.0, col)));
    }
    p.text(c - Vec2::new(0.0, 6.0), egui::Align2::CENTER_CENTER, score.to_string(), egui::FontId::proportional(46.0), TEXT);
    p.text(c + Vec2::new(0.0, 30.0), egui::Align2::CENTER_CENTER, "de 100", egui::FontId::proportional(13.0), DIM);
}

// ───────────────────────── Estado ─────────────────────────

#[derive(PartialEq, Clone, Copy)]
enum Tab {
    Summary,
    Recs,
    Tools,
    Catalog,
    Analysis,
    History,
    About,
}

#[derive(PartialEq, Clone, Copy)]
enum ToolSection {
    Network,
    Browsers,
    Files,
    Apps,
    Devices,
    System,
}

impl ToolSection {
    const ALL: [(ToolSection, &'static str, &'static str); 6] = [
        (ToolSection::Network, "Red", "Qué ve de ti cada red a la que te conectas: firewall, DNS, identidad y redes de confianza."),
        (ToolSection::Browsers, "Navegadores", "Privacidad de Firefox y Chromium, y qué permisos tienen tus extensiones."),
        (ToolSection::Files, "Archivos y rastros", "Lo que tus archivos y tu propio equipo dejan a la vista de otros."),
        (ToolSection::Apps, "Aplicaciones", "Qué pueden ver tus apps y cómo navegar de forma anónima."),
        (ToolSection::Devices, "Dispositivos", "Cámara, micrófono y puertos USB."),
        (ToolSection::System, "Sistema", "Endurecimiento del sistema y revisión de tus llaves SSH."),
    ];
}

/// Acciones que borran o descargan algo y piden confirmación antes de ejecutarse.
#[derive(Clone)]
enum SimpleAction {
    CleanTraces(Vec<String>),
    Panic,
    InstallTor,
    InstallSystem,
    Update(String),
}

struct ConfirmSimple {
    title: String,
    lines: Vec<String>,
    warn: Option<String>,
    action: SimpleAction,
}

#[derive(PartialEq, Clone, Copy)]
enum Filter {
    All,
    Auto,
    Manual,
    InUse,
}

struct OpDone {
    label: String,
    reverted: bool,
    outcomes: Vec<Outcome>,
    guard: Vec<(String, String)>,
}

#[derive(Clone)]
enum EasyAction {
    Rules(Vec<String>),
    Tool(ToolRequest),
}

struct ConfirmEasy {
    actions: Vec<EasyAction>,
    bullets: Vec<String>,
    details: Vec<String>,
    needs_root: bool,
    guards: Vec<(String, String)>,
}

struct EasyItem {
    id: &'static str,
    title: &'static str,
    plain: String,
    active: bool,
    default_on: bool,
}

struct ConfirmRules {
    ids: Vec<String>,
}

struct ConfirmTool {
    req: ToolRequest,
    label: String,
    lines: Vec<String>,
    needs_root: bool,
    guarded: bool,
}

struct Guard {
    items: Vec<(String, String)>,
    deadline: Instant,
}

pub struct App {
    ctx: egui::Context,
    rules: Arc<Vec<Rule>>,
    learned: Learned,
    level: Level,
    snap: Option<Arc<Snapshot>>,
    report: Option<Arc<Report>>,
    drift: Vec<String>,
    scan_rx: Option<Receiver<Snapshot>>,
    op_rx: Option<Receiver<OpDone>>,
    busy: Option<String>,
    tab: Tab,
    filter: Filter,
    search: String,
    selected: BTreeSet<String>,
    expanded: BTreeSet<String>,
    history: Vec<JournalEntry>,
    active_keys: BTreeSet<String>,
    confirm_rules: Option<ConfirmRules>,
    confirm_tool: Option<ConfirmTool>,
    confirm_easy: Option<ConfirmEasy>,
    easy_sel: BTreeSet<String>,
    easy_init: bool,
    advanced: bool,
    result: Option<OpDone>,
    guard: Option<Guard>,
    toast: Option<(String, Instant)>,
    redact: bool,
    // opciones de herramientas
    dns_provider: String,
    dns_strict: bool,
    id_wifi: bool,
    id_eth: bool,
    id_dhcp: bool,
    id_tcp: bool,
    id_host: tools::HostnameStyle,
    br_level: String,
    br_ddg: bool,
    br_light: bool,
    tools_section: ToolSection,
    meta_input: String,
    traces_cache: Option<Vec<crate::extras::Trace>>,
    trace_sel: BTreeSet<String>,
    ext_list: Option<Vec<crate::extras::Ext>>,
    ssh_notes: Option<Vec<String>>,
    trusted_sel: BTreeSet<String>,
    confirm_simple: Option<ConfirmSimple>,
    update: Option<crate::update::Release>,
    update_rx: Option<Receiver<Result<Option<crate::update::Release>, String>>>,
    update_status: Option<String>,
    update_manual: bool,
    br_ublock: bool,
    fw_level: String,
    fw_allow: BTreeSet<String>,
    fw_allow_init: bool,
}

impl App {
    fn new(ctx: egui::Context) -> Self {
        let rules = Arc::new(crate::rules::load().expect("catálogo de reglas inválido"));
        let learned = Learned::load();
        let advanced = learned.advanced;
        let mut app = App {
            ctx,
            rules,
            level: learned.level.unwrap_or(Level::Basic),
            learned,
            snap: None,
            report: None,
            drift: vec![],
            scan_rx: None,
            op_rx: None,
            busy: None,
            tab: Tab::Summary,
            filter: Filter::All,
            search: String::new(),
            selected: BTreeSet::new(),
            expanded: BTreeSet::new(),
            history: vec![],
            active_keys: BTreeSet::new(),
            confirm_rules: None,
            confirm_tool: None,
            confirm_easy: None,
            easy_sel: BTreeSet::new(),
            easy_init: false,
            advanced: false,
            result: None,
            guard: None,
            toast: None,
            redact: true,
            dns_provider: "quad9".into(),
            dns_strict: false,
            id_wifi: true,
            id_eth: false,
            id_dhcp: true,
            id_tcp: true,
            id_host: tools::HostnameStyle::Windows,
            br_level: "balanced".into(),
            br_ddg: true,
            br_light: true,
            tools_section: ToolSection::Network,
            meta_input: String::new(),
            traces_cache: None,
            trace_sel: BTreeSet::new(),
            ext_list: None,
            ssh_notes: None,
            trusted_sel: BTreeSet::new(),
            confirm_simple: None,
            update: None,
            update_rx: None,
            update_status: None,
            update_manual: false,
            br_ublock: true,
            fw_level: "standard".into(),
            fw_allow: BTreeSet::new(),
            fw_allow_init: false,
        };
        app.advanced = advanced;
        // Solo para desarrollo y capturas de pantalla: abrir directamente en una pestaña.
        if let Ok(t) = std::env::var("SILENCE_TAB") {
            app.tab = match t.as_str() {
                "recs" => { app.advanced = true; Tab::Recs }
                "advanced" => { app.advanced = true; Tab::Summary }
                "tools" => Tab::Tools,
                "catalog" => { app.advanced = true; Tab::Catalog }
                "analysis" => { app.advanced = true; Tab::Analysis }
                "history" => Tab::History,
                "about" => Tab::About,
                _ => Tab::Summary,
            };
        }
        app.refresh_history();
        app.rescan();
        if !app.learned.no_update_check {
            app.check_updates(false);
        }
        app
    }

    fn refresh_history(&mut self) {
        self.history = ops::history();
        self.active_keys = self.history.iter().filter(|e| !e.reverted).map(|e| e.key.clone()).collect();
    }

    fn rescan(&mut self) {
        if self.scan_rx.is_some() {
            return;
        }
        let (tx, rx) = channel();
        let rules = self.rules.clone();
        let ctx = self.ctx.clone();
        std::thread::spawn(move || {
            let snap = crate::collect::collect(&RealRunner::default(), &rules);
            let _ = tx.send(snap);
            ctx.request_repaint();
        });
        self.scan_rx = Some(rx);
    }

    fn recompute(&mut self) {
        let Some(snap) = self.snap.clone() else { return };
        let report = crate::engine::evaluate(&self.rules, &snap, self.level, &self.learned);
        self.drift = crate::report::drift(&report, &snap, &self.history);
        self.selected.retain(|id| report.findings.iter().any(|f| &f.rule.id == id && f.status == Status::Todo && f.rule.fix.is_auto() && !f.ignored));
        self.report = Some(Arc::new(report));
    }

    fn set_level(&mut self, l: Level) {
        self.level = l;
        self.learned.level = Some(l);
        self.learned.save();
        self.recompute();
    }

    fn start_op(&mut self, label: &str, reverted: bool, guard: Vec<(String, String)>, work: impl FnOnce() -> Vec<Outcome> + Send + 'static) {
        if self.op_rx.is_some() {
            return;
        }
        let (tx, rx) = channel();
        let ctx = self.ctx.clone();
        let label_s = label.to_string();
        std::thread::spawn(move || {
            let outcomes = work();
            let _ = tx.send(OpDone { label: label_s, reverted, outcomes, guard });
            ctx.request_repaint();
        });
        self.busy = Some(label.to_string());
        self.op_rx = Some(rx);
    }

    fn apply_rules(&mut self, ids: Vec<String>) {
        let rules = self.rules.clone();
        self.start_op("Aplicando cambios…", false, vec![], move || ops::apply_rules(&rules, &ids));
    }

    fn apply_tool(&mut self, req: ToolRequest, label: &str, guarded: bool) {
        let guard: Vec<(String, String)> = if guarded { vec![(req.key().to_string(), label.to_string())] } else { vec![] };
        self.start_op(&format!("Aplicando: {label}…"), false, guard, move || ops::apply_tool(&req));
    }

    fn revert_key(&mut self, key: &str, label: &str) {
        let key = key.to_string();
        self.start_op(&format!("Quitando: {label}…"), true, vec![], move || ops::revert_key(&key));
    }

    fn revert_keys(&mut self, items: Vec<(String, String)>) {
        self.start_op("Deshaciendo los cambios de red…", true, vec![], move || items.iter().flat_map(|(k, _)| ops::revert_key(k)).collect());
    }

    fn revert_entry(&mut self, e: JournalEntry) {
        let label = e.title.clone();
        self.start_op(&format!("Revirtiendo: {label}…"), true, vec![], move || vec![ops::revert_entry(&e)]);
    }

    fn plan_env(&self) -> PlanEnv {
        let active = |n: &str| self.snap.as_ref().and_then(|s| s.units.get(n)).map(|u| u.is_active()).unwrap_or(false);
        PlanEnv { nm_active: active("NetworkManager.service"), resolved_active: active("systemd-resolved.service") }
    }

    fn ask_tool(&mut self, req: ToolRequest, label: &str, guarded: bool) {
        match tools::plan(&req, &self.plan_env()) {
            Err(e) => self.toast = Some((e, Instant::now())),
            Ok(plan) => {
                let mut lines = Vec::new();
                for f in &plan.fixes {
                    match f {
                        Fix::SetHostname { name } => lines.push(hostname_line(name)),
                        other => lines.extend(other.preview()),
                    }
                }
                let needs_root = plan.fixes.iter().any(|f| f.needs_root());
                self.confirm_tool = Some(ConfirmTool { req, label: label.into(), lines, needs_root, guarded });
            }
        }
    }

    fn check_updates(&mut self, manual: bool) {
        if self.update_rx.is_some() {
            return;
        }
        let (tx, rx) = channel();
        let ctx = self.ctx.clone();
        std::thread::spawn(move || {
            let _ = tx.send(crate::update::check(&RealRunner::default()));
            ctx.request_repaint();
        });
        self.update_rx = Some(rx);
        self.update_manual = manual;
        if manual {
            self.update_status = Some("Buscando actualizaciones…".into());
        }
    }

    fn poll(&mut self) {
        if let Some(rx) = &self.update_rx {
            if let Ok(res) = rx.try_recv() {
                self.update_rx = None;
                match res {
                    Ok(Some(rel)) => {
                        self.update_status = None;
                        self.update = Some(rel);
                    }
                    Ok(None) => {
                        self.update = None;
                        self.update_status = if self.update_manual { Some(format!("Ya tienes la última versión ({}).", crate::update::CURRENT)) } else { None };
                    }
                    // Una comprobación automática que falla no molesta al usuario.
                    Err(e) => self.update_status = if self.update_manual { Some(e) } else { None },
                }
            }
        }
        if let Some(rx) = &self.scan_rx {
            if let Ok(snap) = rx.try_recv() {
                self.scan_rx = None;
                if !self.fw_allow_init {
                    self.fw_allow = tools::suggested_firewall_allow(&snap).into_iter().collect();
                    self.fw_allow_init = true;
                }
                self.snap = Some(Arc::new(snap));
                self.recompute();
            }
        }
        if let Some(rx) = &self.op_rx {
            if let Ok(done) = rx.try_recv() {
                self.op_rx = None;
                self.busy = None;
                let now = chrono::Utc::now().timestamp();
                for o in done.outcomes.iter().filter(|o| o.ok) {
                    if self.rules.iter().any(|r| r.id == o.key) {
                        if done.reverted { self.learned.record_reverted(&o.key, now) } else { self.learned.record_applied(&o.key, now) }
                    }
                }
                self.learned.save();
                self.refresh_history();
                if !done.guard.is_empty() && done.outcomes.iter().any(|o| o.ok && done.guard.iter().any(|(k, _)| k == &o.key)) {
                    self.guard = Some(Guard { items: done.guard.clone(), deadline: Instant::now() + Duration::from_secs(30) });
                }
                self.selected.clear();
                self.result = Some(done);
                self.rescan();
            }
        }
        // Temporizador de seguridad: si no se confirma, se revierte solo.
        if let Some(g) = &self.guard {
            if Instant::now() >= g.deadline && self.op_rx.is_none() {
                let items = g.items.clone();
                self.guard = None;
                self.revert_keys(items);
            }
        }
        if let Some((_, t)) = &self.toast {
            if t.elapsed() > Duration::from_secs(6) {
                self.toast = None;
            }
        }
    }

    fn is_busy(&self) -> bool {
        self.busy.is_some() || self.scan_rx.is_some()
    }
}

// ───────────────────────── Dibujo ─────────────────────────

impl eframe::App for App {
    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        self.poll();
        let ctx = ui.ctx().clone();
        let dropped: Vec<String> = ctx.input(|i| i.raw.dropped_files.iter().map(|f| f.path().display().to_string()).collect());
        if !dropped.is_empty() {
            self.tab = Tab::Tools;
            self.tools_section = ToolSection::Files;
            for d in dropped {
                if !self.meta_input.is_empty() && !self.meta_input.ends_with('\n') {
                    self.meta_input.push('\n');
                }
                self.meta_input.push_str(&d);
            }
        }
        if self.is_busy() || self.guard.is_some() {
            ctx.request_repaint_after(Duration::from_millis(120));
        }
        let report = self.report.clone();
        let snap = self.snap.clone();

        egui::Panel::top("top").frame(Frame::NONE.fill(PANEL).stroke(Stroke::new(1.0, BORDER)).inner_margin(Margin::symmetric(28, 16))).show(ui, |ui| {
            ui.horizontal(|ui| {
                ui.label(RichText::new("S I L E N C E").size(18.0).strong().color(ACCENT));
                ui.label(dim("Privacidad para Linux"));
                if let Some(s) = &snap {
                    ui.label(dim(format!("{} · {}", s.info.distro_name, s.info.desktop)));
                }
                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                    if ui.add_enabled(!self.is_busy(), egui::Button::new("Volver a escanear")).clicked() {
                        self.rescan();
                    }
                    if let Some(b) = &self.busy {
                        ui.add(egui::Spinner::new());
                        ui.label(dim(b.clone()));
                    } else if self.scan_rx.is_some() {
                        ui.add(egui::Spinner::new());
                        ui.label(dim("Escaneando el sistema…"));
                    }
                });
            });
        });

        egui::Panel::left("nav").exact_size(230.0).frame(Frame::NONE.fill(PANEL).stroke(Stroke::new(1.0, BORDER)).inner_margin(Margin::same(18))).show(ui, |ui| {
            ui.add_space(10.0);
            let todo = report.as_ref().map(|r| r.todo().count()).unwrap_or(0);
            let mut items = vec![(Tab::Summary, "Inicio".to_string()), (Tab::Tools, "Protecciones".to_string())];
            if self.advanced {
                items.push((Tab::Recs, format!("Recomendaciones ({todo})")));
                items.push((Tab::Catalog, "Catálogo".to_string()));
                items.push((Tab::Analysis, "Análisis".to_string()));
            }
            items.push((Tab::History, "Historial".to_string()));
            items.push((Tab::About, "Acerca de".to_string()));
            for (t, label) in items {
                let sel = self.tab == t;
                let resp = ui.add_sized([ui.available_width(), 42.0], egui::Button::selectable(sel, RichText::new(label).size(14.5)));
                if resp.clicked() {
                    self.tab = t;
                }
            }
            ui.with_layout(Layout::bottom_up(Align::Min), |ui| {
                ui.add_space(8.0);
                if ui.checkbox(&mut self.advanced, "Modo avanzado").changed() {
                    self.learned.advanced = self.advanced;
                    self.learned.save();
                    if !self.advanced && matches!(self.tab, Tab::Recs | Tab::Catalog | Tab::Analysis) {
                        self.tab = Tab::Summary;
                    }
                }
            });
        });

        egui::CentralPanel::default().frame(Frame::NONE.fill(BG).inner_margin(Margin::symmetric(40, 32))).show(ui, |ui| {
            ScrollArea::vertical().auto_shrink([false, false]).show(ui, |ui| match (&report, &snap) {
                (Some(r), Some(s)) => match self.tab {
                    Tab::Summary => self.tab_summary(ui, r, s),
                    Tab::Recs => self.tab_recs(ui, r),
                    Tab::Tools => self.tab_tools(ui, s),
                    Tab::Catalog => self.tab_catalog(ui, r),
                    Tab::Analysis => self.tab_analysis(ui, s),
                    Tab::History => self.tab_history(ui),
                    Tab::About => self.tab_about(ui, r, s),
                },
                _ => {
                    ui.add_space(80.0);
                    ui.vertical_centered(|ui| {
                        ui.add(egui::Spinner::new().size(36.0));
                        ui.add_space(16.0);
                        ui.label(dim("Leyendo el estado de tu sistema (solo lectura)…"));
                    });
                }
            });
        });

        self.dialogs(&ctx);
    }
}

impl App {
    fn dialogs(&mut self, ctx: &egui::Context) {
        // Confirmar reglas
        if let Some(c) = &self.confirm_rules {
            let ids = c.ids.clone();
            let report = self.report.clone();
            let mut go = false;
            let mut cancel = false;
            egui::Modal::new(egui::Id::new("confirm_rules")).show(ctx, |ui| {
                ui.set_width(560.0);
                ui.heading("Confirmar cambios");
                ui.label(dim("Esto es exactamente lo que Silence va a hacer. Todo se puede revertir desde la pestaña Historial."));
                ui.add_space(10.0);
                let mut needs_root = false;
                ScrollArea::vertical().max_height(320.0).show(ui, |ui| {
                    if let Some(r) = &report {
                        for id in &ids {
                            if let Some(f) = r.findings.iter().find(|f| &f.rule.id == id) {
                                needs_root |= f.rule.fix.needs_root();
                                card(ui, |ui| {
                                    ui.label(RichText::new(&f.rule.title).strong());
                                    for l in f.rule.fix.preview() {
                                        ui.label(RichText::new(l).monospace().size(12.0).color(ACCENT));
                                    }
                                    ui.label(dim(format!("Puede notarse: {}", f.rule.breaks.trim())));
                                });
                            }
                        }
                    }
                });
                if needs_root {
                    ui.label(RichText::new("Se te pedirá la contraseña de administrador una sola vez.").color(WARN));
                }
                ui.add_space(10.0);
                ui.horizontal(|ui| {
                    if ui.add(primary_button("Aplicar")).clicked() {
                        go = true;
                    }
                    if ui.button("Cancelar").clicked() {
                        cancel = true;
                    }
                });
            });
            if go {
                self.confirm_rules = None;
                self.apply_rules(ids);
            } else if cancel {
                self.confirm_rules = None;
            }
        }

        // Confirmar protección con un clic
        if let Some(c) = &self.confirm_easy {
            let (actions, bullets, details, needs_root, guards) = (c.actions.clone(), c.bullets.clone(), c.details.clone(), c.needs_root, c.guards.clone());
            let mut go = false;
            let mut cancel = false;
            egui::Modal::new(egui::Id::new("confirm_easy")).show(ctx, |ui| {
                ui.set_width(580.0);
                ui.heading("Esto es lo que vamos a hacer");
                ui.add_space(8.0);
                for b in &bullets {
                    ui.label(format!("• {b}"));
                }
                ui.add_space(8.0);
                egui::CollapsingHeader::new("Ver detalles técnicos").show(ui, |ui| {
                    ScrollArea::vertical().max_height(180.0).show(ui, |ui| {
                        for d in &details {
                            ui.label(RichText::new(d).monospace().size(12.0).color(ACCENT));
                        }
                    });
                });
                ui.add_space(8.0);
                if needs_root {
                    ui.label(RichText::new("Se te pedirá tu contraseña de administrador.").color(WARN));
                }
                if !guards.is_empty() {
                    ui.label(dim("Después tendrás 30 segundos para confirmar que internet sigue funcionando; si no, Silence lo deshace solo."));
                }
                ui.label(dim("Todo se puede deshacer desde Historial."));
                ui.add_space(10.0);
                ui.horizontal(|ui| {
                    if ui.add(primary_button("Proteger")).clicked() {
                        go = true;
                    }
                    if ui.button("Cancelar").clicked() {
                        cancel = true;
                    }
                });
            });
            if go {
                self.confirm_easy = None;
                let rules = self.rules.clone();
                self.start_op("Activando protecciones…", false, guards, move || {
                    let mut out = Vec::new();
                    for a in actions {
                        match a {
                            EasyAction::Rules(ids) => out.extend(ops::apply_rules(&rules, &ids)),
                            EasyAction::Tool(req) => out.extend(ops::apply_tool(&req)),
                        }
                    }
                    out
                });
            } else if cancel {
                self.confirm_easy = None;
            }
        }

        // Confirmar herramienta
        if let Some(c) = &self.confirm_tool {
            let (req, label, lines, needs_root, guarded) = (c.req.clone(), c.label.clone(), c.lines.clone(), c.needs_root, c.guarded);
            let mut go = false;
            let mut cancel = false;
            egui::Modal::new(egui::Id::new("confirm_tool")).show(ctx, |ui| {
                ui.set_width(560.0);
                ui.heading(&label);
                ui.label(dim("Esto es lo que se va a hacer:"));
                ScrollArea::vertical().max_height(300.0).show(ui, |ui| {
                    for l in &lines {
                        ui.label(RichText::new(format!("• {l}")).monospace().size(12.0).color(ACCENT));
                    }
                });
                if needs_root {
                    ui.label(RichText::new("Se te pedirá la contraseña de administrador.").color(WARN));
                }
                if guarded {
                    ui.label(dim("Después tendrás 30 segundos para confirmar que todo funciona; si no, Silence lo revierte solo."));
                }
                ui.add_space(10.0);
                ui.horizontal(|ui| {
                    if ui.add(primary_button("Aplicar")).clicked() {
                        go = true;
                    }
                    if ui.button("Cancelar").clicked() {
                        cancel = true;
                    }
                });
            });
            if go {
                self.confirm_tool = None;
                self.apply_tool(req, &label, guarded);
            } else if cancel {
                self.confirm_tool = None;
            }
        }

        // Resultado
        if let Some(c) = &self.confirm_simple {
            let (title, lines, warn, action) = (c.title.clone(), c.lines.clone(), c.warn.clone(), c.action.clone());
            let mut go = false;
            let mut cancel = false;
            egui::Modal::new(egui::Id::new("confirm_simple")).show(ctx, |ui| {
                ui.set_width(560.0);
                ui.heading(&title);
                ui.add_space(6.0);
                ScrollArea::vertical().max_height(300.0).show(ui, |ui| {
                    for l in &lines {
                        ui.label(RichText::new(l).monospace().size(12.0).color(ACCENT));
                    }
                });
                if let Some(w) = &warn {
                    ui.label(RichText::new(w).color(WARN));
                }
                ui.add_space(14.0);
                ui.horizontal(|ui| {
                    if ui.add(primary_button("Continuar")).clicked() {
                        go = true;
                    }
                    if ui.button("Cancelar").clicked() {
                        cancel = true;
                    }
                });
            });
            if go {
                self.confirm_simple = None;
                self.run_simple(action);
            } else if cancel {
                self.confirm_simple = None;
            }
        }

        if self.result.is_some() && self.confirm_rules.is_none() && self.confirm_tool.is_none() && self.confirm_easy.is_none() && self.confirm_simple.is_none() {
            let mut close = false;
            let mut reconnect = false;
            let nm = self.snap.as_ref().map(|s| s.nm_profiles.clone()).unwrap_or_default();
            if let Some(res) = &self.result {
                egui::Modal::new(egui::Id::new("result")).show(ctx, |ui| {
                    ui.set_width(540.0);
                    let all_ok = res.outcomes.iter().all(|o| o.ok);
                    ui.heading(if all_ok { "Listo" } else { "Terminó con avisos" });
                    ScrollArea::vertical().max_height(320.0).show(ui, |ui| {
                        for o in &res.outcomes {
                            card(ui, |ui| {
                                ui.horizontal(|ui| {
                                    pill(ui, if o.ok { "OK" } else { "ERROR" }, if o.ok { OK } else { DANGER });
                                    ui.label(RichText::new(&o.title).strong());
                                });
                                ui.label(dim(o.message.clone()));
                            });
                        }
                    });
                    ui.add_space(10.0);
                    ui.horizontal(|ui| {
                        if res.outcomes.iter().any(|o| o.ok && o.key.starts_with("tool.")) && nm.iter().any(|p| p.active) && ui.button("Reconectar red ahora").clicked() {
                            reconnect = true;
                        }
                        if ui.add(primary_button("Cerrar")).clicked() {
                            close = true;
                        }
                    });
                });
            }
            if reconnect {
                let msgs = ops::reconnect_active(&nm);
                self.toast = Some((msgs.join(" · "), Instant::now()));
            }
            if close {
                self.result = None;
            }
        }

        // Temporizador de seguridad
        if let Some(g) = &self.guard {
            let left = g.deadline.saturating_duration_since(Instant::now()).as_secs();
            let items = g.items.clone();
            let label = items.iter().map(|(_, l)| l.as_str()).collect::<Vec<_>>().join(", ");
            let mut keep = false;
            let mut undo = false;
            egui::Modal::new(egui::Id::new("guard")).show(ctx, |ui| {
                ui.set_width(460.0);
                ui.heading("¿Sigue funcionando todo?");
                ui.label(format!("Acabas de aplicar: {label}."));
                ui.label(RichText::new(format!("Si no confirmas, se revierte automáticamente en {left} s.")).color(WARN));
                ui.add(egui::ProgressBar::new(left as f32 / 30.0));
                ui.add_space(10.0);
                ui.horizontal(|ui| {
                    if ui.add(primary_button("Sí, mantener")).clicked() {
                        keep = true;
                    }
                    if ui.button("No, revertir ahora").clicked() {
                        undo = true;
                    }
                });
            });
            if keep {
                self.guard = None;
            } else if undo {
                self.guard = None;
                self.revert_keys(items);
            }
        }

        // Aviso breve
        if let Some((msg, _)) = &self.toast {
            egui::Area::new(egui::Id::new("toast")).anchor(egui::Align2::CENTER_BOTTOM, [0.0, -16.0]).show(ctx, |ui| {
                Frame::NONE.fill(Color32::from_rgb(30, 38, 54)).stroke(Stroke::new(1.0, ACCENT)).corner_radius(CornerRadius::same(8)).inner_margin(Margin::same(10)).show(ui, |ui| {
                    ui.label(msg.clone());
                });
            });
        }
    }

    // ───────────── Resumen ─────────────

    // ───────────── Inicio (modo fácil) ─────────────

    fn easy_items(&self, r: &Report, s: &Snapshot) -> Vec<EasyItem> {
        let mut v = Vec::new();
        let env = self.plan_env();
        let name = |t: &str| match t {
            "ssh" => "SSH",
            "kdeconnect" => "KDE Connect",
            "localsend" => "LocalSend",
            _ => "",
        };
        if s.browsers.iter().any(|b| b.installed) || !s.firefox.is_empty() {
            v.push(EasyItem {
                id: "browsers",
                title: "Navegadores que no te rastrean",
                plain: "Firefox y Chromium dejan de enviar datos de uso, usan DuckDuckGo como buscador y bloquean anuncios y rastreadores.".into(),
                active: self.active_keys.contains(tools::KEY_BROWSERS),
                default_on: true,
            });
        }
        if env.nm_active && env.resolved_active {
            v.push(EasyItem {
                id: "dns",
                title: "Internet privado",
                plain: "Tu proveedor de internet deja de ver qué páginas visitas: tus consultas viajan cifradas con Quad9 (Suiza, sin ánimo de lucro).".into(),
                active: tools::provider_in_use(&s.dns.servers).is_some() || self.active_keys.contains(tools::KEY_DNS),
                default_on: true,
            });
        }
        if s.firewall.backend.is_some() {
            let fires = r.findings.iter().any(|f| f.rule.id == "network.firewall_zone" && f.status == Status::Todo);
            let keep: Vec<&str> = tools::suggested_firewall_allow(s).iter().map(|t| name(t)).collect();
            v.push(EasyItem {
                id: "firewall",
                title: "Firewall que cierra puertas",
                plain: format!(
                    "Cierra las puertas que tu Wi-Fi deja abiertas a otros equipos de la red. Se mantiene accesible lo que usas: {}.",
                    if keep.is_empty() { "nada (no se detectó uso)".to_string() } else { keep.join(", ") }
                ),
                active: !fires || self.active_keys.contains(tools::KEY_FIREWALL),
                default_on: fires,
            });
        }
        let safe: Vec<&Finding> = r.todo().filter(|f| f.preselect && !is_guided(&f.rule)).collect();
        if !safe.is_empty() {
            v.push(EasyItem {
                id: "system",
                title: "Ajustes seguros del sistema",
                plain: format!("{} ajuste(s) del sistema que no se notan al usar el equipo y reducen lo que tu equipo cuenta de sí mismo a la red.", safe.len()),
                active: false,
                default_on: true,
            });
        }
        if env.nm_active {
            v.push(EasyItem {
                id: "identity",
                title: "Identidad de red cambiante",
                plain: "Tu equipo cambia de «cara» en cada Wi-Fi (dirección MAC aleatoria y nombre tipo Windows) para que no te reconozcan entre redes. Opcional.".into(),
                active: self.active_keys.contains(tools::KEY_IDENTITY),
                default_on: false,
            });
        }
        v.push(EasyItem {
            id: "ipv6",
            title: "Apagar IPv6",
            plain: "Evita que se filtre tu dirección real si usas una VPN. Opcional.".into(),
            active: tools::ipv6_off(s) || self.active_keys.contains(tools::KEY_IPV6),
            default_on: false,
        });
        v
    }

    fn build_easy(&mut self, r: &Report, s: &Snapshot) {
        let env = self.plan_env();
        let mut actions = Vec::new();
        let mut bullets = Vec::new();
        let mut details = Vec::new();
        let mut guards = Vec::new();
        let mut needs_root = false;
        let items = self.easy_items(r, s);
        for it in items.iter().filter(|i| self.easy_sel.contains(i.id) && !i.active) {
            let req = match it.id {
                "browsers" => Some(ToolRequest::Browsers { level: "balanced+light".into(), ddg: true, ublock: true }),
                "dns" => Some(ToolRequest::Dns { provider: "quad9".into(), strict: false }),
                "firewall" => Some(ToolRequest::Firewall { level: "standard".into(), allow: tools::suggested_firewall_allow(s) }),
                "identity" => Some(ToolRequest::Identity { wifi_mac: true, ethernet_mac: false, dhcp_windows: true, tcp_windows: true, hostname: tools::HostnameStyle::Windows }),
                "ipv6" => Some(ToolRequest::Ipv6Off {}),
                _ => None,
            };
            bullets.push(format!("{}: {}", it.title, it.plain));
            match req {
                Some(req) => match tools::plan(&req, &env) {
                    Ok(plan) => {
                        for f in &plan.fixes {
                            needs_root |= f.needs_root();
                            match f {
                                Fix::SetHostname { name } => details.push(hostname_line(name)),
                                other => details.extend(other.preview()),
                            }
                        }
                        if matches!(it.id, "dns" | "firewall" | "identity" | "ipv6") {
                            guards.push((req.key().to_string(), plan.title.clone()));
                        }
                        actions.push(EasyAction::Tool(req));
                    }
                    Err(e) => {
                        self.toast = Some((format!("{}: {e}", it.title), Instant::now()));
                        return;
                    }
                },
                None => {
                    let ids: Vec<String> = r.todo().filter(|f| f.preselect && !is_guided(&f.rule)).map(|f| f.rule.id.clone()).collect();
                    for f in r.todo().filter(|f| ids.contains(&f.rule.id)) {
                        needs_root |= f.rule.fix.needs_root();
                        details.extend(f.rule.fix.preview());
                    }
                    actions.push(EasyAction::Rules(ids));
                }
            }
        }
        if actions.is_empty() {
            self.toast = Some(("No hay nada seleccionado para activar.".into(), Instant::now()));
            return;
        }
        self.confirm_easy = Some(ConfirmEasy { actions, bullets, details, needs_root, guards });
    }

    /// Tarjeta «hay una versión nueva» con lo que trae. Devuelve true si se dibujó.
    fn update_card(&mut self, ui: &mut egui::Ui) -> bool {
        let Some(rel) = self.update.clone() else { return false };
        card(ui, |ui| {
            ui.horizontal(|ui| {
                ui.label(RichText::new(format!("Hay una actualización: Silence {}", rel.version)).color(ACCENT).strong().size(16.0));
                pill(ui, &format!("tienes {}", crate::update::CURRENT), DIM);
            });
            let notes = crate::update::plain_notes(&rel.notes, 12);
            if notes.is_empty() {
                ui.label(dim("Esta versión no trae notas."));
            } else {
                ui.label(dim("Qué trae:"));
                for l in &notes {
                    ui.label(l);
                }
            }
            ui.add_space(6.0);
            ui.horizontal(|ui| {
                let appimage = std::env::var_os("APPIMAGE").is_some();
                if let (true, Some(url)) = (appimage, rel.appimage_url.clone()) {
                    if ui.add_enabled(!self.is_busy(), primary_button("Actualizar ahora")).clicked() {
                        self.confirm_simple = Some(ConfirmSimple {
                            title: format!("Actualizar a Silence {}", rel.version),
                            lines: vec![format!("Descargar {url}"), "Reemplazar el AppImage actual por el nuevo".into()],
                            warn: Some("Después, cierra y vuelve a abrir Silence.".into()),
                            action: SimpleAction::Update(url),
                        });
                    }
                }
                if ui.button("Ver en GitHub").clicked() {
                    let _ = std::process::Command::new("xdg-open").arg(&rel.page_url).spawn();
                }
                if ui.button("Más tarde").clicked() {
                    self.update = None;
                }
            });
        });
        true
    }

    fn tab_summary(&mut self, ui: &mut egui::Ui, r: &Report, s: &Snapshot) {
        ui.heading("Inicio");
        if self.update.is_some() {
            ui.add_space(12.0);
            self.update_card(ui);
        }
        if crate::selfinstall::needs_install() {
            ui.add_space(12.0);
            card(ui, |ui| {
                ui.label(RichText::new("Falta un paso para poder aplicar cambios").color(WARN).strong());
                ui.label(dim("Estás usando Silence como AppImage. Para cambiar la configuración del sistema necesita copiarse una vez a una ubicación protegida (así nadie puede suplantarlo para obtener permisos de administrador). Escanear y ver el estado funciona sin esto."));
                ui.add_space(6.0);
                if ui.add_enabled(!self.is_busy(), primary_button("Instalar en el sistema")).clicked() {
                    self.confirm_simple = Some(ConfirmSimple {
                        title: "Instalar en el sistema".into(),
                        lines: crate::selfinstall::preview(),
                        warn: Some("Se te pedirá la contraseña de administrador. Se hace una sola vez (y de nuevo si actualizas el AppImage).".into()),
                        action: SimpleAction::InstallSystem,
                    });
                }
            });
        }
        let (word, col, sentence) = if r.score >= 80 {
            ("Muy bien protegido", OK, "Tu equipo ya cuida bien tu privacidad.")
        } else if r.score >= 50 {
            ("Mejorable", WARN, "Hay protecciones fáciles que todavía no tienes activadas.")
        } else {
            ("Poco protegido", DANGER, "Tu equipo comparte más información de la necesaria.")
        };
        card(ui, |ui| {
            ui.horizontal(|ui| {
                gauge(ui, r.score);
                ui.add_space(14.0);
                ui.vertical(|ui| {
                    ui.add_space(14.0);
                    ui.label(dim("Tu nivel de privacidad"));
                    ui.label(RichText::new(word).size(30.0).strong().color(col));
                    ui.label(dim(sentence));
                    ui.add_space(10.0);
                    let n = r.todo().count();
                    ui.label(if n == 0 { RichText::new("No hay nada pendiente.").color(OK) } else { RichText::new(format!("{n} cosa(s) por mejorar")).color(DIM) });
                });
            });
        });

        if !self.drift.is_empty() {
            ui.add_space(16.0);
            card(ui, |ui| {
                ui.label(RichText::new("Algo que activaste se deshizo").color(WARN).strong());
                for d in &self.drift {
                    ui.label(format!("• {d}"));
                }
                ui.label(dim("Suele pasar tras una actualización o al conectarte a una red nueva. Vuelve a activar la protección."));
            });
        }

        let items = self.easy_items(r, s);
        if !self.easy_init {
            self.easy_sel = items.iter().filter(|i| i.default_on && !i.active).map(|i| i.id.to_string()).collect();
            self.easy_init = true;
        }
        ui.add_space(16.0);
        card(ui, |ui| {
            ui.label(title("Protégete con un clic"));
            ui.label(dim("Marcamos lo que recomendamos para tu equipo. Puedes cambiarlo. Todo se puede deshacer."));
            ui.add_space(8.0);
            for it in &items {
                ui.horizontal(|ui| {
                    if it.active {
                        ui.add_enabled(false, egui::Checkbox::new(&mut true, ""));
                    } else {
                        let mut on = self.easy_sel.contains(it.id);
                        if ui.checkbox(&mut on, "").changed() {
                            if on { self.easy_sel.insert(it.id.to_string()); } else { self.easy_sel.remove(it.id); }
                        }
                    }
                    ui.vertical(|ui| {
                        ui.horizontal(|ui| {
                            ui.label(RichText::new(it.title).strong().size(14.5));
                            if it.active { pill(ui, "Ya activa", OK); }
                        });
                        ui.label(dim(it.plain.clone()));
                    });
                });
                ui.add_space(6.0);
            }
            ui.add_space(10.0);
            let n = items.iter().filter(|i| self.easy_sel.contains(i.id) && !i.active).count();
            ui.horizontal(|ui| {
                let btn = egui::Button::new(RichText::new(if n == 0 { "Nada que activar".to_string() } else { format!("Protegerme ahora ({n})") }).size(16.0).strong().color(Color32::from_rgb(8, 30, 28)))
                    .fill(ACCENT)
                    .min_size(Vec2::new(240.0, 40.0));
                if ui.add_enabled(n > 0 && !self.is_busy(), btn).clicked() {
                    self.build_easy(r, s);
                }
                ui.label(dim("Antes de cambiar nada te mostramos qué se hará."));
            });
        });

        ui.add_space(20.0);
        card(ui, |ui| {
            ui.label(title("Modo pánico"));
            ui.label(dim("Si necesitas dejar el equipo ya: borra tu historial de terminal, el portapapeles, los archivos recientes, las miniaturas y los informes de fallos, y bloquea la pantalla."));
            ui.add_space(6.0);
            if ui.add_enabled(!self.is_busy(), egui::Button::new(RichText::new("Borrar rastros y bloquear").color(DANGER).strong())).clicked() {
                self.confirm_simple = Some(ConfirmSimple {
                    title: "Modo pánico".into(),
                    lines: vec![
                        "Borrar: archivos recientes, miniaturas, historial de terminal, portapapeles, informes de fallos".into(),
                        "No toca la papelera ni tus archivos".into(),
                        "Bloquear la pantalla (loginctl lock-session)".into(),
                    ],
                    warn: Some("Los rastros borrados no se pueden recuperar.".into()),
                    action: SimpleAction::Panic,
                });
            }
        });

        if self.advanced {
            self.summary_details(ui, r, s);
        } else {
            ui.add_space(16.0);
            ui.label(dim("¿Quieres ver el detalle técnico de cada cosa? Activa «Modo avanzado» abajo a la izquierda."));
        }
    }

    fn summary_details(&mut self, ui: &mut egui::Ui, r: &Report, s: &Snapshot) {
        ui.add_space(16.0);
        card(ui, |ui| {
            ui.label(title("Perfil de privacidad"));
            ui.label(dim("Decide cuánto quieres endurecer. Cada nivel incluye los anteriores."));
            ui.add_space(8.0);
            let mut chosen = None;
            ui.horizontal_wrapped(|ui| {
                for l in Level::ALL {
                    let sel = self.level == l;
                    let resp = Frame::NONE
                        .fill(if sel { ACCENT.gamma_multiply(0.14) } else { Color32::from_rgb(30, 36, 50) })
                        .stroke(Stroke::new(if sel { 1.5 } else { 1.0 }, if sel { ACCENT } else { BORDER }))
                        .corner_radius(CornerRadius::same(10))
                        .inner_margin(Margin::same(12))
                        .show(ui, |ui| {
                            ui.set_width(220.0);
                            ui.set_min_height(64.0);
                            ui.vertical(|ui| {
                                ui.label(RichText::new(l.label()).strong().size(15.0).color(if sel { ACCENT } else { TEXT }));
                                ui.label(dim(l.blurb()));
                            });
                        })
                        .response
                        .interact(Sense::click());
                    if resp.clicked() {
                        chosen = Some(l);
                    }
                }
            });
            if let Some(l) = chosen {
                self.set_level(l);
            }
            if r.hidden_by_level > 0 {
                ui.label(RichText::new(format!("Hay {} hallazgo(s) más que solo aparecen en perfiles más estrictos.", r.hidden_by_level)).color(INFO));
            }
        });

        ui.add_space(16.0);
        card(ui, |ui| {
            ui.label(title("Por categoría"));
            for c in Category::ALL {
                let all: Vec<&Finding> = r.findings.iter().filter(|f| f.rule.category == c && !f.ignored).collect();
                if all.is_empty() {
                    continue;
                }
                let ok = all.iter().filter(|f| f.status == Status::Ok).count();
                ui.horizontal(|ui| {
                    ui.allocate_ui_with_layout(Vec2::new(210.0, 18.0), Layout::left_to_right(Align::Center), |ui| {
                        ui.label(c.label());
                    });
                    ui.add(egui::ProgressBar::new(ok as f32 / all.len() as f32).desired_width(260.0).text(format!("{ok}/{}", all.len())));
                });
            }
        });

        if !s.notes.is_empty() {
            ui.add_space(16.0);
            card(ui, |ui| {
                ui.label(title("Límites de este escaneo"));
                for n in &s.notes {
                    ui.label(dim(format!("• {n}")));
                }
            });
        }
    }

    // ───────────── Recomendaciones ─────────────

    fn tab_recs(&mut self, ui: &mut egui::Ui, r: &Report) {
        ui.heading("Recomendaciones");
        ui.horizontal(|ui| {
            ui.add(egui::TextEdit::singleline(&mut self.search).hint_text("Buscar…").desired_width(220.0));
            for (f, label) in [(Filter::All, "Todas"), (Filter::Auto, "Automáticas"), (Filter::Manual, "Manuales"), (Filter::InUse, "En uso")] {
                if ui.add(egui::Button::selectable(self.filter == f, label)).clicked() {
                    self.filter = f;
                }
            }
        });
        ui.add_space(8.0);
        let q = self.search.to_lowercase();
        let visible: Vec<&Finding> = r
            .todo()
            .filter(|f| match self.filter {
                Filter::All => true,
                Filter::Auto => f.rule.fix.is_auto(),
                Filter::Manual => !f.rule.fix.is_auto(),
                Filter::InUse => f.safety == Safety::InUse,
            })
            .filter(|f| q.is_empty() || f.rule.title.to_lowercase().contains(&q) || f.rule.what.to_lowercase().contains(&q))
            .collect();
        if visible.is_empty() {
            card(ui, |ui| {
                ui.label(RichText::new("Nada pendiente con estos filtros.").color(OK));
            });
        }
        for c in Category::ALL {
            let group: Vec<&&Finding> = visible.iter().filter(|f| f.rule.category == c).collect();
            if group.is_empty() {
                continue;
            }
            ui.add_space(10.0);
            ui.label(RichText::new(c.label()).size(13.0).color(DIM).strong());
            for f in group {
                self.finding_card(ui, f);
            }
        }
        let ignored: Vec<&Finding> = r.findings.iter().filter(|f| f.ignored).collect();
        if !ignored.is_empty() {
            ui.add_space(16.0);
            ui.label(RichText::new("Ignoradas").size(13.0).color(DIM).strong());
            for f in ignored {
                card(ui, |ui| {
                    ui.horizontal(|ui| {
                        ui.label(&f.rule.title);
                        if ui.small_button("Dejar de ignorar").clicked() {
                            self.learned.set_ignored(&f.rule.id, false);
                            self.learned.save();
                            self.recompute();
                        }
                    });
                });
            }
        }
        // Barra de aplicar
        if !self.selected.is_empty() {
            ui.add_space(16.0);
            card(ui, |ui| {
                ui.horizontal(|ui| {
                    ui.label(format!("{} seleccionada(s)", self.selected.len()));
                    if ui.add_enabled(!self.is_busy(), primary_button("Revisar y aplicar")).clicked() {
                        self.confirm_rules = Some(ConfirmRules { ids: self.selected.iter().cloned().collect() });
                    }
                    if ui.button("Limpiar selección").clicked() {
                        self.selected.clear();
                    }
                });
            });
        }
    }

    fn finding_card(&mut self, ui: &mut egui::Ui, f: &Finding) {
        let id = f.rule.id.clone();
        let open = self.expanded.contains(&id);
        card(ui, |ui| {
            ui.horizontal(|ui| {
                if f.rule.fix.is_auto() && !is_guided(&f.rule) {
                    let mut sel = self.selected.contains(&id);
                    if ui.checkbox(&mut sel, "").changed() {
                        if sel { self.selected.insert(id.clone()); } else { self.selected.remove(&id); }
                    }
                } else {
                    ui.add_space(24.0);
                }
                ui.label(RichText::new(&f.rule.title).strong().size(14.5));
                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                    if ui.small_button(if open { "Ocultar" } else { "Detalles" }).clicked() {
                        if open { self.expanded.remove(&id); } else { self.expanded.insert(id.clone()); }
                    }
                    pill(ui, f.safety.label(), safety_color(f.safety));
                    pill(ui, f.rule.severity.label(), severity_color(f.rule.severity));
                    if !f.rule.fix.is_auto() {
                        pill(ui, "Manual", INFO);
                    }
                });
            });
            ui.label(dim(f.rule.what.trim()));
            if let Some(n) = &f.learned_note {
                ui.label(RichText::new(n).color(INFO).size(12.5));
            }
            if open {
                ui.add_space(8.0);
                ui.separator();
                detail_block(ui, "Por qué importa", &f.rule.why);
                detail_block(ui, "Qué puede dejar de funcionar", &f.rule.breaks);
                if !f.observed.is_empty() {
                    ui.label(RichText::new("Detectado en tu equipo").strong());
                    for o in &f.observed {
                        ui.label(dim(format!("• {o}")));
                    }
                }
                if let Some(e) = &f.evidence {
                    ui.label(RichText::new("Evidencia de uso").strong());
                    ui.label(RichText::new(format!("• {}", e.detail)).color(match e.in_use { Some(true) => WARN, _ => OK }));
                }
                if !f.blockers.is_empty() {
                    ui.label(RichText::new("Otros servicios activos dependen de esto:").color(DANGER).strong());
                    for b in &f.blockers {
                        ui.label(RichText::new(format!("• {b}")).color(DANGER));
                    }
                }
                ui.label(RichText::new(if f.rule.fix.is_auto() { "Se ejecutará" } else { "Pasos manuales" }).strong());
                for l in f.rule.fix.preview() {
                    ui.label(RichText::new(l).monospace().size(12.0).color(ACCENT));
                }
                ui.horizontal(|ui| {
                    if is_guided(&f.rule) {
                        if ui.add(primary_button("Abrir el configurador")).clicked() {
                            self.tab = Tab::Tools;
                        }
                    } else if f.rule.fix.is_auto() && ui.add_enabled(!self.is_busy(), egui::Button::new("Aplicar solo este")).clicked() {
                        self.confirm_rules = Some(ConfirmRules { ids: vec![id.clone()] });
                    }
                    if ui.button("Ignorar").clicked() {
                        self.learned.set_ignored(&id, true);
                        self.learned.save();
                        self.recompute();
                    }
                });
            }
        });
    }

    // ───────────── Catálogo ─────────────

    fn tab_catalog(&mut self, ui: &mut egui::Ui, r: &Report) {
        ui.heading("Catálogo completo");
        ui.label(dim("Todas las reglas que conoce Silence, aunque no apliquen a este equipo. Cada una explica qué hace, por qué y qué se rompe."));
        ui.add(egui::TextEdit::singleline(&mut self.search).hint_text("Buscar en el catálogo…").desired_width(320.0));
        let q = self.search.to_lowercase();
        let rules = self.rules.clone();
        for c in Category::ALL {
            let list: Vec<&Rule> = rules
                .iter()
                .filter(|x| x.category == c)
                .filter(|x| q.is_empty() || x.title.to_lowercase().contains(&q) || x.what.to_lowercase().contains(&q) || x.id.contains(&q))
                .collect();
            if list.is_empty() {
                continue;
            }
            ui.add_space(14.0);
            ui.label(RichText::new(format!("{} ({})", c.label(), list.len())).size(13.0).color(DIM).strong());
            for rule in list {
                let finding = r.findings.iter().find(|f| f.rule.id == rule.id);
                let (status, color) = match finding {
                    Some(f) if f.ignored => ("Ignorada", DIM),
                    Some(f) if f.status == Status::Todo => ("Pendiente", WARN),
                    Some(_) => ("Ya está bien", OK),
                    None if r.hidden_ids.contains(&rule.id) => ("Pendiente (perfil más estricto)", INFO),
                    None => ("No aplica a este equipo", DIM),
                };
                let open = self.expanded.contains(&format!("cat:{}", rule.id));
                card(ui, |ui| {
                    ui.horizontal(|ui| {
                        if let Some(f) = finding {
                            if f.status == Status::Todo && f.rule.fix.is_auto() && !f.ignored && !is_guided(&f.rule) {
                                let mut sel = self.selected.contains(&rule.id);
                                if ui.checkbox(&mut sel, "").changed() {
                                    if sel { self.selected.insert(rule.id.clone()); } else { self.selected.remove(&rule.id); }
                                }
                            }
                        }
                        ui.label(RichText::new(&rule.title).strong());
                        ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                            if ui.small_button(if open { "Ocultar" } else { "Detalles" }).clicked() {
                                let k = format!("cat:{}", rule.id);
                                if open { self.expanded.remove(&k); } else { self.expanded.insert(k); }
                            }
                            pill(ui, status, color);
                            pill(ui, rule.level.label(), DIM);
                        });
                    });
                    if open {
                        ui.separator();
                        ui.label(dim(rule.what.trim()));
                        detail_block(ui, "Por qué importa", &rule.why);
                        detail_block(ui, "Qué puede dejar de funcionar", &rule.breaks);
                        ui.label(RichText::new(if rule.fix.is_auto() { "Se ejecutaría" } else { "Pasos manuales" }).strong());
                        for l in rule.fix.preview() {
                            ui.label(RichText::new(l).monospace().size(12.0).color(ACCENT));
                        }
                        ui.label(dim(format!("id: {}", rule.id)));
                    }
                });
            }
        }
        if !self.selected.is_empty() {
            ui.add_space(16.0);
            card(ui, |ui| {
                ui.horizontal(|ui| {
                    ui.label(format!("{} seleccionada(s)", self.selected.len()));
                    if ui.add_enabled(!self.is_busy(), primary_button("Revisar y aplicar")).clicked() {
                        self.confirm_rules = Some(ConfirmRules { ids: self.selected.iter().cloned().collect() });
                    }
                });
            });
        }
    }

    // ───────────── Herramientas ─────────────

    fn tab_tools(&mut self, ui: &mut egui::Ui, s: &Snapshot) {
        ui.heading("Protecciones");
        ui.label(dim("Agrupadas por tema. Cada una se puede quitar y te muestra los cambios exactos antes de aplicarse."));
        ui.add_space(16.0);
        ui.horizontal_wrapped(|ui| {
            for (sec, label, _) in ToolSection::ALL {
                let txt = RichText::new(label).size(14.0);
                if ui.add(egui::Button::selectable(self.tools_section == sec, txt).min_size(Vec2::new(0.0, 36.0))).clicked() {
                    self.tools_section = sec;
                }
            }
        });
        if let Some((_, _, intro)) = ToolSection::ALL.iter().find(|(sec, _, _)| *sec == self.tools_section) {
            ui.add_space(6.0);
            ui.label(dim(*intro));
        }
        match self.tools_section {
            ToolSection::Network => self.section_network(ui, s),
            ToolSection::Browsers => self.section_browsers(ui, s),
            ToolSection::Files => self.section_files(ui),
            ToolSection::Apps => self.section_apps(ui, s),
            ToolSection::Devices => self.section_devices(ui, s),
            ToolSection::System => self.section_system(ui),
        }
        ui.add_space(20.0);
    }

    fn section_network(&mut self, ui: &mut egui::Ui, s: &Snapshot) {
        let busy = self.is_busy();
        // ── Firewall
        let active = self.active_keys.contains(tools::KEY_FIREWALL);
        tool_header(ui, "Firewall", active, |ui, this| {
            let fw = &s.firewall;
            match fw.backend.as_deref() {
                Some("firewalld") => {
                    ui.label(dim(format!("firewalld {} · zona por defecto: {}", if fw.active { "activo" } else { "apagado" }, fw.default_zone.clone().unwrap_or_default())));
                    for (z, info) in &fw.zones {
                        if !info.interfaces.is_empty() {
                            let open: Vec<String> = info.services.iter().chain(info.ports.iter()).cloned().collect();
                            ui.label(RichText::new(format!("• {} → zona «{z}»: {}", info.interfaces.join(", "), if open.is_empty() { "sin servicios".into() } else { open.join(", ") })).size(12.5));
                        }
                    }
                }
                Some("ufw") => {
                    ui.label(dim("ufw detectado."));
                }
                _ => {
                    ui.label(RichText::new("No hay firewalld ni ufw instalado. Instala uno para poder configurarlo.").color(WARN));
                }
            }
            ui.label(dim("Mueve tus redes a una zona restrictiva (NetworkManager manda sobre la zona por defecto, por eso se fija en cada red guardada)."));
            ui.horizontal(|ui| {
                ui.selectable_value(&mut this.fw_level, "standard".to_string(), "Estándar (zona public)");
                ui.selectable_value(&mut this.fw_level, "strict".to_string(), "Estricto (zona drop)");
            });
            ui.label(dim("Mantener accesible:"));
            ui.horizontal(|ui| {
                for (tok, label) in [("ssh", "SSH"), ("kdeconnect", "KDE Connect"), ("localsend", "LocalSend")] {
                    let mut on = this.fw_allow.contains(tok);
                    if ui.checkbox(&mut on, label).changed() {
                        if on { this.fw_allow.insert(tok.to_string()); } else { this.fw_allow.remove(tok); }
                    }
                }
            });
            if this.fw_level == "strict" && this.fw_allow.is_empty() {
                ui.label(RichText::new("El modo estricto descarta todo lo entrante; las conexiones que tú inicias funcionan normal.").color(WARN).size(12.5));
            }
        }, |ui, this| {
            let allow: Vec<String> = this.fw_allow.iter().cloned().collect();
            if ui.add_enabled(!busy && s.firewall.backend.is_some(), primary_button(if active { "Volver a aplicar" } else { "Aplicar firewall" })).clicked() {
                this.ask_tool(ToolRequest::Firewall { level: this.fw_level.clone(), allow }, "Firewall", true);
            }
            if active && ui.add_enabled(!busy, egui::Button::new("Quitar")).clicked() {
                this.revert_key(tools::KEY_FIREWALL, "Firewall");
            }
        }, self);

        // ── DNS
        let active = self.active_keys.contains(tools::KEY_DNS);
        let in_use = tools::provider_in_use(&s.dns.servers);
        tool_header(ui, "DNS privado", active, |ui, this| {
            ui.label(dim(format!("DNS actual: {}{}", if s.dns.servers.is_empty() { "—".to_string() } else { s.dns.servers.join(", ") }, match in_use { Some(p) => format!("  (ya usas {})", p.name), None => String::new() })));
            ui.label(dim("Tus consultas DNS dicen a tu proveedor de internet cada sitio que visitas. Con DNS-over-TLS viajan cifradas hacia un resolvedor que no es Google ni Cloudflare."));
            for p in &tools::DNS_PROVIDERS {
                let sel = this.dns_provider == p.id;
                let resp = Frame::NONE
                    .fill(if sel { ACCENT.gamma_multiply(0.12) } else { Color32::from_rgb(30, 36, 50) })
                    .stroke(Stroke::new(if sel { 1.5 } else { 1.0 }, if sel { ACCENT } else { BORDER }))
                    .corner_radius(CornerRadius::same(8))
                    .inner_margin(Margin::same(10))
                    .show(ui, |ui| {
                        ui.set_width(ui.available_width());
                        ui.label(RichText::new(format!("{} — {}", p.name, p.ips.join(", "))).strong());
                        ui.label(dim(p.tagline));
                        if sel {
                            for d in p.details {
                                ui.label(dim(format!("• {d}")));
                            }
                        }
                    })
                    .response
                    .interact(Sense::click());
                if resp.clicked() {
                    this.dns_provider = p.id.to_string();
                }
            }
            ui.checkbox(&mut this.dns_strict, "Exigir cifrado (más privado, pero sin internet en redes que bloqueen el puerto 853)");
            if !this.plan_env().nm_active || !this.plan_env().resolved_active {
                ui.label(RichText::new("Necesita NetworkManager y systemd-resolved activos.").color(WARN));
            }
        }, |ui, this| {
            if ui.add_enabled(!busy, primary_button(if active { "Cambiar proveedor" } else { "Usar este DNS" })).clicked() {
                this.ask_tool(ToolRequest::Dns { provider: this.dns_provider.clone(), strict: this.dns_strict }, "DNS privado", true);
            }
            if active && ui.add_enabled(!busy, egui::Button::new("Restaurar el de mi red")).clicked() {
                this.revert_key(tools::KEY_DNS, "DNS privado");
            }
        }, self);

        // ── Identidad de red
        let active = self.active_keys.contains(tools::KEY_IDENTITY);
        tool_header(ui, "Identidad de red: MAC cambiante y huella tipo Windows", active, |ui, this| {
            ui.label(dim(format!(
                "Ahora: nombre «{}»{}{}.",
                s.info.hostname,
                if tools::hostname_is_windows_style(&s.info.hostname) { " (estilo Windows)" } else if tools::hostname_is_phone_style(&s.info.hostname) { " (estilo celular)" } else { "" },
                if tools::tcp_is_windows_style(s) { " · pila TCP estilo Windows" } else { "" }
            )));
            ui.label(dim("Dificulta que una red identifique tu equipo y sepa que usa Linux."));
            ui.checkbox(&mut this.id_wifi, "MAC aleatoria en cada conexión Wi-Fi");
            ui.checkbox(&mut this.id_eth, "También en cable (Ethernet)");
            ui.checkbox(&mut this.id_dhcp, "Huella DHCP estilo Windows (clase «MSFT 5.0», identificador por MAC)");
            ui.label("Nombre del equipo en las redes:");
            ui.horizontal_wrapped(|ui| {
                ui.radio_value(&mut this.id_host, tools::HostnameStyle::Phone, "Celular (android-XXXXXXXXXXXXXXXX, como Android)");
                ui.radio_value(&mut this.id_host, tools::HostnameStyle::Windows, "PC con Windows (DESKTOP-XXXXXXX)");
                ui.radio_value(&mut this.id_host, tools::HostnameStyle::Keep, "No cambiarlo");
            });
            ui.label(dim("El nombre que ve cada red cambia en cada conexión, igual que la MAC. El nombre de tu sistema no cambia, así que no afecta a tus programas. Si usas KDE Connect, también anuncia tu equipo en la red; ciérralo en redes ajenas."));
            ui.checkbox(&mut this.id_tcp, "Pila TCP/IP estilo Windows (TTL 128, sin marcas de tiempo ni ECN)");
            ui.label(RichText::new("Límites honestos: el orden de las opciones DHCP y el tamaño de ventana TCP siguen siendo de Linux, así que una herramienta de huella avanzada (p0f, Fingerbank) aún puede distinguirlo. Con MAC aleatoria, redes con filtro por MAC o portales con tiempo limitado te tratarán como un equipo nuevo.").color(WARN).size(12.0));
        }, |ui, this| {
            let any = this.id_wifi || this.id_eth || this.id_dhcp || this.id_tcp || this.id_host != tools::HostnameStyle::Keep;
            if ui.add_enabled(!busy && any, primary_button(if active { "Volver a aplicar" } else { "Activar identidad" })).clicked() {
                this.ask_tool(
                    ToolRequest::Identity { wifi_mac: this.id_wifi, ethernet_mac: this.id_eth, dhcp_windows: this.id_dhcp, tcp_windows: this.id_tcp, hostname: this.id_host },
                    "Identidad de red",
                    true,
                );
            }
            if active && ui.add_enabled(!busy, egui::Button::new("Quitar")).clicked() {
                this.revert_key(tools::KEY_IDENTITY, "Identidad de red");
            }
        }, self);

        // ── IPv6
        let active = self.active_keys.contains(tools::KEY_IPV6);
        let off = tools::ipv6_off(s);
        tool_header(ui, "Apagar IPv6", active || off, |ui, this| {
            ui.label(dim(format!("IPv6 está {} ahora.", if off { "apagado" } else { "encendido" })));
            ui.label(dim("Impide cualquier comunicación por IPv6. Útil con VPN que no cubren IPv6 (evita fugas de tu dirección real). El loopback (::1) se conserva para que los programas locales sigan funcionando."));
            ui.label(RichText::new("Puede fallar en redes que solo ofrecen IPv6 (poco comunes) y en sitios o servicios que prefieren IPv6.").color(WARN).size(12.5));
        }, |ui, this| {
            if ui.add_enabled(!busy && !off, primary_button("Apagar IPv6")).clicked() {
                this.ask_tool(ToolRequest::Ipv6Off {}, "Apagar IPv6", true);
            }
            if active && ui.add_enabled(!busy, egui::Button::new("Volver a encender IPv6")).clicked() {
                this.revert_key(tools::KEY_IPV6, "Apagar IPv6");
            }
        }, self);
        self.card_trusted_networks(ui, s);
    }

    fn section_browsers(&mut self, ui: &mut egui::Ui, s: &Snapshot) {
        let busy = self.is_busy();
        // ── Navegadores
        let active = self.active_keys.contains(tools::KEY_BROWSERS);
        tool_header(ui, "Navegadores: privacidad con un clic", active, |ui, this| {
            let found: Vec<String> = s.browsers.iter().filter(|b| b.installed).map(|b| b.name.clone()).collect();
            ui.label(dim(format!("Detectados: {}", if found.is_empty() { "ninguno instalado como paquete del sistema".into() } else { found.join(", ") })));
            ui.label(dim("Firefox, Chromium, Chrome, Edge y Brave. Las versiones Flatpak/Snap de Chromium no se pueden configurar así (Firefox Flatpak sí, por perfil)."));
            ui.horizontal(|ui| {
                ui.selectable_value(&mut this.br_level, "balanced".to_string(), "Equilibrado (recomendado)");
                ui.selectable_value(&mut this.br_level, "maximum".to_string(), "Máximo");
            });
            if this.br_level == "balanced" {
                ui.label(dim("Sin telemetría, sin patrocinadores, sin estudios, sin rastreo entre sitios por diseño, WebRTC sin filtrar tu IP local. No debería romper ningún sitio."));
            } else {
                ui.label(RichText::new("Añade: cookies de terceros bloqueadas, protección estricta contra rastreo y huellas, solo-HTTPS, sin sugerencias de búsqueda. Algún sitio puede necesitar una excepción (inicio de sesión embebido).").color(WARN).size(12.5));
            }
            ui.checkbox(&mut this.br_ddg, "DuckDuckGo como buscador por defecto");
            ui.checkbox(&mut this.br_light, "Más ligero y rápido (menos RAM, menos escrituras a disco, sin avisos ni promociones)");
            if this.br_light {
                ui.label(dim("Firefox: 4 procesos de pestañas en vez de 8, guarda la sesión cada minuto y quita promociones. Chromium: ahorro de memoria en pestañas inactivas, sin avisos de navegador predeterminado ni descarga del modelo de IA local."));
            }
            ui.checkbox(&mut this.br_ublock, "Instalar uBlock Origin en Firefox (bloquea anuncios y rastreadores; Firefox lo descarga de Mozilla al abrirse)");
            ui.label(dim("En Firefox puedes cambiar el buscador luego; en la familia Chromium la política lo fija hasta que la quites."));
        }, |ui, this| {
            if ui.add_enabled(!busy, primary_button(if active { "Volver a aplicar" } else { "Proteger mis navegadores" })).clicked() {
                this.ask_tool(ToolRequest::Browsers { level: if this.br_light { format!("{}+light", this.br_level) } else { this.br_level.clone() }, ddg: this.br_ddg, ublock: this.br_ublock }, "Privacidad de navegadores", false);
            }
            if active && ui.add_enabled(!busy, egui::Button::new("Quitar")).clicked() {
                this.revert_key(tools::KEY_BROWSERS, "Privacidad de navegadores");
            }
        }, self);

        self.card_extensions(ui);
    }

    // ───────────── Secciones nuevas de Protecciones ─────────────

    fn card_trusted_networks(&mut self, ui: &mut egui::Ui, s: &Snapshot) {
        let busy = self.is_busy();
        let active = self.active_keys.contains(tools::KEY_TRUSTED);
        let nets: Vec<String> = s.nm_profiles.iter().filter(|p| p.kind == "802-11-wireless" || p.kind == "802-3-ethernet").map(|p| p.name.clone()).collect();
        let firewalld = s.firewall.backend.as_deref() == Some("firewalld");
        tool_header(ui, "Redes de confianza", active, |ui, this| {
            ui.label(dim("Marca tus redes de casa. Las demás (cafés, aeropuertos, hoteles) se tratan como públicas: el firewall bloquea todo lo que llega a tu equipo."));
            if !firewalld {
                ui.label(RichText::new("Necesita firewalld. Instálalo y actívalo desde la sección Firewall.").color(WARN));
            } else if nets.is_empty() {
                ui.label(dim("Aún no tienes redes guardadas."));
            } else {
                for n in &nets {
                    let mut on = this.trusted_sel.contains(n);
                    if ui.checkbox(&mut on, format!("{n}  ·  de confianza")).changed() {
                        if on { this.trusted_sel.insert(n.clone()); } else { this.trusted_sel.remove(n); }
                    }
                }
            }
        }, |ui, this| {
            if ui.add_enabled(!busy && firewalld && !nets.is_empty(), primary_button("Aplicar")).clicked() {
                let trusted: Vec<String> = nets.iter().filter(|n| this.trusted_sel.contains(*n)).cloned().collect();
                let others: Vec<String> = nets.iter().filter(|n| !this.trusted_sel.contains(*n)).cloned().collect();
                this.ask_tool(ToolRequest::TrustedNetworks { trusted, others }, "Redes de confianza", true);
            }
            if active && ui.add_enabled(!busy, egui::Button::new("Quitar")).clicked() {
                this.revert_key(tools::KEY_TRUSTED, "Redes de confianza");
            }
        }, self);
    }

    fn card_extensions(&mut self, ui: &mut egui::Ui) {
        tool_header(ui, "Extensiones de tus navegadores", self.ext_list.is_some(), |ui, this| {
            ui.label(dim("Una extensión con permiso para «leer todas las páginas» puede ver tus contraseñas, tus mensajes y tus compras. Revisa cuáles tienes y qué piden."));
            let Some(list) = &this.ext_list else { return };
            if list.is_empty() {
                ui.label(RichText::new("No se encontraron extensiones instaladas.").color(OK));
                return;
            }
            for e in list {
                ui.add_space(4.0);
                ui.horizontal(|ui| {
                    ui.label(RichText::new(&e.name).strong());
                    pill(ui, &e.browser, DIM);
                });
                if e.risks.is_empty() {
                    ui.label(dim("Pide pocos permisos."));
                }
                for r in &e.risks {
                    ui.label(RichText::new(format!("• {r}")).color(WARN).size(12.5));
                }
            }
            ui.add_space(6.0);
            ui.label(dim("Para quitar una, ábrela desde el menú de extensiones de tu navegador. Silence solo te avisa."));
        }, |ui, this| {
            if ui.add(primary_button(if this.ext_list.is_some() { "Volver a revisar" } else { "Revisar mis extensiones" })).clicked() {
                this.ext_list = Some(crate::extras::audit_extensions(&home_dir()));
            }
        }, self);
    }

    fn section_files(&mut self, ui: &mut egui::Ui) {
        let busy = self.is_busy();
        // ── Metadatos
        tool_header(ui, "Limpiar metadatos de archivos", false, |ui, this| {
            ui.label(dim("Una foto lleva dentro dónde y cuándo se tomó y con qué cámara; un PDF, el nombre de su autor. Límpialos antes de compartir."));
            ui.label(dim("Arrastra aquí archivos o carpetas, o escribe sus rutas (una por línea). Se crea una copia «nombre.limpio.ext»; el original no se toca."));
            ui.add(egui::TextEdit::multiline(&mut this.meta_input).desired_rows(4).desired_width(f32::INFINITY).hint_text("/home/tu-usuario/Imágenes/viaje.jpg"));
            ui.label(dim("JPEG y PNG se limpian al instante. Para PDF, documentos, audio y vídeo hace falta tener instalado «mat2» o «exiftool». Las fotos con rotación guardada pueden verse de lado."));
        }, |ui, this| {
            let any = !this.meta_input.trim().is_empty();
            if ui.add_enabled(!busy && any, primary_button("Limpiar y crear copias")).clicked() {
                let inputs: Vec<String> = this.meta_input.lines().map(String::from).collect();
                this.run_clean_metadata(inputs);
            }
            if ui.add_enabled(any, egui::Button::new("Vaciar lista")).clicked() {
                this.meta_input.clear();
            }
        }, self);

        // ── Rastros
        if self.traces_cache.is_none() {
            self.traces_cache = Some(crate::extras::traces(&home_dir()));
        }
        let traces = self.traces_cache.clone().unwrap_or_default();
        tool_header(ui, "Borrar rastros de tu uso", false, |ui, this| {
            ui.label(dim("Tu equipo recuerda lo que hiciste: archivos abiertos, comandos, lo que copiaste. Quien use tu equipo después puede verlo. Borrarlos no se puede deshacer."));
            for t in &traces {
                ui.add_space(4.0);
                ui.horizontal(|ui| {
                    let mut on = this.trace_sel.contains(t.id);
                    let empty = t.files == 0;
                    if ui.add_enabled(!empty, egui::Checkbox::new(&mut on, "")).changed() {
                        if on { this.trace_sel.insert(t.id.to_string()); } else { this.trace_sel.remove(t.id); }
                    }
                    ui.vertical(|ui| {
                        ui.horizontal(|ui| {
                            ui.label(RichText::new(t.label).strong());
                            if empty {
                                pill(ui, "Vacío", OK);
                            } else {
                                pill(ui, &format!("{} · {} elemento(s)", crate::extras::human_size(t.bytes), t.files), WARN);
                            }
                        });
                        ui.label(dim(t.why));
                    });
                });
            }
        }, |ui, this| {
            let n = this.trace_sel.len();
            let label = if n == 0 { "Elige qué borrar".to_string() } else { format!("Borrar lo marcado ({n})") };
            if ui.add_enabled(!busy && n > 0, primary_button(&label)).clicked() {
                let ids: Vec<String> = this.trace_sel.iter().cloned().collect();
                this.ask_clean_traces(ids);
            }
            if ui.button("Actualizar").clicked() {
                this.traces_cache = None;
            }
        }, self);
    }

    fn section_apps(&mut self, ui: &mut egui::Ui, s: &Snapshot) {
        let busy = self.is_busy();
        let active = self.active_keys.contains(tools::KEY_FLATPAK);
        let flat_ok = !s.flatpaks.is_empty();
        let wide: Vec<FlatpakApp> = s.flatpaks.iter().filter(|a| !a.broad.is_empty()).cloned().collect();
        tool_header(ui, "Permisos de tus apps Flatpak", active, |ui, this| {
            ui.label(dim("Cada app Flatpak vive en una «jaula». Algunas traen permiso para ver toda tu carpeta personal o todos tus dispositivos. Quítaselo a las que no lo necesiten."));
            if !flat_ok {
                ui.label(dim("No tienes apps Flatpak instaladas."));
            } else if wide.is_empty() {
                ui.label(RichText::new("Ninguna de tus apps Flatpak tiene permisos amplios.").color(OK));
            }
            for a in &wide {
                ui.add_space(6.0);
                ui.label(RichText::new(&a.id).strong());
                for b in &a.broad {
                    ui.label(RichText::new(format!("• {b}")).color(WARN).size(12.5));
                }
                let home = a.broad.iter().any(|b| b.contains("carpeta personal") || b.contains("sistema de archivos") || b.contains("raíz"));
                let dev = a.broad.iter().any(|b| b.contains("dispositivos"));
                ui.horizontal(|ui| {
                    if home && ui.add_enabled(!busy, egui::Button::new("Quitar acceso a mis archivos")).clicked() {
                        this.ask_tool(ToolRequest::Flatpak { app: a.id.clone(), home: true, devices: false }, &format!("Permisos de {}", a.id), false);
                    }
                    if dev && ui.add_enabled(!busy, egui::Button::new("Quitar acceso a dispositivos")).clicked() {
                        this.ask_tool(ToolRequest::Flatpak { app: a.id.clone(), home: false, devices: true }, &format!("Permisos de {}", a.id), false);
                    }
                });
            }
            ui.add_space(6.0);
            ui.label(dim("Algunas apps dejan de ver tus archivos: tendrás que darles acceso a una carpeta concreta (por ejemplo con Flatseal). Cierra y abre la app para que aplique."));
        }, |ui, this| {
            if active && ui.add_enabled(!busy, egui::Button::new("Deshacer todos los permisos recortados")).clicked() {
                this.revert_key(tools::KEY_FLATPAK, "Permisos de apps");
            }
        }, self);

        tool_header(ui, "Navegar de forma anónima con Tor", false, |ui, this| {
            let _ = this;
            ui.label(dim("Tor Browser oculta quién eres y desde dónde te conectas pasando tu tráfico por tres relés. Es más lento, pero útil para lo sensible."));
            ui.label(dim("Se instala desde Flathub (descarga unos 100 MB) y se abre desde el menú de aplicaciones."));
            if !flat_ok && !s.commands.contains("flatpak") {
                ui.label(RichText::new("Necesita Flatpak instalado.").color(WARN));
            }
        }, |ui, this| {
            if ui.add_enabled(!busy, primary_button("Instalar Tor Browser")).clicked() {
                this.confirm_simple = Some(ConfirmSimple {
                    title: "Instalar Tor Browser".into(),
                    lines: vec!["flatpak install -y flathub org.torproject.torbrowser-launcher".into()],
                    warn: Some("Descarga el programa desde Flathub. Puede pedirte la contraseña de administrador.".into()),
                    action: SimpleAction::InstallTor,
                });
            }
        }, self);
    }

    fn section_devices(&mut self, ui: &mut egui::Ui, s: &Snapshot) {
        let busy = self.is_busy();
        let active = self.active_keys.contains(tools::KEY_CAMERA);
        tool_header(ui, "Cámara web", active, |ui, _this| {
            ui.label(dim("Bloquea el controlador de las cámaras USB y las integradas. Ningún programa, ni malicioso, podrá encenderla. Surte efecto al reiniciar."));
            ui.label(RichText::new("No podrás hacer videollamadas hasta que lo quites.").color(WARN).size(12.5));
        }, |ui, this| {
            if !active && ui.add_enabled(!busy, primary_button("Bloquear cámara")).clicked() {
                this.ask_tool(ToolRequest::Camera {}, "Bloquear la cámara web", false);
            }
            if active && ui.add_enabled(!busy, egui::Button::new("Permitir la cámara otra vez")).clicked() {
                this.revert_key(tools::KEY_CAMERA, "Bloquear la cámara web");
            }
        }, self);

        tool_header(ui, "Micrófono", false, |ui, _this| {
            ui.label(dim("Silencia el micrófono de todo el sistema al instante (PipeWire). Es inmediato y no cambia nada de forma permanente."));
        }, |ui, this| {
            if ui.add_enabled(!busy, primary_button("Silenciar micrófono")).clicked() {
                this.set_mic_mute(true);
            }
            if ui.add_enabled(!busy, egui::Button::new("Activar micrófono")).clicked() {
                this.set_mic_mute(false);
            }
        }, self);

        let installed = s.packages.contains("usbguard");
        let running = s.units.get("usbguard.service").map(|u| u.is_active()).unwrap_or(false);
        tool_header(ui, "Puertos USB (USBGuard)", installed && running, |ui, _this| {
            ui.label(dim("Un USB desconocido puede hacerse pasar por un teclado y teclear comandos por ti. USBGuard bloquea todo dispositivo nuevo hasta que lo apruebes."));
            if !installed {
                ui.label(RichText::new("No está instalado. Silence lo instala con el gestor de paquetes de tu distribución, permite lo que tienes conectado ahora (para no dejarte sin teclado ni ratón) y lo enciende.").size(12.5).color(WARN));
            } else if running {
                ui.label(RichText::new("USBGuard está activo: los USB nuevos quedan bloqueados hasta que los apruebes con «usbguard allow-device».").color(OK));
            } else {
                ui.label(dim("USBGuard está instalado pero apagado."));
            }
        }, |ui, this| {
            if !installed {
                if ui.add_enabled(!busy, primary_button("Instalar y activar")).clicked() {
                    this.ask_tool(ToolRequest::Usbguard { mode: "setup".into() }, "Instalar y activar USBGuard", false);
                }
            } else if running {
                if ui.add_enabled(!busy, egui::Button::new("Apagar USBGuard")).clicked() {
                    this.ask_tool(ToolRequest::Usbguard { mode: "off".into() }, "Apagar USBGuard", false);
                }
            } else if ui.add_enabled(!busy, primary_button("Encender USBGuard")).clicked() {
                this.ask_tool(ToolRequest::Usbguard { mode: "on".into() }, "Encender USBGuard", false);
            }
        }, self);
    }

    fn section_system(&mut self, ui: &mut egui::Ui) {
        let busy = self.is_busy();
        let report = self.report.clone();
        let pending: Vec<(String, String)> = report
            .as_ref()
            .map(|r| r.todo().filter(|f| f.rule.id.starts_with("hardening.") && f.rule.fix.is_auto()).map(|f| (f.rule.id.clone(), f.rule.title.clone())).collect())
            .unwrap_or_default();
        tool_header(ui, "Endurecimiento del sistema", pending.is_empty(), |ui, _this| {
            ui.label(dim("Ajustes del kernel que cierran puertas a ataques: espionaje entre programas, direcciones internas visibles, volcados de memoria y más. Casi nunca se nota nada."));
            if pending.is_empty() {
                ui.label(RichText::new("Todo lo recomendado ya está aplicado.").color(OK));
            }
            for (_, title) in &pending {
                ui.label(format!("• {title}"));
            }
            ui.add_space(4.0);
            ui.label(dim("Sobre el arranque: tu kernel ya trae activadas las defensas de memoria más importantes, así que no hace falta tocar sus parámetros."));
        }, |ui, this| {
            if ui.add_enabled(!busy && !pending.is_empty(), primary_button(&format!("Aplicar ({})", pending.len()))).clicked() {
                this.confirm_rules = Some(ConfirmRules { ids: pending.iter().map(|(id, _)| id.clone()).collect() });
            }
        }, self);

        tool_header(ui, "Llaves SSH", false, |ui, this| {
            ui.label(dim("Una llave SSH sin contraseña da acceso a tus servidores a quien la copie. Comprobamos ~/.ssh: permisos abiertos y llaves sin protección."));
            match &this.ssh_notes {
                None => {}
                Some(n) if n.is_empty() => {
                    ui.label(RichText::new("Todo en orden en ~/.ssh.").color(OK));
                }
                Some(n) => {
                    for l in n {
                        ui.label(RichText::new(format!("• {l}")).color(WARN).size(12.5));
                    }
                }
            }
        }, |ui, this| {
            if ui.add(primary_button(if this.ssh_notes.is_some() { "Volver a revisar" } else { "Revisar mis llaves" })).clicked() {
                this.ssh_notes = Some(crate::extras::ssh_audit(&home_dir()));
            }
        }, self);
    }

    // ───────────── Acciones directas (sin root) ─────────────

    fn run_clean_metadata(&mut self, inputs: Vec<String>) {
        self.start_op("Limpiando metadatos…", false, vec![], move || {
            let files = crate::extras::expand_paths(&inputs);
            if files.is_empty() {
                return vec![direct_outcome("extras.meta", "Limpiar metadatos", false, "No se encontró ningún archivo en esas rutas.".into())];
            }
            let r = RealRunner { timeout: Duration::from_secs(120) };
            let has = |c: &str| r.exists(c);
            let run = |p: &str, a: &[&str]| r.run(p, a).ok;
            let mut lines = Vec::new();
            let mut done = 0;
            for f in &files {
                let res = crate::extras::clean_file(f, &has, &run);
                if res.out.is_some() {
                    done += 1;
                }
                lines.push(format!("{}: {}", f.file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_default(), res.message));
            }
            vec![direct_outcome("extras.meta", &format!("Metadatos limpiados en {done} de {} archivo(s)", files.len()), done > 0, lines.join("\n"))]
        });
    }

    fn ask_clean_traces(&mut self, ids: Vec<String>) {
        let traces = self.traces_cache.clone().unwrap_or_default();
        let mut lines = Vec::new();
        for id in &ids {
            if let Some(t) = traces.iter().find(|t| t.id == id.as_str()) {
                lines.push(format!("{} ({}):", t.label, crate::extras::human_size(t.bytes)));
                for p in &t.paths {
                    lines.push(format!("   {}", p.display()));
                }
            }
        }
        self.confirm_simple = Some(ConfirmSimple {
            title: "Borrar rastros".into(),
            lines,
            warn: Some("Esto no se puede deshacer.".into()),
            action: SimpleAction::CleanTraces(ids),
        });
    }

    fn run_simple(&mut self, action: SimpleAction) {
        match action {
            SimpleAction::CleanTraces(ids) => self.run_clean_traces(ids, false),
            SimpleAction::Panic => self.run_clean_traces(["recent", "thumbs", "shell", "clipboard", "crash"].iter().map(|s| s.to_string()).collect(), true),
            SimpleAction::Update(url) => {
                self.start_op("Descargando la actualización…", false, vec![], move || {
                    let target = std::env::var_os("APPIMAGE").map(std::path::PathBuf::from);
                    let Some(target) = target else {
                        return vec![direct_outcome("extras.update", "Actualizar", false, "Solo se puede actualizar solo el AppImage.".into())];
                    };
                    match crate::update::replace_appimage(&RealRunner { timeout: Duration::from_secs(660) }, &url, &target) {
                        Ok(()) => vec![direct_outcome("extras.update", "Actualización lista", true, "Se reemplazó el AppImage. Cierra Silence y ábrelo de nuevo para usar la versión nueva. Si ya lo habías instalado en el sistema, te pedirá instalarlo otra vez.".into())],
                        Err(e) => vec![direct_outcome("extras.update", "Actualizar", false, e)],
                    }
                });
            }
            SimpleAction::InstallSystem => {
                self.start_op("Instalando Silence en el sistema…", false, vec![], || {
                    match crate::selfinstall::install_system() {
                        Ok(()) => vec![direct_outcome("extras.install", "Instalar en el sistema", true, "Listo. Ya puedes aplicar cambios que necesiten permisos de administrador.".into())],
                        Err(e) => vec![direct_outcome("extras.install", "Instalar en el sistema", false, e)],
                    }
                });
            }
            SimpleAction::InstallTor => {
                self.start_op("Instalando Tor Browser…", false, vec![], || {
                    let r = RealRunner { timeout: Duration::from_secs(900) };
                    let o = r.run("flatpak", &["install", "-y", "flathub", "org.torproject.torbrowser-launcher"]);
                    let msg = if o.ok { "Instalado. Ábrelo desde el menú de aplicaciones («Tor Browser Launcher»).".to_string() } else { format!("No se pudo instalar: {}", o.stderr.trim()) };
                    vec![direct_outcome("extras.tor", "Instalar Tor Browser", o.ok, msg)]
                });
            }
        }
    }

    fn run_clean_traces(&mut self, ids: Vec<String>, lock: bool) {
        self.traces_cache = None;
        self.trace_sel.clear();
        self.start_op(if lock { "Modo pánico…" } else { "Borrando rastros…" }, false, vec![], move || {
            let home = home_dir();
            let mut lines = Vec::new();
            let mut ok = true;
            for id in &ids {
                match crate::extras::clean_trace(&home, id) {
                    Ok(n) => lines.push(format!("{id}: {n} elemento(s) borrado(s)")),
                    Err(e) => {
                        ok = false;
                        lines.push(format!("{id}: {e}"));
                    }
                }
            }
            if lock {
                let l = RealRunner::default().run("loginctl", &["lock-session"]);
                lines.push(if l.ok { "Pantalla bloqueada.".to_string() } else { "No se pudo bloquear la pantalla: hazlo tú con Meta+L.".to_string() });
            }
            vec![direct_outcome("extras.traces", if lock { "Modo pánico" } else { "Borrar rastros" }, ok, lines.join("\n"))]
        });
    }

    fn set_mic_mute(&mut self, mute: bool) {
        let o = RealRunner::default().run("wpctl", &["set-mute", "@DEFAULT_AUDIO_SOURCE@", if mute { "1" } else { "0" }]);
        let msg = if !o.ok {
            "No se pudo cambiar el micrófono (¿PipeWire/wpctl instalado?).".to_string()
        } else if mute {
            "Micrófono silenciado.".to_string()
        } else {
            "Micrófono activado.".to_string()
        };
        self.toast = Some((msg, Instant::now()));
    }

    fn tab_analysis(&mut self, ui: &mut egui::Ui, s: &Snapshot) {
        ui.heading("Análisis del sistema");
        ui.label(dim("Lo que Silence ve ahora mismo. Nada de esto sale de tu equipo."));
        section(ui, "Sistema", true, |ui| {
            let i = &s.info;
            for (k, v) in [
                ("Distribución", i.distro_name.clone()),
                ("Kernel", i.kernel.clone()),
                ("Escritorio", format!("{} ({})", i.desktop, i.session_type)),
                ("Init", i.init.clone()),
                ("Gestor de paquetes", i.pkg_manager.clone().unwrap_or("desconocido".into())),
                ("Paquetes instalados", s.packages.len().to_string()),
                ("Hardware", i.hardware.iter().cloned().collect::<Vec<_>>().join(", ")),
                ("Control de acceso", format!("{} ({})", s.mac.system, if s.mac.enforcing { "activo" } else { "inactivo" })),
            ] {
                ui.horizontal(|ui| {
                    ui.allocate_ui_with_layout(Vec2::new(170.0, 18.0), Layout::left_to_right(Align::Center), |ui| {
                        ui.label(dim(k));
                    });
                    ui.label(v);
                });
            }
        });
        section(ui, &format!("Puertos en escucha ({})", s.listeners.len()), true, |ui| {
            egui::Grid::new("ports").striped(true).show(ui, |ui| {
                for h in ["Proto", "Puerto", "Dirección", "Alcance", "Programa"] {
                    ui.label(RichText::new(h).strong());
                }
                ui.end_row();
                let mut ls: Vec<&Listener> = s.listeners.iter().collect();
                ls.sort_by_key(|l| (l.exposure == Exposure::Loopback, l.port));
                for l in ls {
                    let (txt, col) = match l.exposure {
                        Exposure::Loopback => ("solo este equipo", OK),
                        Exposure::AllInterfaces => ("toda la red", WARN),
                        Exposure::Specific => ("una interfaz", INFO),
                    };
                    ui.label(l.proto.to_uppercase());
                    ui.label(l.port.to_string());
                    ui.label(&l.addr);
                    ui.label(RichText::new(txt).color(col));
                    ui.label(l.process.clone().unwrap_or("—".into()));
                    ui.end_row();
                }
            });
        });
        section(ui, &format!("Conexiones salientes ahora ({})", s.connections.len()), false, |ui| {
            let mut by: std::collections::BTreeMap<String, Vec<&Connection>> = Default::default();
            for c in s.connections.iter().filter(|c| !c.remote_addr.starts_with("127.") && c.remote_addr != "::1") {
                by.entry(c.process.clone().unwrap_or("(otros usuarios / sistema)".into())).or_default().push(c);
            }
            for (p, cs) in by {
                ui.label(RichText::new(format!("{p} — {} conexión(es)", cs.len())).strong());
                let mut remotes: Vec<String> = cs.iter().map(|c| format!("{}:{}", c.remote_addr, c.remote_port)).collect();
                remotes.sort();
                remotes.dedup();
                ui.label(dim(remotes.into_iter().take(6).collect::<Vec<_>>().join("  ·  ")));
            }
        });
        section(ui, "DNS", false, |ui| {
            let d = &s.dns;
            ui.label(format!("Servidores: {}", if d.servers.is_empty() { "—".into() } else { d.servers.join(", ") }));
            ui.label(format!("DNS-over-TLS: {} · LLMNR: {} · mDNS: {}", if d.dns_over_tls { "sí" } else { "no" }, if d.llmnr.is_empty() { "no" } else { &d.llmnr }, if d.mdns { "sí" } else { "no" }));
        });
        section(ui, "Almacenamiento", false, |ui| {
            ui.label(format!("Disco del sistema cifrado: {}", match s.storage.root_encrypted { Some(true) => "sí", Some(false) => "no", None => "desconocido" }));
            for sw in &s.storage.swaps {
                ui.label(format!("Swap {} ({}): {}", sw.device, sw.kind, match sw.encrypted { Some(true) => "protegida", Some(false) => "SIN cifrar", None => "desconocido" }));
            }
        });
        section(ui, &format!("Redes guardadas ({})", s.nm_profiles.len()), false, |ui| {
            for p in &s.nm_profiles {
                ui.label(format!("{} ({}){}", p.name, p.kind, if p.active { " · activa" } else { "" }));
            }
        });
        section(ui, &format!("Servicios en ejecución ({})", s.running_services.len()), false, |ui| {
            for (n, d) in &s.running_services {
                ui.label(format!("{n} — {d}"));
            }
        });
        section(ui, &format!("Inicio automático ({})", s.autostart.len()), false, |ui| {
            for a in &s.autostart {
                ui.label(format!("{} {}", a.name, if a.system_wide { "(del sistema)" } else { "" }));
            }
        });
    }

    // ───────────── Historial ─────────────

    fn tab_history(&mut self, ui: &mut egui::Ui) {
        ui.heading("Historial");
        ui.label(dim("Cada cambio guarda cómo deshacerlo. Revertir devuelve el estado exacto de antes."));
        if self.history.is_empty() {
            card(ui, |ui| {
                ui.label(dim("Todavía no has aplicado nada."));
            });
        }
        let entries = self.history.clone();
        for e in entries {
            card(ui, |ui| {
                ui.horizontal(|ui| {
                    ui.label(RichText::new(&e.title).strong());
                    pill(ui, if e.scope == Scope::Root { "Sistema" } else { "Usuario" }, DIM);
                    if e.reverted {
                        pill(ui, "Revertido", DIM);
                    } else {
                        pill(ui, "Activo", OK);
                    }
                    ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                        if !e.reverted && ui.add_enabled(!self.is_busy(), egui::Button::new("Revertir")).clicked() {
                            self.revert_entry(e.clone());
                        }
                        ui.label(dim(fmt_ts(e.ts)));
                    });
                });
                for n in &e.notes {
                    ui.label(RichText::new(n).color(WARN).size(12.0));
                }
            });
        }
    }

    // ───────────── Acerca ─────────────

    fn tab_about(&mut self, ui: &mut egui::Ui, r: &Report, s: &Snapshot) {
        ui.heading("Acerca de Silence");
        ui.add_space(8.0);
        if !self.update_card(ui) {
            card(ui, |ui| {
                ui.label(title("Actualizaciones"));
                ui.label(dim(format!("Versión instalada: {}", crate::update::CURRENT)));
                if let Some(m) = self.update_status.clone() {
                    ui.label(m);
                }
                ui.horizontal(|ui| {
                    if ui.add_enabled(self.update_rx.is_none(), primary_button("Buscar actualizaciones")).clicked() {
                        self.check_updates(true);
                    }
                });
            });
        }
        let mut auto = !self.learned.no_update_check;
        if ui.checkbox(&mut auto, "Buscar actualizaciones al abrir (consulta GitHub)").changed() {
            self.learned.no_update_check = !auto;
            self.learned.save();
        }
        ui.add_space(8.0);
        ui.label(dim("Silence es una aplicación de privacidad para quienes usan Linux: te dice qué comparte tu equipo, lo explica sin jerga y lo arregla con tu permiso."));
        card(ui, |ui| {
            ui.label(title("Qué hace y qué no hace"));
            for t in [
                "No tiene telemetría. Su única conexión es consultar en GitHub si hay una versión nueva (GitHub ve tu IP, como en cualquier descarga); no envía nada de tu sistema y puedes desactivarlo abajo.",
                "Escanear es solo lectura. Nada cambia hasta que confirmas, viendo los comandos exactos.",
                "Antes de recomendar apagar algo, comprueba si lo estás usando (impresoras, Bluetooth, SSH…).",
                "Todo cambio guarda cómo deshacerse; el helper con permisos solo acepta acciones del catálogo.",
                "Aprende de ti en local: si revertes algo, no vuelve a insistirte. Nada de eso sale de tu equipo.",
            ] {
                ui.label(format!("• {t}"));
            }
        });
        ui.add_space(14.0);
        card(ui, |ui| {
            ui.label(title("Lo que no puede garantizar"));
            for t in [
                "El puntaje es una guía, no una certificación de seguridad.",
                "Sin permisos de administrador no ve los procesos de otros usuarios ni las reglas internas del firewall.",
                "Un sitio puede seguir identificándote por otros medios (cuenta, huella del navegador, comportamiento).",
                "Las reglas se probaron en Fedora; en otras distribuciones los nombres de servicios pueden variar.",
            ] {
                ui.label(dim(format!("• {t}")));
            }
        });
        ui.add_space(14.0);
        card(ui, |ui| {
            ui.label(title("Exportar reporte"));
            ui.checkbox(&mut self.redact, "Ocultar usuario, nombre del equipo, IPs y MACs");
            if ui.button("Guardar reporte (Markdown)").clicked() {
                let md = crate::report::markdown(r, s, self.redact);
                let dir = std::env::var("HOME").map(|h| format!("{h}/Documents")).unwrap_or_else(|_| ".".into());
                let _ = std::fs::create_dir_all(&dir);
                let path = format!("{dir}/silence-reporte-{}.md", chrono::Local::now().format("%Y%m%d-%H%M"));
                self.toast = Some((match std::fs::write(&path, md) { Ok(()) => format!("Guardado en {path}"), Err(e) => format!("No se pudo guardar: {e}") }, Instant::now()));
            }
        });
        ui.add_space(14.0);
        ui.label(dim(format!("Silence {} · {} reglas", env!("CARGO_PKG_VERSION"), self.rules.len())));
    }
}

/// Reglas cuyo arreglo necesita decisiones del usuario: se configuran en Herramientas, no con un clic.
fn is_guided(rule: &Rule) -> bool {
    matches!(rule.fix, Fix::Firewall { .. })
}

fn detail_block(ui: &mut egui::Ui, head: &str, body: &str) {
    ui.label(RichText::new(head).strong());
    ui.label(dim(body.trim()));
}

fn section(ui: &mut egui::Ui, name: &str, open: bool, add: impl FnOnce(&mut egui::Ui)) {
    ui.add_space(10.0);
    egui::CollapsingHeader::new(RichText::new(name).strong().size(14.5)).default_open(open).show(ui, |ui| {
        card(ui, add);
    });
}

/// Tarjeta de herramienta: cabecera con estado, cuerpo con opciones y barra de botones.
fn tool_header(
    ui: &mut egui::Ui,
    name: &str,
    active: bool,
    body: impl FnOnce(&mut egui::Ui, &mut App),
    buttons: impl FnOnce(&mut egui::Ui, &mut App),
    app: &mut App,
) {
    ui.add_space(20.0);
    card(ui, |ui| {
        ui.horizontal(|ui| {
            ui.label(RichText::new(name).size(18.0).strong());
            pill(ui, if active { "Activo" } else { "Inactivo" }, if active { OK } else { DIM });
        });
        soft_sep(ui);
        body(ui, app);
        soft_sep(ui);
        ui.horizontal(|ui| buttons(ui, app));
    });
}

pub fn run() -> i32 {
    let opts = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([1120.0, 780.0])
            .with_min_inner_size([860.0, 560.0])
            .with_title("Silence")
            .with_app_id("silence"),
        ..Default::default()
    };
    match eframe::run_native(
        "Silence",
        opts,
        Box::new(|cc| {
            setup_style(&cc.egui_ctx);
            Ok(Box::new(App::new(cc.egui_ctx.clone())))
        }),
    ) {
        Ok(()) => 0,
        Err(e) => {
            eprintln!("No se pudo abrir la interfaz: {e}");
            1
        }
    }
}

fn home_dir() -> std::path::PathBuf {
    std::path::PathBuf::from(std::env::var("HOME").unwrap_or_default())
}

fn direct_outcome(key: &str, title: &str, ok: bool, message: String) -> Outcome {
    Outcome { key: key.into(), title: title.into(), ok, message, entry_id: None }
}

fn hostname_line(name: &str) -> String {
    if tools::hostname_is_phone_style(name) {
        "Nombre del equipo como un celular (android-XXXXXXXXXXXXXXXX), distinto en cada conexión".to_string()
    } else {
        "Nombre del equipo como un PC con Windows (DESKTOP-XXXXXXX), distinto en cada conexión".to_string()
    }
}
