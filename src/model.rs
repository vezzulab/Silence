//! Modelo de datos: reglas (conocimiento), snapshot (lo que vemos en el sistema)
//! y hallazgos (resultado de cruzar ambos).

use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

// ───────────────────────── Reglas ─────────────────────────

/// Perfiles acumulativos: Strict incluye Basic, Paranoid incluye ambos.
#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug, Hash)]
#[serde(rename_all = "lowercase")]
pub enum Level {
    Basic,
    Strict,
    Paranoid,
}

impl Level {
    pub const ALL: [Level; 3] = [Level::Basic, Level::Strict, Level::Paranoid];
    pub fn label(self) -> &'static str {
        match self {
            Level::Basic => "Básico",
            Level::Strict => "Estricto",
            Level::Paranoid => "Paranoico",
        }
    }
    pub fn blurb(self) -> &'static str {
        match self {
            Level::Basic => "Cambios que casi nadie nota. Recomendado para todos.",
            Level::Strict => "Más privacidad; algunas funciones de conveniencia pueden dejar de estar.",
            Level::Paranoid => "Máxima reducción de superficie. Puede requerir ajustes manuales.",
        }
    }
    pub fn id(self) -> &'static str {
        match self {
            Level::Basic => "basic",
            Level::Strict => "strict",
            Level::Paranoid => "paranoid",
        }
    }
    pub fn from_id(s: &str) -> Option<Level> {
        Level::ALL.into_iter().find(|l| l.id() == s)
    }
}

#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug, Hash)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Low,
    Medium,
    High,
}

impl Severity {
    pub fn weight(self) -> u32 {
        match self {
            Severity::Low => 1,
            Severity::Medium => 3,
            Severity::High => 6,
        }
    }
    pub fn label(self) -> &'static str {
        match self {
            Severity::Low => "Baja",
            Severity::Medium => "Media",
            Severity::High => "Alta",
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug, Hash)]
#[serde(rename_all = "snake_case")]
pub enum Category {
    Telemetry,
    Network,
    Services,
    Storage,
    Desktop,
    Hardening,
    Browser,
}

impl Category {
    pub const ALL: [Category; 7] = [
        Category::Telemetry,
        Category::Network,
        Category::Services,
        Category::Storage,
        Category::Desktop,
        Category::Browser,
        Category::Hardening,
    ];
    pub fn label(self) -> &'static str {
        match self {
            Category::Telemetry => "Telemetría y reportes",
            Category::Network => "Red",
            Category::Services => "Servicios",
            Category::Storage => "Disco y arranque",
            Category::Desktop => "Escritorio",
            Category::Hardening => "Endurecimiento del sistema",
            Category::Browser => "Navegadores y apps",
        }
    }
}

/// Cuánto se nota en el uso diario si se aplica el arreglo (juicio editorial de la regla).
#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug, Hash)]
#[serde(rename_all = "lowercase")]
pub enum Breakage {
    #[serde(rename = "none")]
    Nothing,
    Minor,
    Notable,
}

#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Eq, Debug, Hash, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceKind {
    Bluetooth,
    Printers,
    Ssh,
    FileShare,
    Modem,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
#[serde(default)]
pub struct Applies {
    /// Todas estas unidades deben estar activas.
    pub units_active: Vec<String>,
    /// Todos estos comandos deben existir.
    pub commands: Vec<String>,
    /// Al menos uno debe coincidir con XDG_CURRENT_DESKTOP (sin distinguir mayúsculas).
    pub desktops: Vec<String>,
    /// Al menos uno debe coincidir con ID / ID_LIKE de os-release.
    pub distros: Vec<String>,
    /// Hardware requerido: wifi, bluetooth, camera, modem.
    pub hardware: Vec<String>,
    /// Solo si el hostname no es genérico (localhost, fedora, ubuntu…).
    pub non_generic_hostname: bool,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Presence {
    Present,
    Absent,
}

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum CmpOp {
    /// Debe ser exactamente igual.
    #[default]
    Eq,
    /// Numérico: cualquier valor >= want es aceptable (más estricto también cuenta).
    AtLeast,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Detect {
    /// Dispara si alguna de las unidades existe y está habilitada o activa.
    Unit { units: Vec<String> },
    /// Dispara si algún paquete está instalado.
    Package { names: Vec<String> },
    /// Dispara si el valor actual del sysctl no cumple `want` (según `op`).
    Sysctl {
        key: String,
        want: String,
        #[serde(default)]
        op: CmpOp,
    },
    Gsettings { schema: String, key: String, want: String },
    /// `missing_is_bad`: si la clave no existe se usa el valor por defecto de la app.
    Kconfig {
        file: String,
        group: String,
        key: String,
        want: String,
        #[serde(default)]
        missing_is_bad: bool,
    },
    FileRegex {
        globs: Vec<String>,
        pattern: String,
        fire_when: Presence,
    },
    /// Comprobación implementada en código (ver engine.rs).
    Builtin { name: String },
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct SysctlSetting {
    pub key: String,
    pub value: String,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum UnitVerb {
    Reload,
    Restart,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct NmProp {
    pub name: String,
    pub value: String,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct FileSpec {
    pub path: String,
    pub content: String,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct UnitCmd {
    pub verb: UnitVerb,
    pub unit: String,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Fix {
    /// Detiene y deshabilita (o enmascara si la unidad es estática). Reversible.
    DisableUnits { units: Vec<String> },
    /// Habilita y arranca servicios. Reversible (revertir los deshabilita). Solo desde herramientas internas.
    EnableUnits { units: Vec<String> },
    /// Instala paquetes (solo una lista cerrada) con el gestor de paquetes de la distribución.
    /// Reversible: revertir los desinstala. Solo desde herramientas internas.
    InstallPackages { names: Vec<String> },
    /// Crea la política de USBGuard con los dispositivos conectados ahora, si aún no hay reglas.
    UsbguardPolicy {},
    Sysctl { settings: Vec<SysctlSetting> },
    /// Crea archivos (drop-ins) bajo /etc. Reversible.
    WriteFiles {
        files: Vec<FileSpec>,
        #[serde(default)]
        after: Vec<UnitCmd>,
    },
    Gsettings { schema: String, key: String, value: String },
    Kwrite { file: String, group: String, key: String, value: String },
    /// Bloque de preferencias en user.js de cada perfil de Firefox (ver firefox.rs).
    /// `level`: None = solo telemetría; "balanced" o "maximum" para el endurecimiento completo.
    FirefoxPrivacyPrefs {
        #[serde(default)]
        level: Option<String>,
    },
    /// Fija propiedades de NetworkManager en los perfiles guardados de ciertos tipos
    /// (p. ej. `802-11-wireless`, `802-3-ethernet`). Reversible: se guarda el valor previo.
    NmProfiles { types: Vec<String>, props: Vec<NmProp> },
    /// Como `NmProfiles`, pero solo en las redes guardadas con esos nombres. Reversible.
    NmProfilesNamed { names: Vec<String>, props: Vec<NmProp> },
    /// Quita permisos a una app Flatpak con un «override» de usuario (no necesita root).
    /// Reversible: se guarda el archivo de overrides anterior.
    FlatpakOverride { app: String, args: Vec<String> },
    /// Cambia el nombre del equipo (hostname). Reversible.
    SetHostname { name: String },
    /// Configura el firewall (firewalld o ufw): activa y restringe las conexiones entrantes.
    /// `level`: "standard" (zona `public`) o "strict" (zona `drop`). `allow`: servicios que
    /// se mantienen accesibles ("ssh", "kdeconnect", "localsend"). Reversible.
    Firewall { level: String, allow: Vec<String> },
    /// Políticas de sistema para los navegadores instalados (Firefox y familia Chromium):
    /// endurecimiento de privacidad, DuckDuckGo por defecto y bloqueador de anuncios. Reversible.
    BrowserPolicies { level: String, ddg: bool, ublock: bool },
    /// Sin cambio automático: pasos para que los haga el usuario.
    Manual { steps: Vec<String> },
}

impl Fix {
    pub fn is_auto(&self) -> bool {
        !matches!(self, Fix::Manual { .. })
    }
    pub fn needs_root(&self) -> bool {
        matches!(
            self,
            Fix::DisableUnits { .. }
                | Fix::EnableUnits { .. }
                | Fix::InstallPackages { .. }
                | Fix::UsbguardPolicy {}
                | Fix::Sysctl { .. }
                | Fix::WriteFiles { .. }
                | Fix::NmProfiles { .. }
                | Fix::NmProfilesNamed { .. }
                | Fix::SetHostname { .. }
                | Fix::Firewall { .. }
                | Fix::BrowserPolicies { .. }
        )
    }
    /// Comandos/acciones tal como se mostrarán al usuario antes de aplicar.
    pub fn preview(&self) -> Vec<String> {
        match self {
            Fix::InstallPackages { names } => vec![format!("Instalar con el gestor de paquetes de tu distribución: {}", names.join(" "))],
            Fix::UsbguardPolicy {} => vec!["usbguard generate-policy > /etc/usbguard/rules.conf  (permite lo que tienes conectado ahora)".to_string()],
            Fix::EnableUnits { units } => vec![format!("systemctl enable --now {}", units.join(" "))],
            Fix::DisableUnits { units } => {
                vec![format!("systemctl disable --now {}", units.join(" "))]
            }
            Fix::Sysctl { settings } => settings
                .iter()
                .map(|s| format!("sysctl -w {}={}  (y se guarda en /etc/sysctl.d/)", s.key, s.value))
                .collect(),
            Fix::WriteFiles { files, after } => {
                let mut v: Vec<String> = files.iter().map(|f| format!("Crear el archivo {}", f.path)).collect();
                for a in after {
                    let verb = if a.verb == UnitVerb::Reload { "reload" } else { "restart" };
                    v.push(format!("systemctl {verb} {}", a.unit));
                }
                v
            }
            Fix::Gsettings { schema, key, value } => {
                vec![format!("gsettings set {schema} {key} {value}")]
            }
            Fix::Kwrite { file, group, key, value } => {
                vec![format!("kwriteconfig6 --file {file} --group {group} --key {key} {value}")]
            }
            Fix::FirefoxPrivacyPrefs { .. } => vec![
                "Añadir un bloque de preferencias de privacidad al archivo user.js de cada perfil de Firefox".into(),
            ],
            Fix::NmProfiles { props, .. } => props
                .iter()
                .map(|p| format!("nmcli connection modify <cada red guardada> {} \"{}\"", p.name, p.value))
                .collect(),
            Fix::NmProfilesNamed { names, props } => names
                .iter()
                .flat_map(|n| props.iter().map(move |p| format!("nmcli connection modify \"{n}\" {} \"{}\"", p.name, p.value)))
                .collect(),
            Fix::FlatpakOverride { app, args } => vec![format!("flatpak override --user {} {app}", args.join(" "))],
            Fix::SetHostname { name } => vec![format!("hostnamectl set-hostname {name}")],
            Fix::Firewall { level, allow } => {
                let zone = if level == "strict" { "drop" } else { "public" };
                let mut v = vec![format!("Mover tus redes a la zona de firewall «{zone}» (nmcli connection modify … connection.zone {zone} y firewall-cmd --change-interface)")];
                if !allow.is_empty() {
                    v.push(format!("Mantener accesible: {}", allow.join(", ")));
                }
                v
            }
            Fix::BrowserPolicies { .. } => vec![
                "Escribir políticas de navegador (Firefox: /etc/firefox/policies/policies.json; Chrome/Chromium/Edge/Brave: carpeta policies/managed)".into(),
            ],
            Fix::Manual { steps } => steps.clone(),
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Rule {
    pub id: String,
    pub category: Category,
    pub level: Level,
    pub severity: Severity,
    pub breakage: Breakage,
    pub title: String,
    /// Qué es, en lenguaje llano.
    pub what: String,
    /// Por qué afecta la privacidad.
    pub why: String,
    /// Qué dejaría de funcionar si se aplica el arreglo.
    pub breaks: String,
    #[serde(default)]
    pub applies: Applies,
    pub detect: Detect,
    pub fix: Fix,
    #[serde(default)]
    pub evidence: Option<EvidenceKind>,
    #[serde(default)]
    pub tags: Vec<String>,
}

// ───────────────────────── Snapshot ─────────────────────────

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct SystemInfo {
    pub distro_id: String,
    pub distro_name: String,
    pub distro_like: Vec<String>,
    pub version: String,
    pub kernel: String,
    pub desktop: String,
    pub session_type: String,
    pub init: String,
    pub pkg_manager: Option<String>,
    pub hostname: String,
    pub user: String,
    pub is_root: bool,
    pub hardware: BTreeSet<String>,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct UnitInfo {
    pub name: String,
    pub exists: bool,
    /// UnitFileState: enabled, disabled, static, masked, indirect…
    pub file_state: String,
    /// ActiveState: active, inactive, failed…
    pub active: String,
    pub required_by: Vec<String>,
}

impl UnitInfo {
    pub fn is_active(&self) -> bool {
        self.active == "active" || self.active == "activating"
    }
    pub fn is_enabled(&self) -> bool {
        self.file_state.starts_with("enabled")
    }
}

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Exposure {
    Loopback,
    /// Escucha en todas las interfaces (0.0.0.0, ::, *).
    AllInterfaces,
    /// Escucha en una IP concreta de la red.
    Specific,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Listener {
    pub proto: String,
    pub addr: String,
    pub port: u16,
    pub process: Option<String>,
    pub pid: Option<u32>,
    pub exposure: Exposure,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Connection {
    pub process: Option<String>,
    pub pid: Option<u32>,
    pub local_port: u16,
    pub remote_addr: String,
    pub remote_port: u16,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct DnsInfo {
    pub resolved_active: bool,
    pub stub_mode: bool,
    pub dns_over_tls: bool,
    pub llmnr: String,
    pub mdns: bool,
    /// Conexiones (enlaces) donde LLMNR está activo (resolve/yes).
    pub llmnr_links: Vec<String>,
    pub servers: Vec<String>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct SwapInfo {
    pub device: String,
    pub kind: String,
    /// None = no se pudo determinar. zram/RAM cuenta como "no aplica" (encrypted = Some(true)).
    pub encrypted: Option<bool>,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct StorageInfo {
    pub root_encrypted: Option<bool>,
    pub swaps: Vec<SwapInfo>,
}

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum SecureBoot {
    Enabled,
    Disabled,
    Unsupported,
    #[default]
    Unknown,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct FlatpakApp {
    pub id: String,
    pub broad: Vec<String>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct AutostartEntry {
    pub name: String,
    pub exec: String,
    pub system_wide: bool,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct FileProbe {
    pub files_checked: usize,
    pub matches: Vec<String>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Evidence {
    /// Some(true) = se usa; Some(false) = sin señales de uso; None = no se puede saber.
    pub in_use: Option<bool>,
    pub detail: String,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct FirefoxProfile {
    pub path: String,
    pub flavor: String,
    pub bad_prefs: Vec<String>,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct MacInfo {
    /// "selinux" | "apparmor" | "none"
    pub system: String,
    pub enforcing: bool,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct ZoneInfo {
    pub services: Vec<String>,
    pub ports: Vec<String>,
    pub interfaces: Vec<String>,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct FirewallInfo {
    /// "firewalld" | "ufw" | None
    pub backend: Option<String>,
    pub active: bool,
    pub default_zone: Option<String>,
    /// Zonas con interfaces activas (firewalld).
    pub zones: std::collections::BTreeMap<String, ZoneInfo>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct BrowserTarget {
    pub name: String,
    /// "firefox" | "chromium"
    pub kind: String,
    pub policy_path: String,
    pub installed: bool,
    /// Ya existe nuestra política de buscador.
    pub search_policy_applied: bool,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct NmProfile {
    pub uuid: String,
    pub name: String,
    pub kind: String,
    pub active: bool,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct Snapshot {
    pub taken_at: i64,
    pub info: SystemInfo,
    /// Comandos pedidos por las reglas (`applies.commands`) que existen en este sistema.
    pub commands: BTreeSet<String>,
    pub units: BTreeMap<String, UnitInfo>,
    pub running_services: Vec<(String, String)>,
    pub enabled_unit_files: usize,
    pub packages: BTreeSet<String>,
    pub listeners: Vec<Listener>,
    pub connections: Vec<Connection>,
    pub sysctl: BTreeMap<String, String>,
    pub gsettings: BTreeMap<String, String>,
    /// clave "file|group|key" → valor (None si no está definido).
    pub kconfig: BTreeMap<String, Option<String>>,
    pub file_probes: BTreeMap<String, FileProbe>,
    pub dns: DnsInfo,
    pub storage: StorageInfo,
    pub secure_boot: SecureBoot,
    pub flatpaks: Vec<FlatpakApp>,
    pub autostart: Vec<AutostartEntry>,
    pub evidence: BTreeMap<EvidenceKind, Evidence>,
    pub firefox: Vec<FirefoxProfile>,
    pub browsers: Vec<BrowserTarget>,
    pub firewall: FirewallInfo,
    pub mac: MacInfo,
    pub nm_profiles: Vec<NmProfile>,
    /// Avisos de qué no se pudo leer (honestidad sobre los límites del escaneo).
    pub notes: Vec<String>,
}

// ───────────────────────── Hallazgos ─────────────────────────

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
pub enum Status {
    /// Hay algo que mejorar.
    Todo,
    /// Ya está bien.
    Ok,
}

/// Qué tan seguro es aplicar el arreglo, tras cruzar la regla con la evidencia de uso.
#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Safety {
    /// No encontramos señales de que lo uses.
    NoSignsOfUse,
    /// No se nota en el uso diario.
    Safe,
    /// Puede que notes algo.
    Minor,
    /// Probablemente notarás que algo deja de funcionar.
    Notable,
    /// Hay señales concretas de que lo estás usando ahora.
    InUse,
}

impl Safety {
    pub fn label(self) -> &'static str {
        match self {
            Safety::NoSignsOfUse => "Sin señales de uso",
            Safety::Safe => "Seguro",
            Safety::Minor => "Cambio menor",
            Safety::Notable => "Se notará",
            Safety::InUse => "En uso",
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Finding {
    pub rule: Rule,
    pub status: Status,
    pub observed: Vec<String>,
    pub evidence: Option<Evidence>,
    pub blockers: Vec<String>,
    pub safety: Safety,
    pub learned_note: Option<String>,
    pub ignored: bool,
    /// Si el botón "aplicar seguras" debe incluirlo por defecto.
    pub preselect: bool,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct Report {
    pub findings: Vec<Finding>,
    /// 0..=100, mayor = mejor. Heurístico.
    pub score: u32,
    pub hidden_by_level: usize,
    pub level: Option<Level>,
    /// Reglas que no aplican a este equipo (para el Catálogo).
    pub not_applicable: Vec<String>,
    /// Reglas pendientes pero ocultas por el perfil elegido.
    pub hidden_ids: Vec<String>,
}

impl Report {
    pub fn todo(&self) -> impl Iterator<Item = &Finding> {
        self.findings.iter().filter(|f| f.status == Status::Todo && !f.ignored)
    }
    pub fn ok(&self) -> impl Iterator<Item = &Finding> {
        self.findings.iter().filter(|f| f.status == Status::Ok)
    }
}
