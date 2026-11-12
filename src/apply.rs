//! Ejecución de arreglos con diario de cambios. Cada acción guarda cómo deshacerse (`Undo`);
//! si un paso falla se revierte lo ya hecho, y todo queda registrado para poder revertir después.
//!
//! Seguridad: aquí solo se ejecutan acciones tipadas (`Fix`). Nunca se ejecuta texto arbitrario,
//! las rutas de escritura deben estar bajo /etc/ y los nombres pasan por listas blancas.

use crate::model::*;
use crate::sys::{CmdOut, Runner};
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Eq, Debug)]
pub enum Scope {
    Root,
    User,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub enum Undo {
    UnitEnable { unit: String, start: bool },
    UnitUnmask { unit: String, start: bool },
    UnitStart { unit: String },
    File { path: String, previous: Option<String> },
    After { verb: UnitVerb, unit: String },
    Sysctl { key: String, previous: String },
    Gsettings { schema: String, key: String, previous: String },
    Kconfig { file: String, group: String, key: String, previous: Option<String> },
    Firefox { dir: String, previous_block: Option<String> },
    NmProp { uuid: String, name: String, prop: String, previous: String },
    /// Archivo de overrides de Flatpak anterior (None = no existía y hay que borrarlo).
    FlatpakOverride { app: String, previous: Option<String> },
    Hostname { static_name: String, pretty: String },
    /// Revertir = `systemctl disable --now` (lo habilitamos nosotros).
    UnitDisableNow { unit: String },
    /// Paquetes que instalamos nosotros; revertir = desinstalar con el mismo gestor.
    PackagesInstalled { pm: String, names: Vec<String> },
    FirewallIface { iface: String, previous_zone: String },
    /// kind: "service" | "port"
    FirewallAllow { zone: String, kind: String, value: String },
    UfwState { was_active: bool, incoming: Option<String>, outgoing: Option<String> },
    UfwRule { rule: String },
}

/// Servicios que el usuario puede mantener accesibles al activar el firewall.
/// (firewalld: servicio o puertos; ufw: reglas equivalentes).
pub const FW_ALLOW: [&str; 3] = ["ssh", "kdeconnect", "localsend"];

fn fw_firewalld_rules(token: &str) -> Vec<(&'static str, &'static str)> {
    match token {
        "ssh" => vec![("service", "ssh")],
        "kdeconnect" => vec![("service", "kdeconnect")],
        "localsend" => vec![("port", "53317/tcp"), ("port", "53317/udp")],
        _ => vec![],
    }
}

fn fw_ufw_rules(token: &str) -> Vec<&'static str> {
    match token {
        "ssh" => vec!["22/tcp"],
        "kdeconnect" => vec!["1714:1764/tcp", "1714:1764/udp"],
        "localsend" => vec!["53317/tcp", "53317/udp"],
        _ => vec![],
    }
}

/// Salida de `firewall-cmd --get-active-zones` → [(zona, [interfaces])].
pub fn parse_active_zones(text: &str) -> Vec<(String, Vec<String>)> {
    let mut out: Vec<(String, Vec<String>)> = Vec::new();
    for line in text.lines() {
        if line.trim().is_empty() {
            continue;
        }
        if !line.starts_with(char::is_whitespace) {
            let name = line.split_whitespace().next().unwrap_or("").to_string();
            out.push((name, vec![]));
        } else if let Some(rest) = line.trim().strip_prefix("interfaces:") {
            if let Some(last) = out.last_mut() {
                last.1 = rest.split_whitespace().map(str::to_string).collect();
            }
        }
    }
    out
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct JournalEntry {
    pub id: u64,
    pub ts: i64,
    /// id de regla o de herramienta (`tool.dns`…).
    pub key: String,
    pub title: String,
    pub scope: Scope,
    pub undo: Vec<Undo>,
    pub reverted: bool,
    pub reverted_ts: Option<i64>,
    pub notes: Vec<String>,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct Journal {
    pub next_id: u64,
    pub entries: Vec<JournalEntry>,
}

pub const ROOT_JOURNAL: &str = "/var/lib/silence/journal.json";

impl Journal {
    pub fn load(path: &Path) -> Journal {
        std::fs::read_to_string(path).ok().and_then(|t| serde_json::from_str(&t).ok()).unwrap_or_default()
    }

    pub fn save(&self, path: &Path) -> std::io::Result<()> {
        if let Some(d) = path.parent() {
            std::fs::create_dir_all(d)?;
        }
        write_atomic(path, &serde_json::to_string_pretty(self).unwrap_or_default(), 0o644)
    }

    pub fn active_for(&self, key: &str) -> Vec<&JournalEntry> {
        self.entries.iter().filter(|e| e.key == key && !e.reverted).collect()
    }

    pub fn is_active(&self, key: &str) -> bool {
        !self.active_for(key).is_empty()
    }
}

/// Resultado de aplicar/revertir algo, para mostrarlo en la interfaz.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Outcome {
    pub key: String,
    pub title: String,
    pub ok: bool,
    pub message: String,
    pub entry_id: Option<u64>,
}

fn write_atomic(path: &Path, content: &str, mode: u32) -> std::io::Result<()> {
    let tmp = path.with_extension(format!("silence-tmp-{}", std::process::id()));
    std::fs::write(&tmp, content)?;
    std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(mode))?;
    std::fs::rename(&tmp, path).inspect_err(|_| {
        let _ = std::fs::remove_file(&tmp);
    })
}

fn slug(s: &str) -> String {
    s.chars().map(|c| if c.is_ascii_alphanumeric() { c.to_ascii_lowercase() } else { '-' }).collect()
}

/// Divide una línea de `nmcli -t` respetando `\:` y `\\`.
pub fn split_terse(line: &str) -> Vec<String> {
    let mut out = vec![String::new()];
    let mut esc = false;
    for c in line.chars() {
        if esc {
            out.last_mut().unwrap().push(c);
            esc = false;
        } else if c == '\\' {
            esc = true;
        } else if c == ':' {
            out.push(String::new());
        } else {
            out.last_mut().unwrap().push(c);
        }
    }
    out
}

/// Propiedades de NetworkManager que Silence puede modificar por perfil (lista blanca).
pub const NM_ALLOWED: [&str; 10] = [
    "connection.zone",
    "802-11-wireless.cloned-mac-address",
    "802-3-ethernet.cloned-mac-address",
    "ipv4.dns",
    "ipv4.ignore-auto-dns",
    "ipv6.ignore-auto-dns",
    "ipv6.method",
    "ipv6.dns",
    "ipv4.dhcp-hostname",
    "ipv6.dhcp-hostname",
];
pub const NM_TYPES: [&str; 2] = ["802-11-wireless", "802-3-ethernet"];

pub struct Applier<'a> {
    pub runner: &'a dyn Runner,
    /// "/" en producción; un directorio temporal en las pruebas.
    pub root: PathBuf,
    pub now: i64,
    /// Para pruebas: perfiles de Firefox a usar en lugar de descubrirlos.
    pub ff_dirs: Option<Vec<PathBuf>>,
}

impl<'a> Applier<'a> {
    pub fn new(runner: &'a dyn Runner) -> Self {
        Applier { runner, root: PathBuf::from("/"), now: chrono::Utc::now().timestamp(), ff_dirs: None }
    }

    fn p(&self, path: &str) -> PathBuf {
        self.root.join(path.trim_start_matches('/'))
    }

    fn sh(&self, prog: &str, args: &[&str]) -> Result<CmdOut, String> {
        let o = self.runner.run(prog, args);
        if o.ok {
            Ok(o)
        } else if o.missing {
            Err(format!("No se encontró el comando «{prog}»."))
        } else {
            Err(format!("«{prog} {}» falló: {}", args.join(" "), o.stderr.trim()))
        }
    }

    // ───────────── aplicar ─────────────

    /// Aplica varios arreglos como una sola operación: si uno falla, se deshace lo anterior.
    pub fn apply_all(&self, key: &str, fixes: &[&Fix]) -> Result<(Vec<Undo>, Vec<String>), String> {
        let mut undo = Vec::new();
        let mut msgs = Vec::new();
        for f in fixes {
            match self.apply(key, f, &mut undo) {
                Ok(mut m) => msgs.append(&mut m),
                Err(e) => {
                    let warn = self.revert(&undo);
                    let extra = if warn.is_empty() { String::new() } else { format!(" (al deshacer: {})", warn.join("; ")) };
                    return Err(format!("{e}. Se deshizo lo que ya se había cambiado{extra}."));
                }
            }
        }
        Ok((undo, msgs))
    }

    pub fn apply(&self, key: &str, fix: &Fix, undo: &mut Vec<Undo>) -> Result<Vec<String>, String> {
        match fix {
            Fix::DisableUnits { units } => self.disable_units(units, undo),
            Fix::EnableUnits { units } => self.enable_units(units, undo),
            Fix::InstallPackages { names } => self.install_packages(names, undo),
            Fix::UsbguardPolicy {} => self.usbguard_policy(undo),
            Fix::Sysctl { settings } => self.sysctl(key, settings, undo),
            Fix::WriteFiles { files, after } => {
                // `After` va primero: al revertir (orden inverso) se ejecuta tras restaurar los archivos.
                for a in after {
                    undo.push(Undo::After { verb: a.verb.clone(), unit: a.unit.clone() });
                }
                for f in files {
                    self.write_file(&f.path, &f.content, undo)?;
                }
                for a in after {
                    self.unit_cmd(&a.verb, &a.unit)?;
                }
                Ok(vec![format!("{} archivo(s) de configuración creado(s).", files.len())])
            }
            Fix::Gsettings { schema, key, value } => {
                let prev = self.sh("gsettings", &["get", schema, key])?.stdout.trim().to_string();
                self.sh("gsettings", &["set", schema, key, value])?;
                undo.push(Undo::Gsettings { schema: schema.clone(), key: key.clone(), previous: prev });
                Ok(vec![format!("{schema} {key} = {value}")])
            }
            Fix::Kwrite { file, group, key, value } => {
                let (rd, wr) = if self.runner.exists("kwriteconfig6") { ("kreadconfig6", "kwriteconfig6") } else { ("kreadconfig5", "kwriteconfig5") };
                let cur = self.runner.run(rd, &["--file", file, "--group", group, "--key", key, "--default", crate::collect::KCONFIG_UNSET]);
                let previous = if cur.ok && cur.stdout.trim() != crate::collect::KCONFIG_UNSET { Some(cur.stdout.trim().to_string()) } else { None };
                self.sh(wr, &["--file", file, "--group", group, "--key", key, value])?;
                undo.push(Undo::Kconfig { file: file.clone(), group: group.clone(), key: key.clone(), previous });
                Ok(vec![format!("{file} [{group}] {key} = {value}")])
            }
            Fix::FirefoxPrivacyPrefs { level } => {
                if let Some(l) = level {
                    if !crate::firefox::level_ok(l) {
                        return Err(format!("Nivel de Firefox desconocido: {l}"));
                    }
                }
                let dirs: Vec<PathBuf> = match &self.ff_dirs {
                    Some(d) => d.clone(),
                    None => crate::firefox::profile_dirs().into_iter().map(|(p, _)| p).collect(),
                };
                if dirs.is_empty() {
                    return Ok(vec!["No se encontró ningún perfil de Firefox (ábrelo una vez y vuelve a intentar).".into()]);
                }
                for d in &dirs {
                    let (_, previous_block) = crate::firefox::apply_to_profile(d, level.as_deref())
                        .map_err(|e| format!("No se pudo escribir user.js en {}: {e}", d.display()))?;
                    undo.push(Undo::Firefox { dir: d.display().to_string(), previous_block });
                }
                Ok(vec![format!("Ajustes de privacidad escritos en {} perfil(es) de Firefox. Reinicia Firefox para que apliquen.", dirs.len())])
            }
            Fix::NmProfiles { types, props } => self.nm_profiles(types, None, props, undo),
            Fix::NmProfilesNamed { names, props } => {
                let types: Vec<String> = NM_TYPES.iter().map(|s| s.to_string()).collect();
                self.nm_profiles(&types, Some(names), props, undo)
            }
            Fix::FlatpakOverride { app, args } => self.flatpak_override(app, args, undo),
            Fix::SetHostname { name } => self.set_hostname(name, undo),
            Fix::Firewall { level, allow } => self.firewall(level, allow, undo),
            Fix::BrowserPolicies { level, ddg, ublock } => {
                let read = |p: &str| std::fs::read_to_string(self.p(p)).ok();
                let (files, names) = crate::browsers::plan_files(self.runner, level, *ddg, *ublock, &read)?;
                if files.is_empty() {
                    return Ok(vec!["No se encontró ningún navegador compatible instalado como paquete del sistema (las versiones Flatpak y Snap no se pueden configurar así).".into()]);
                }
                for f in &files {
                    self.write_file(&f.path, &f.content, undo)?;
                }
                Ok(vec![format!("Políticas escritas para: {}. Reinicia el navegador para que apliquen.", names.join(", "))])
            }
            Fix::Manual { .. } => Err("Este cambio es manual; Silence no lo aplica automáticamente.".into()),
        }
    }

    fn write_file(&self, path: &str, content: &str, undo: &mut Vec<Undo>) -> Result<(), String> {
        if !path.starts_with("/etc/") || path.contains("..") || path.contains('\0') || path.ends_with('/') {
            return Err(format!("Ruta no permitida: {path}"));
        }
        let real = self.p(path);
        let previous = std::fs::read_to_string(&real).ok();
        if let Some(d) = real.parent() {
            std::fs::create_dir_all(d).map_err(|e| format!("No se pudo crear {}: {e}", d.display()))?;
        }
        write_atomic(&real, content, if path.starts_with("/etc/NetworkManager/dispatcher.d/") { 0o755 } else { 0o644 }).map_err(|e| format!("No se pudo escribir {path}: {e}"))?;
        undo.push(Undo::File { path: path.to_string(), previous });
        Ok(())
    }

    fn unit_active(&self, unit: &str) -> bool {
        self.runner.run("systemctl", &["is-active", unit]).stdout.trim() == "active"
    }

    fn unit_cmd(&self, verb: &UnitVerb, unit: &str) -> Result<(), String> {
        if !self.unit_active(unit) {
            return Ok(()); // si no está corriendo, el cambio se tomará al arrancar
        }
        let v = if *verb == UnitVerb::Reload { "reload" } else { "restart" };
        self.sh("systemctl", &[v, unit]).map(|_| ())
    }

    /// (UnitFileState, activa) o None si la unidad no existe.
    fn unit_state(&self, unit: &str) -> Option<(String, bool)> {
        let o = self.runner.run("systemctl", &["show", "--no-pager", "-p", "LoadState", "-p", "UnitFileState", "-p", "ActiveState", unit]);
        let mut load = String::new();
        let mut file = String::new();
        let mut active = String::new();
        for l in o.stdout.lines() {
            if let Some(v) = l.strip_prefix("LoadState=") {
                load = v.into();
            } else if let Some(v) = l.strip_prefix("UnitFileState=") {
                file = v.into();
            } else if let Some(v) = l.strip_prefix("ActiveState=") {
                active = v.into();
            }
        }
        if load.is_empty() || load == "not-found" {
            None
        } else {
            Some((file, active == "active" || active == "activating"))
        }
    }

    /// (gestor, comando de instalación, comando de desinstalación)
    fn pm_commands(&self) -> Option<(&'static str, Vec<&'static str>, Vec<&'static str>)> {
        if self.runner.exists("dnf") {
            Some(("dnf", vec!["install", "-y"], vec!["remove", "-y"]))
        } else if self.runner.exists("apt-get") {
            Some(("apt-get", vec!["install", "-y"], vec!["remove", "-y"]))
        } else if self.runner.exists("pacman") {
            Some(("pacman", vec!["-S", "--noconfirm"], vec!["-R", "--noconfirm"]))
        } else if self.runner.exists("zypper") {
            Some(("zypper", vec!["--non-interactive", "install"], vec!["--non-interactive", "remove"]))
        } else {
            None
        }
    }

    fn install_packages(&self, names: &[String], undo: &mut Vec<Undo>) -> Result<Vec<String>, String> {
        const ALLOWED: [&str; 1] = ["usbguard"];
        if names.is_empty() || !names.iter().all(|n| ALLOWED.contains(&n.as_str())) {
            return Err("Paquete no permitido.".into());
        }
        let (pm, install, _) = self.pm_commands().ok_or("No se encontró un gestor de paquetes compatible (dnf, apt, pacman o zypper).")?;
        let missing: Vec<&String> = names.iter().filter(|n| !self.runner.exists(n)).collect();
        if missing.is_empty() {
            return Ok(vec!["Ya estaba instalado.".into()]);
        }
        let mut args: Vec<&str> = install.clone();
        args.extend(missing.iter().map(|s| s.as_str()));
        self.sh(pm, &args)?;
        undo.push(Undo::PackagesInstalled { pm: pm.to_string(), names: missing.iter().map(|s| s.to_string()).collect() });
        Ok(vec![format!("Instalado: {}", missing.iter().map(|s| s.as_str()).collect::<Vec<_>>().join(", "))])
    }

    fn usbguard_policy(&self, undo: &mut Vec<Undo>) -> Result<Vec<String>, String> {
        let path = "/etc/usbguard/rules.conf";
        let current = std::fs::read_to_string(self.p(path)).unwrap_or_default();
        if current.lines().any(|l| !l.trim().is_empty() && !l.trim_start().starts_with('#')) {
            return Ok(vec!["USBGuard ya tiene reglas guardadas; se conservan.".into()]);
        }
        let o = self.sh("usbguard", &["generate-policy"])?;
        if !o.stdout.lines().any(|l| l.trim_start().starts_with("allow")) {
            return Err("No se pudo generar la política: USBGuard no vio ningún dispositivo.".into());
        }
        self.write_file(path, &o.stdout, undo)?;
        // La carpeta debe quedar solo para root, como pide USBGuard.
        if let Some(d) = self.p(path).parent() {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(self.p(path), std::fs::Permissions::from_mode(0o600));
            let _ = d;
        }
        Ok(vec!["Política creada: se permiten los dispositivos conectados ahora.".into()])
    }

    fn enable_units(&self, units: &[String], undo: &mut Vec<Undo>) -> Result<Vec<String>, String> {
        let re = Regex::new(r"^[A-Za-z0-9:_.@\-]+$").unwrap();
        let mut msgs = Vec::new();
        for u in units {
            if !re.is_match(u) {
                return Err(format!("Nombre de unidad no permitido: {u}"));
            }
            // USBGuard sin reglas guardadas bloquea todos los USB nuevos, teclado incluido.
            if u == "usbguard.service" {
                let rules = std::fs::read_to_string(self.p("/etc/usbguard/rules.conf")).unwrap_or_default();
                if !rules.lines().any(|l| !l.trim().is_empty() && !l.trim_start().starts_with('#')) {
                    return Err("USBGuard no tiene reglas guardadas: al encenderlo bloquearía todos tus USB, incluido el teclado. Genera primero la política: sudo sh -c 'usbguard generate-policy > /etc/usbguard/rules.conf'".into());
                }
            }
            if self.unit_state(u).is_none() {
                return Err(format!("{u} no está instalado."));
            }
            if self.unit_active(u) && self.unit_state(u).map(|(f, _)| f.starts_with("enabled")).unwrap_or(false) {
                continue;
            }
            self.sh("systemctl", &["enable", "--now", u])?;
            undo.push(Undo::UnitDisableNow { unit: u.clone() });
            msgs.push(format!("{u}: habilitado y en marcha"));
        }
        if msgs.is_empty() {
            msgs.push("Nada que cambiar: ya estaba encendido.".into());
        }
        Ok(msgs)
    }

    fn disable_units(&self, units: &[String], undo: &mut Vec<Undo>) -> Result<Vec<String>, String> {
        let re = Regex::new(r"^[A-Za-z0-9:_.@\-]+$").unwrap();
        let mut msgs = Vec::new();
        for u in units {
            if !re.is_match(u) {
                return Err(format!("Nombre de unidad no permitido: {u}"));
            }
            let Some((file_state, active)) = self.unit_state(u) else { continue };
            match file_state.as_str() {
                "masked" | "masked-runtime" => {}
                "enabled" | "enabled-runtime" => {
                    self.sh("systemctl", &["disable", "--now", u])?;
                    undo.push(Undo::UnitEnable { unit: u.clone(), start: active });
                    msgs.push(format!("{u}: deshabilitado y detenido"));
                }
                "disabled" => {
                    if active {
                        self.sh("systemctl", &["stop", u])?;
                        undo.push(Undo::UnitStart { unit: u.clone() });
                        msgs.push(format!("{u}: detenido"));
                    }
                }
                // static / indirect / generated / alias…: no se pueden deshabilitar, se enmascaran.
                _ => {
                    self.sh("systemctl", &["mask", "--now", u])?;
                    undo.push(Undo::UnitUnmask { unit: u.clone(), start: active });
                    msgs.push(format!("{u}: enmascarado y detenido"));
                }
            }
        }
        if msgs.is_empty() {
            msgs.push("Nada que cambiar: las unidades ya estaban desactivadas.".into());
        }
        Ok(msgs)
    }

    fn sysctl(&self, key: &str, settings: &[SysctlSetting], undo: &mut Vec<Undo>) -> Result<Vec<String>, String> {
        let key_re = Regex::new(r"^[a-z0-9_]+(\.[a-z0-9_]+)+$").unwrap();
        let val_re = Regex::new(r"^[A-Za-z0-9_.\-]+$").unwrap();
        let mut content = format!("# Creado por Silence ({key}). Para revertir usa la pestaña Historial de Silence.\n");
        let mut msgs = Vec::new();
        for s in settings {
            if !key_re.is_match(&s.key) || !val_re.is_match(&s.value) {
                return Err(format!("Ajuste de kernel no permitido: {}={}", s.key, s.value));
            }
            let cur = self.runner.run("sysctl", &["-n", &s.key]);
            if !cur.ok || cur.stdout.trim().is_empty() {
                msgs.push(format!("{}: no existe en este kernel, se omite", s.key));
                continue;
            }
            let previous = cur.stdout.trim().to_string();
            self.sh("sysctl", &["-w", &format!("{}={}", s.key, s.value)])?;
            undo.push(Undo::Sysctl { key: s.key.clone(), previous });
            content.push_str(&format!("{} = {}\n", s.key, s.value));
            msgs.push(format!("{} = {}", s.key, s.value));
        }
        let path = format!("/etc/sysctl.d/90-silence-{}.conf", slug(key));
        self.write_file(&path, &content, undo)?;
        Ok(msgs)
    }

    fn flatpak_override(&self, app: &str, args: &[String], undo: &mut Vec<Undo>) -> Result<Vec<String>, String> {
        const OK_ARGS: [&str; 5] = ["--nofilesystem=home", "--nofilesystem=host", "--nofilesystem=host-os", "--nofilesystem=host-etc", "--nodevice=all"];
        if !Regex::new(r"^[A-Za-z0-9_][A-Za-z0-9_.\-]{1,200}$").unwrap().is_match(app) || !app.contains('.') {
            return Err(format!("Nombre de app Flatpak no válido: {app}"));
        }
        if args.is_empty() || !args.iter().all(|a| OK_ARGS.contains(&a.as_str())) {
            return Err("Permiso de Flatpak no permitido.".into());
        }
        if !self.runner.exists("flatpak") {
            return Err("Flatpak no está instalado.".into());
        }
        let home = std::env::var("HOME").unwrap_or_default();
        let path = self.p(&format!("{home}/.local/share/flatpak/overrides/{app}"));
        let previous = std::fs::read_to_string(&path).ok();
        let mut cmd: Vec<&str> = vec!["override", "--user"];
        cmd.extend(args.iter().map(String::as_str));
        cmd.push(app);
        self.sh("flatpak", &cmd)?;
        undo.push(Undo::FlatpakOverride { app: app.to_string(), previous });
        Ok(vec![format!("{app}: permisos recortados. Cierra y vuelve a abrir la app para que apliquen.")])
    }

    fn nm_profiles(&self, types: &[String], only: Option<&Vec<String>>, props: &[NmProp], undo: &mut Vec<Undo>) -> Result<Vec<String>, String> {
        let val_re = Regex::new(r"^[A-Za-z0-9_.:#,@ \-]*$").unwrap();
        for t in types {
            if !NM_TYPES.contains(&t.as_str()) {
                return Err(format!("Tipo de red no permitido: {t}"));
            }
        }
        for p in props {
            if !NM_ALLOWED.contains(&p.name.as_str()) || !val_re.is_match(&p.value) {
                return Err(format!("Propiedad de NetworkManager no permitida: {}={}", p.name, p.value));
            }
        }
        if !self.runner.exists("nmcli") {
            return Err("NetworkManager (nmcli) no está disponible en este sistema.".into());
        }
        let list = self.sh("nmcli", &["-t", "-f", "UUID,NAME,TYPE", "connection", "show"])?;
        let mut n = 0;
        for line in list.stdout.lines() {
            let f = split_terse(line);
            if f.len() < 3 {
                continue;
            }
            let (uuid, name, typ) = (f[0].clone(), f[1..f.len() - 1].join(":"), f[f.len() - 1].clone());
            if !types.contains(&typ) {
                continue;
            }
            if let Some(only) = only {
                if !only.contains(&name) {
                    continue;
                }
            }
            for p in props {
                let prev = self.runner.run("nmcli", &["-g", &p.name, "connection", "show", &uuid]);
                let previous = prev.stdout.trim_end_matches('\n').replace('|', ",");
                self.sh("nmcli", &["connection", "modify", &uuid, &p.name, &p.value])?;
                undo.push(Undo::NmProp { uuid: uuid.clone(), name: name.clone(), prop: p.name.clone(), previous });
            }
            n += 1;
        }
        Ok(vec![if n == 0 {
            "No hay redes guardadas de ese tipo; los valores por defecto se aplicarán a las que crees.".to_string()
        } else {
            format!("{n} red(es) guardada(s) actualizada(s). Vuelve a conectarte a la red para que el cambio aplique.")
        }])
    }

    fn firewall(&self, level: &str, allow: &[String], undo: &mut Vec<Undo>) -> Result<Vec<String>, String> {
        if level != "standard" && level != "strict" {
            return Err(format!("Nivel de firewall desconocido: {level}"));
        }
        if let Some(bad) = allow.iter().find(|a| !FW_ALLOW.contains(&a.as_str())) {
            return Err(format!("Servicio no permitido en el firewall: {bad}"));
        }
        if self.runner.exists("firewall-cmd") {
            self.firewalld(level, allow, undo)
        } else if self.runner.exists("ufw") {
            self.ufw(allow, undo)
        } else {
            Err("No se encontró firewalld ni ufw. Instala uno primero (Fedora: sudo dnf install firewalld · Ubuntu/Debian: sudo apt install ufw).".into())
        }
    }

    fn firewalld(&self, level: &str, allow: &[String], undo: &mut Vec<Undo>) -> Result<Vec<String>, String> {
        let zone = if level == "strict" { "drop" } else { "public" };
        let mut msgs = Vec::new();
        if !self.unit_active("firewalld.service") {
            self.sh("systemctl", &["enable", "--now", "firewalld.service"])?;
            undo.push(Undo::UnitDisableNow { unit: "firewalld.service".into() });
            msgs.push("firewalld estaba apagado: se activó.".into());
        }
        // 1) Los perfiles de NetworkManager mandan sobre la zona por defecto: por eso hay que fijarla ahí.
        if self.runner.exists("nmcli") {
            let props = [NmProp { name: "connection.zone".into(), value: zone.into() }];
            let types: Vec<String> = NM_TYPES.iter().map(|s| s.to_string()).collect();
            msgs.extend(self.nm_profiles(&types, None, &props, undo)?);
        }
        // 2) Interfaces activas ahora mismo (efecto inmediato, sin esperar a reconectar).
        let zflag = format!("--zone={zone}");
        let active = self.sh("firewall-cmd", &["--get-active-zones"])?;
        let mut moved = 0;
        for (z, ifaces) in parse_active_zones(&active.stdout) {
            if z == zone {
                continue;
            }
            for i in ifaces {
                self.sh("firewall-cmd", &[&zflag, "--change-interface", &i])?;
                undo.push(Undo::FirewallIface { iface: i.clone(), previous_zone: z.clone() });
                moved += 1;
            }
        }
        msgs.push(format!("{moved} interfaz(ces) movida(s) a la zona «{zone}»."));
        // 3) Lo que el usuario quiere mantener accesible.
        for token in allow {
            for (kind, value) in fw_firewalld_rules(token) {
                let q = self.runner.run("firewall-cmd", &[&zflag, &format!("--query-{kind}={value}")]);
                if q.stdout.trim() == "yes" {
                    continue;
                }
                let add = format!("--add-{kind}={value}");
                self.sh("firewall-cmd", &[&zflag, &add])?;
                self.sh("firewall-cmd", &["--permanent", &zflag, &add])?;
                undo.push(Undo::FirewallAllow { zone: zone.into(), kind: kind.into(), value: value.into() });
            }
            msgs.push(format!("«{token}» se mantiene accesible."));
        }
        Ok(msgs)
    }

    fn ufw(&self, allow: &[String], undo: &mut Vec<Undo>) -> Result<Vec<String>, String> {
        let st = self.runner.run("ufw", &["status", "verbose"]).stdout;
        let was_active = st.contains("Status: active");
        let re = Regex::new(r"Default:\s*(\w+) \(incoming\),\s*(\w+) \(outgoing\)").unwrap();
        let (incoming, outgoing) = match re.captures(&st) {
            Some(c) => (Some(c[1].to_string()), Some(c[2].to_string())),
            None => (None, None),
        };
        // Primero: al revertir (orden inverso) esto se restaura el último.
        undo.push(Undo::UfwState { was_active, incoming, outgoing });
        self.sh("ufw", &["default", "deny", "incoming"])?;
        self.sh("ufw", &["default", "allow", "outgoing"])?;
        for token in allow {
            for r in fw_ufw_rules(token) {
                self.sh("ufw", &["allow", r])?;
                undo.push(Undo::UfwRule { rule: r.to_string() });
            }
        }
        self.sh("ufw", &["--force", "enable"])?;
        Ok(vec!["ufw activado: se bloquea todo lo entrante salvo lo que elegiste mantener.".into()])
    }

    fn set_hostname(&self, name: &str, undo: &mut Vec<Undo>) -> Result<Vec<String>, String> {
        if !Regex::new(r"^[A-Za-z0-9][A-Za-z0-9\-]{0,62}$").unwrap().is_match(name) {
            return Err(format!("Nombre de equipo no válido: {name}"));
        }
        let static_name = self.runner.run("hostnamectl", &["--static"]).stdout.trim().to_string();
        let pretty = self.runner.run("hostnamectl", &["--pretty"]).stdout.trim().to_string();
        self.sh("hostnamectl", &["set-hostname", name])?;
        undo.push(Undo::Hostname { static_name, pretty });
        Ok(vec![format!("Nombre del equipo: {name}")])
    }

    // ───────────── revertir ─────────────

    /// Revierte en orden inverso. Es tolerante: sigue ante errores y devuelve avisos.
    pub fn revert(&self, undo: &[Undo]) -> Vec<String> {
        let mut warn = Vec::new();
        let mut note = |r: Result<(), String>| {
            if let Err(e) = r {
                warn.push(e);
            }
        };
        for u in undo.iter().rev() {
            match u {
                Undo::UnitEnable { unit, start } => {
                    note(self.sh("systemctl", &["enable", unit]).map(|_| ()));
                    if *start {
                        note(self.sh("systemctl", &["start", unit]).map(|_| ()));
                    }
                }
                Undo::UnitUnmask { unit, start } => {
                    note(self.sh("systemctl", &["unmask", unit]).map(|_| ()));
                    if *start {
                        note(self.sh("systemctl", &["start", unit]).map(|_| ()));
                    }
                }
                Undo::UnitStart { unit } => note(self.sh("systemctl", &["start", unit]).map(|_| ())),
                Undo::File { path, previous } => {
                    let real = self.p(path);
                    let r = match previous {
                        Some(c) => write_atomic(&real, c, 0o644).map_err(|e| format!("No se pudo restaurar {path}: {e}")),
                        None => match std::fs::remove_file(&real) {
                            Ok(()) => Ok(()),
                            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
                            Err(e) => Err(format!("No se pudo borrar {path}: {e}")),
                        },
                    };
                    note(r);
                }
                Undo::After { verb, unit } => note(self.unit_cmd(verb, unit)),
                Undo::Sysctl { key, previous } => {
                    if !previous.is_empty() {
                        note(self.sh("sysctl", &["-w", &format!("{key}={previous}")]).map(|_| ()));
                    }
                }
                Undo::Gsettings { schema, key, previous } => {
                    note(self.sh("gsettings", &["set", schema, key, previous]).map(|_| ()));
                }
                Undo::Kconfig { file, group, key, previous } => {
                    let wr = if self.runner.exists("kwriteconfig6") { "kwriteconfig6" } else { "kwriteconfig5" };
                    let r = match previous {
                        Some(v) => self.sh(wr, &["--file", file, "--group", group, "--key", key, v]),
                        None => self.sh(wr, &["--file", file, "--group", group, "--key", key, "--delete"]),
                    };
                    note(r.map(|_| ()));
                }
                Undo::Firefox { dir, previous_block } => {
                    note(crate::firefox::revert_profile(Path::new(dir), previous_block.as_deref())
                        .map(|_| ())
                        .map_err(|e| format!("No se pudo revertir user.js en {dir}: {e}")));
                }
                Undo::NmProp { uuid, name, prop, previous } => {
                    // Si la red ya no existe, no es un error.
                    let o = self.runner.run("nmcli", &["connection", "modify", uuid, prop, previous]);
                    if !o.ok {
                        warn_push(&mut note, format!("No se pudo restaurar {prop} en «{name}» (¿se borró esa red?)"));
                    }
                }
                Undo::FlatpakOverride { app, previous } => {
                    let home = std::env::var("HOME").unwrap_or_default();
                    let path = self.p(&format!("{home}/.local/share/flatpak/overrides/{app}"));
                    let r = match previous {
                        Some(text) => std::fs::write(&path, text),
                        None => match std::fs::remove_file(&path) {
                            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
                            other => other,
                        },
                    };
                    note(r.map_err(|e| format!("No se pudo restaurar los permisos de {app}: {e}")));
                }
                Undo::PackagesInstalled { pm, names } => {
                    let cmd = match pm.as_str() {
                        "dnf" | "apt-get" => vec!["remove", "-y"],
                        "pacman" => vec!["-R", "--noconfirm"],
                        _ => vec!["--non-interactive", "remove"],
                    };
                    let mut args = cmd;
                    args.extend(names.iter().map(String::as_str));
                    note(self.sh(pm, &args).map(|_| ()));
                }
                Undo::UnitDisableNow { unit } => note(self.sh("systemctl", &["disable", "--now", unit]).map(|_| ())),
                Undo::FirewallIface { iface, previous_zone } => {
                    note(self.sh("firewall-cmd", &[&format!("--zone={previous_zone}"), "--change-interface", iface]).map(|_| ()));
                }
                Undo::FirewallAllow { zone, kind, value } => {
                    let rm = format!("--remove-{kind}={value}");
                    let z = format!("--zone={zone}");
                    note(self.sh("firewall-cmd", &[&z, &rm]).map(|_| ()));
                    note(self.sh("firewall-cmd", &["--permanent", &z, &rm]).map(|_| ()));
                }
                Undo::UfwRule { rule } => note(self.sh("ufw", &["--force", "delete", "allow", rule]).map(|_| ())),
                Undo::UfwState { was_active, incoming, outgoing } => {
                    if let Some(i) = incoming {
                        note(self.sh("ufw", &["default", i, "incoming"]).map(|_| ()));
                    }
                    if let Some(o) = outgoing {
                        note(self.sh("ufw", &["default", o, "outgoing"]).map(|_| ()));
                    }
                    if !*was_active {
                        note(self.sh("ufw", &["--force", "disable"]).map(|_| ()));
                    }
                }
                Undo::Hostname { static_name, pretty } => {
                    note(self.sh("hostnamectl", &["set-hostname", static_name]).map(|_| ()));
                    note(self.sh("hostnamectl", &["set-hostname", "--pretty", pretty]).map(|_| ()));
                }
            }
        }
        warn
    }

    // ───────────── con diario ─────────────

    /// Aplica los arreglos de `fixes` que correspondan a `scope`, y los registra en el diario.
    /// Si ya había un cambio activo con la misma `key`, se revierte primero (así cambiar de
    /// proveedor DNS o de nivel no acumula cambios).
    pub fn run_fixes(&self, journal_path: &Path, scope: Scope, key: &str, title: &str, fixes: &[Fix]) -> Option<Outcome> {
        let mine: Vec<&Fix> = fixes.iter().filter(|f| f.needs_root() == (scope == Scope::Root)).collect();
        if mine.is_empty() {
            return None;
        }
        let mut journal = Journal::load(journal_path);
        let fail = |m: String| Outcome { key: key.into(), title: title.into(), ok: false, message: m, entry_id: None };

        let old: Vec<u64> = journal.active_for(key).iter().map(|e| e.id).collect();
        for id in old {
            if let Some(e) = journal.entries.iter_mut().find(|e| e.id == id) {
                let w = self.revert(&e.undo);
                e.reverted = true;
                e.reverted_ts = Some(self.now);
                if !w.is_empty() {
                    e.notes.extend(w);
                }
            }
        }
        match self.apply_all(key, &mine) {
            Err(e) => {
                let _ = journal.save(journal_path);
                Some(fail(e))
            }
            Ok((undo, msgs)) => {
                let id = journal.next_id + 1;
                journal.next_id = id;
                journal.entries.push(JournalEntry {
                    id,
                    ts: self.now,
                    key: key.into(),
                    title: title.into(),
                    scope,
                    undo,
                    reverted: false,
                    reverted_ts: None,
                    notes: vec![],
                });
                if let Err(e) = journal.save(journal_path) {
                    return Some(fail(format!("Se aplicó, pero no se pudo guardar el diario: {e}")));
                }
                Some(Outcome { key: key.into(), title: title.into(), ok: true, message: msgs.join("\n"), entry_id: Some(id) })
            }
        }
    }

    pub fn revert_entry(&self, journal_path: &Path, id: u64) -> Outcome {
        let mut journal = Journal::load(journal_path);
        let Some(e) = journal.entries.iter_mut().find(|e| e.id == id) else {
            return Outcome { key: String::new(), title: String::new(), ok: false, message: format!("No existe el cambio #{id}."), entry_id: Some(id) };
        };
        if e.reverted {
            return Outcome { key: e.key.clone(), title: e.title.clone(), ok: false, message: "Ese cambio ya estaba revertido.".into(), entry_id: Some(id) };
        }
        let warn = self.revert(&e.undo);
        e.reverted = true;
        e.reverted_ts = Some(self.now);
        e.notes.extend(warn.clone());
        let (key, title) = (e.key.clone(), e.title.clone());
        let saved = journal.save(journal_path);
        let mut message = "Cambio revertido.".to_string();
        if !warn.is_empty() {
            message = format!("Revertido con avisos: {}", warn.join("; "));
        }
        if let Err(er) = saved {
            message.push_str(&format!(" (no se pudo actualizar el diario: {er})"));
        }
        Outcome { key, title, ok: true, message, entry_id: Some(id) }
    }
}

fn warn_push(note: &mut impl FnMut(Result<(), String>), m: String) {
    note(Err(m));
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sys::mock::MockRunner;

    fn tmp(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("silence-apply-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    fn applier<'a>(r: &'a MockRunner, root: &Path) -> Applier<'a> {
        Applier { runner: r, root: root.to_path_buf(), now: 1000, ff_dirs: None }
    }

    fn show(unit: &str) -> String {
        format!("systemctl show --no-pager -p LoadState -p UnitFileState -p ActiveState {unit}")
    }

    #[test]
    fn disable_enabled_unit_and_revert_restores() {
        let r = MockRunner::new();
        r.on(&show("cups.service"), "LoadState=loaded\nUnitFileState=enabled\nActiveState=active\n");
        r.on(&show("cups.socket"), "LoadState=loaded\nUnitFileState=static\nActiveState=inactive\n");
        r.on(&show("nope.service"), "LoadState=not-found\nUnitFileState=\nActiveState=inactive\n");
        let a = applier(&r, &tmp("units"));
        let mut undo = vec![];
        let units = vec!["cups.service".to_string(), "cups.socket".to_string(), "nope.service".to_string()];
        a.apply("services.cups", &Fix::DisableUnits { units }, &mut undo).unwrap();
        let calls = r.calls();
        assert!(calls.contains(&"systemctl disable --now cups.service".to_string()));
        assert!(calls.contains(&"systemctl mask --now cups.socket".to_string()), "static debe enmascararse");
        assert!(!calls.iter().any(|c| c.contains("nope.service") && c.contains("disable")));
        assert_eq!(undo.len(), 2);
        assert!(a.revert(&undo).is_empty());
        let calls = r.calls();
        assert!(calls.contains(&"systemctl enable cups.service".to_string()));
        assert!(calls.contains(&"systemctl start cups.service".to_string()), "estaba activo: debe volver a arrancar");
        assert!(calls.contains(&"systemctl unmask cups.socket".to_string()));
        assert!(!calls.contains(&"systemctl start cups.socket".to_string()), "estaba inactivo");
    }

    #[test]
    fn rejects_malicious_unit_names() {
        let r = MockRunner::new();
        let a = applier(&r, &tmp("evil"));
        let mut undo = vec![];
        let e = a.apply("x", &Fix::DisableUnits { units: vec!["a.service; rm -rf /".into()] }, &mut undo).unwrap_err();
        assert!(e.contains("no permitido"));
        assert!(r.calls().is_empty());
    }

    #[test]
    fn write_files_rejects_paths_outside_etc() {
        let r = MockRunner::new();
        let root = tmp("paths");
        let a = applier(&r, &root);
        for bad in ["/usr/bin/evil", "/etc/../root/x", "/etc/dir/", "relative/etc/x"] {
            let mut undo = vec![];
            let fix = Fix::WriteFiles { files: vec![FileSpec { path: bad.into(), content: "x".into() }], after: vec![] };
            assert!(a.apply("x", &fix, &mut undo).is_err(), "{bad}");
            assert!(undo.is_empty());
        }
        assert!(!root.join("usr").exists());
    }

    #[test]
    fn write_files_roundtrip_and_after_commands() {
        let r = MockRunner::new();
        r.on("systemctl is-active NetworkManager.service", "active\n");
        let root = tmp("write");
        std::fs::create_dir_all(root.join("etc/NetworkManager/conf.d")).unwrap();
        std::fs::write(root.join("etc/NetworkManager/conf.d/a.conf"), "ORIGINAL\n").unwrap();
        let a = applier(&r, &root);
        let fix = Fix::WriteFiles {
            files: vec![
                FileSpec { path: "/etc/NetworkManager/conf.d/a.conf".into(), content: "NUEVO\n".into() },
                FileSpec { path: "/etc/systemd/resolved.conf.d/x.conf".into(), content: "Z\n".into() },
            ],
            after: vec![UnitCmd { verb: UnitVerb::Reload, unit: "NetworkManager.service".into() }],
        };
        let mut undo = vec![];
        a.apply("k", &fix, &mut undo).unwrap();
        assert_eq!(std::fs::read_to_string(root.join("etc/NetworkManager/conf.d/a.conf")).unwrap(), "NUEVO\n");
        assert!(root.join("etc/systemd/resolved.conf.d/x.conf").exists());
        assert!(r.calls().contains(&"systemctl reload NetworkManager.service".to_string()));
        let before = r.calls().len();
        assert!(a.revert(&undo).is_empty());
        // Se restauró el original y se borró el creado.
        assert_eq!(std::fs::read_to_string(root.join("etc/NetworkManager/conf.d/a.conf")).unwrap(), "ORIGINAL\n");
        assert!(!root.join("etc/systemd/resolved.conf.d/x.conf").exists());
        // El reload posterior a la restauración se ejecuta DESPUÉS de restaurar los archivos.
        assert!(r.calls().len() > before);
    }

    #[test]
    fn after_skipped_when_unit_inactive() {
        let r = MockRunner::new();
        r.fail_on("systemctl is-active"); // is-active devuelve error/"" ⇒ inactiva
        let a = applier(&r, &tmp("inactive"));
        let fix = Fix::WriteFiles {
            files: vec![FileSpec { path: "/etc/x/y.conf".into(), content: "a".into() }],
            after: vec![UnitCmd { verb: UnitVerb::Restart, unit: "foo.service".into() }],
        };
        let mut undo = vec![];
        a.apply("k", &fix, &mut undo).unwrap();
        assert!(!r.calls().iter().any(|c| c.starts_with("systemctl restart")));
    }

    #[test]
    fn sysctl_applies_persists_and_reverts_in_order() {
        let r = MockRunner::new();
        r.on("sysctl -n net.ipv6.conf.all.disable_ipv6", "0\n");
        r.on("sysctl -n net.ipv6.conf.lo.disable_ipv6", "0\n");
        r.on("sysctl", "");
        let root = tmp("sysctl");
        let a = applier(&r, &root);
        let fix = Fix::Sysctl {
            settings: vec![
                SysctlSetting { key: "net.ipv6.conf.all.disable_ipv6".into(), value: "1".into() },
                SysctlSetting { key: "net.ipv6.conf.lo.disable_ipv6".into(), value: "0".into() },
                SysctlSetting { key: "net.no.existe".into(), value: "1".into() },
            ],
        };
        r.fail_on("sysctl -n net.no.existe");
        let mut undo = vec![];
        let msgs = a.apply("tool.ipv6", &fix, &mut undo).unwrap();
        assert!(msgs.iter().any(|m| m.contains("no existe")));
        let f = std::fs::read_to_string(root.join("etc/sysctl.d/90-silence-tool-ipv6.conf")).unwrap();
        assert!(f.contains("net.ipv6.conf.all.disable_ipv6 = 1") && f.contains("net.ipv6.conf.lo.disable_ipv6 = 0"));
        assert!(!f.contains("net.no.existe"));
        // El orden importa: «all» primero y «lo» después (para dejar lo operativo).
        assert!(f.find("all.disable_ipv6").unwrap() < f.find("lo.disable_ipv6").unwrap());
        a.revert(&undo);
        assert!(!root.join("etc/sysctl.d/90-silence-tool-ipv6.conf").exists());
        let calls = r.calls();
        assert!(calls.contains(&"sysctl -w net.ipv6.conf.all.disable_ipv6=0".to_string()));
    }

    #[test]
    fn failure_midway_rolls_back_everything() {
        let r = MockRunner::new();
        r.on(&show("a.service"), "LoadState=loaded\nUnitFileState=enabled\nActiveState=active\n");
        r.on(&show("b.service"), "LoadState=loaded\nUnitFileState=enabled\nActiveState=active\n");
        r.fail_on("systemctl disable --now b.service");
        let a = applier(&r, &tmp("rollback"));
        let fix = Fix::DisableUnits { units: vec!["a.service".into(), "b.service".into()] };
        let e = a.apply_all("k", &[&fix]).unwrap_err();
        assert!(e.contains("Se deshizo"), "{e}");
        let calls = r.calls();
        assert!(calls.contains(&"systemctl disable --now a.service".to_string()));
        assert!(calls.contains(&"systemctl enable a.service".to_string()), "a debe volver a habilitarse");
        assert!(calls.contains(&"systemctl start a.service".to_string()));
    }

    #[test]
    fn nm_profiles_filters_types_and_restores_previous() {
        let r = MockRunner::new();
        r.on(
            "nmcli -t -f UUID,NAME,TYPE connection show",
            "aaaa-1:Casa\\: wifi:802-11-wireless\nbbbb-2:Oficina:802-3-ethernet\ncccc-3:VPN:vpn\ndddd-4:lo:loopback\n",
        );
        r.on("nmcli -g ipv6.method connection show aaaa-1", "auto\n");
        let a = applier(&r, &tmp("nm"));
        let fix = Fix::NmProfiles {
            types: vec!["802-11-wireless".into()],
            props: vec![NmProp { name: "ipv6.method".into(), value: "disabled".into() }],
        };
        let mut undo = vec![];
        a.apply("tool.ipv6", &fix, &mut undo).unwrap();
        let calls = r.calls();
        assert!(calls.contains(&"nmcli connection modify aaaa-1 ipv6.method disabled".to_string()));
        assert!(!calls.iter().any(|c| c.contains("bbbb-2") && c.contains("modify")), "ethernet no estaba en types");
        assert!(!calls.iter().any(|c| c.contains("cccc-3") && c.contains("modify")), "las VPN nunca se tocan");
        match &undo[0] {
            Undo::NmProp { name, previous, .. } => {
                assert_eq!(name, "Casa: wifi", "nombre con ':' escapado");
                assert_eq!(previous, "auto");
            }
            u => panic!("{u:?}"),
        }
        a.revert(&undo);
        assert!(r.calls().contains(&"nmcli connection modify aaaa-1 ipv6.method auto".to_string()));
    }

    #[test]
    fn nm_profiles_named_only_touches_listed_networks() {
        let r = MockRunner::new();
        r.on("nmcli -t -f UUID,NAME,TYPE connection show", "aaaa-1:Casa:802-11-wireless\nbbbb-2:Cafe:802-11-wireless\ncccc-3:VPN:vpn\n");
        r.on("nmcli -g connection.zone connection show aaaa-1", "\n");
        let a = applier(&r, &tmp("nm-named"));
        let fix = Fix::NmProfilesNamed { names: vec!["Casa".into(), "VPN".into()], props: vec![NmProp { name: "connection.zone".into(), value: "home".into() }] };
        let mut undo = vec![];
        a.apply("tool.trusted", &fix, &mut undo).unwrap();
        let calls = r.calls();
        assert!(calls.contains(&"nmcli connection modify aaaa-1 connection.zone home".to_string()));
        assert!(!calls.iter().any(|c| c.contains("bbbb-2") && c.contains("modify")), "Cafe no estaba en la lista");
        assert!(!calls.iter().any(|c| c.contains("cccc-3") && c.contains("modify")), "las VPN nunca se tocan");
    }

    #[test]
    fn flatpak_override_roundtrip_restores_previous_file() {
        let r = MockRunner::new();
        r.on("flatpak --version", "Flatpak 1.16\n");
        let root = tmp("flatpak");
        let a = applier(&r, &root);
        let home = std::env::var("HOME").unwrap_or_default();
        let dir = root.join(home.trim_start_matches('/')).join(".local/share/flatpak/overrides");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("org.videolan.VLC"), "[Context]\nsockets=x11;\n").unwrap();
        let fix = Fix::FlatpakOverride { app: "org.videolan.VLC".into(), args: vec!["--nofilesystem=home".into()] };
        let mut undo = vec![];
        a.apply("tool.flatpak", &fix, &mut undo).unwrap();
        assert!(r.calls().contains(&"flatpak override --user --nofilesystem=home org.videolan.VLC".to_string()));
        // Simula que flatpak modificó el archivo y revierte.
        std::fs::write(dir.join("org.videolan.VLC"), "[Context]\nfilesystems=!home;\n").unwrap();
        assert!(a.revert(&undo).is_empty());
        assert_eq!(std::fs::read_to_string(dir.join("org.videolan.VLC")).unwrap(), "[Context]\nsockets=x11;\n");
        // Sin archivo previo: revertir lo borra.
        let mut undo2 = vec![];
        a.apply("tool.flatpak", &Fix::FlatpakOverride { app: "org.nuevo.App".into(), args: vec!["--nodevice=all".into()] }, &mut undo2).unwrap();
        std::fs::write(dir.join("org.nuevo.App"), "x").unwrap();
        assert!(a.revert(&undo2).is_empty());
        assert!(!dir.join("org.nuevo.App").exists());
    }

    #[test]
    fn flatpak_override_rejects_bad_names_and_args() {
        let r = MockRunner::new();
        r.on("flatpak --version", "Flatpak 1.16\n");
        let a = applier(&r, &tmp("flatpak-bad"));
        for (app, arg) in [("../x.y", "--nodevice=all"), ("nodot", "--nodevice=all"), ("org.a.B", "--filesystem=host"), ("org.a.B;rm", "--nodevice=all")] {
            let fix = Fix::FlatpakOverride { app: app.into(), args: vec![arg.into()] };
            assert!(a.apply("k", &fix, &mut vec![]).is_err(), "{app} {arg}");
        }
        assert!(!r.calls().iter().any(|c| c.starts_with("flatpak override")));
    }

    #[test]
    fn enable_usbguard_requires_saved_rules_and_reverts() {
        let r = MockRunner::new();
        r.on("systemctl is-active usbguard.service", "inactive\n");
        r.on("systemctl show --no-pager -p LoadState -p UnitFileState -p ActiveState usbguard.service", "LoadState=loaded\nUnitFileState=disabled\nActiveState=inactive\n");
        let root = tmp("usbguard");
        let a = applier(&r, &root);
        let fix = Fix::EnableUnits { units: vec!["usbguard.service".into()] };
        let e = a.apply("tool.usbguard", &fix, &mut vec![]).unwrap_err();
        assert!(e.contains("sin") || e.contains("no tiene reglas"), "{e}");
        assert!(!r.calls().iter().any(|c| c.contains("enable")), "no debe encenderlo sin reglas");
        std::fs::create_dir_all(root.join("etc/usbguard")).unwrap();
        std::fs::write(root.join("etc/usbguard/rules.conf"), "# solo comentario\n").unwrap();
        assert!(a.apply("tool.usbguard", &fix, &mut vec![]).is_err(), "solo comentarios no cuenta");
        std::fs::write(root.join("etc/usbguard/rules.conf"), "allow id 1d6b:0002\n").unwrap();
        let mut undo = vec![];
        a.apply("tool.usbguard", &fix, &mut undo).unwrap();
        assert!(r.calls().contains(&"systemctl enable --now usbguard.service".to_string()));
        assert!(a.revert(&undo).is_empty());
        assert!(r.calls().contains(&"systemctl disable --now usbguard.service".to_string()));
        assert!(a.apply("k", &Fix::EnableUnits { units: vec!["x; rm".into()] }, &mut vec![]).is_err());
    }

    #[test]
    fn usbguard_setup_installs_creates_policy_and_reverts_everything() {
        let r = MockRunner::new();
        r.on("dnf --version", "4\n");
        r.on("usbguard generate-policy", "allow id 1d6b:0002 name \"xHCI Host Controller\"\n");
        r.on("systemctl is-active usbguard.service", "inactive\n");
        r.on("systemctl show --no-pager -p LoadState -p UnitFileState -p ActiveState usbguard.service", "LoadState=loaded\nUnitFileState=disabled\nActiveState=inactive\n");
        let root = tmp("usbguard-setup");
        std::fs::create_dir_all(root.join("etc/usbguard")).unwrap();
        std::fs::write(root.join("etc/usbguard/rules.conf"), "").unwrap();
        let a = applier(&r, &root);
        let fixes = [Fix::InstallPackages { names: vec!["usbguard".into()] }, Fix::UsbguardPolicy {}, Fix::EnableUnits { units: vec!["usbguard.service".into()] }];
        let refs: Vec<&Fix> = fixes.iter().collect();
        let (undo, _) = a.apply_all("tool.usbguard", &refs).unwrap();
        assert!(!r.calls().iter().any(|c| c.starts_with("dnf")), "ya estaba instalado: no se vuelve a instalar");
        assert!(std::fs::read_to_string(root.join("etc/usbguard/rules.conf")).unwrap().contains("allow id 1d6b:0002"));
        assert!(r.calls().contains(&"systemctl enable --now usbguard.service".to_string()));
        assert!(a.revert(&undo).is_empty());
        assert!(r.calls().contains(&"systemctl disable --now usbguard.service".to_string()));
        assert!(!r.calls().iter().any(|c| c.starts_with("dnf remove")), "no se desinstala lo que ya estaba");
        assert_eq!(std::fs::read_to_string(root.join("etc/usbguard/rules.conf")).unwrap(), "", "se restaura el archivo");
        // Paquetes fuera de la lista cerrada se rechazan.
        assert!(a.apply("k", &Fix::InstallPackages { names: vec!["rm".into()] }, &mut vec![]).is_err());
    }

    #[test]
    fn install_packages_runs_pm_and_reverts_with_removal() {
        let r = MockRunner::new();
        r.on("dnf --version", "4\n");
        let a = applier(&r, &tmp("pkg"));
        let mut undo = vec![];
        a.apply("tool.usbguard", &Fix::InstallPackages { names: vec!["usbguard".into()] }, &mut undo).unwrap();
        assert!(r.calls().contains(&"dnf install -y usbguard".to_string()), "{:?}", r.calls());
        assert!(a.revert(&undo).is_empty());
        assert!(r.calls().contains(&"dnf remove -y usbguard".to_string()));
        // Sin gestor de paquetes conocido, error claro.
        let none = MockRunner::new();
        let b = applier(&none, &tmp("pkg2"));
        assert!(b.apply("k", &Fix::InstallPackages { names: vec!["usbguard".into()] }, &mut vec![]).unwrap_err().contains("gestor de paquetes"));
    }

    #[test]
    fn usbguard_policy_keeps_existing_rules_and_refuses_empty_output() {
        let r = MockRunner::new();
        r.on("usbguard generate-policy", "# nada\n");
        let root = tmp("usbguard-keep");
        std::fs::create_dir_all(root.join("etc/usbguard")).unwrap();
        let a = applier(&r, &root);
        assert!(a.apply("k", &Fix::UsbguardPolicy {}, &mut vec![]).is_err(), "sin dispositivos no se escribe nada");
        assert!(!root.join("etc/usbguard/rules.conf").exists());
        std::fs::write(root.join("etc/usbguard/rules.conf"), "allow id aaaa:bbbb\n").unwrap();
        let before = r.calls().len();
        a.apply("k", &Fix::UsbguardPolicy {}, &mut vec![]).unwrap();
        assert_eq!(r.calls().len(), before, "con reglas existentes ni siquiera se invoca usbguard");
    }

    #[test]
    fn nm_profiles_rejects_non_whitelisted() {
        let r = MockRunner::new();
        r.on("nmcli", "");
        let a = applier(&r, &tmp("nm2"));
        let mut undo = vec![];
        let bad_prop = Fix::NmProfiles { types: vec!["802-11-wireless".into()], props: vec![NmProp { name: "connection.permissions".into(), value: "x".into() }] };
        assert!(a.apply("k", &bad_prop, &mut undo).is_err());
        let bad_type = Fix::NmProfiles { types: vec!["vpn".into()], props: vec![] };
        assert!(a.apply("k", &bad_type, &mut undo).is_err());
        let bad_val = Fix::NmProfiles { types: vec!["802-11-wireless".into()], props: vec![NmProp { name: "ipv6.method".into(), value: "a; reboot".into() }] };
        assert!(a.apply("k", &bad_val, &mut undo).is_err());
        assert!(!r.calls().iter().any(|c| c.contains("modify")));
    }

    #[test]
    fn active_zones_parser_real_sample() {
        let z = parse_active_zones("home\n  interfaces: wlo1\npublic (default)\n");
        assert_eq!(z[0], ("home".to_string(), vec!["wlo1".to_string()]));
        assert_eq!(z[1].0, "public");
        assert!(z[1].1.is_empty());
    }

    fn fw_runner() -> MockRunner {
        let r = MockRunner::new();
        r.on("firewall-cmd --get-active-zones", "home\n  interfaces: wlo1\npublic (default)\n");
        r.on("systemctl is-active firewalld.service", "active\n");
        r.on("nmcli -t -f UUID,NAME,TYPE connection show", "u1:Casa:802-11-wireless\nu2:VPN:vpn\n");
        r.on("nmcli -g connection.zone connection show u1", "home\n");
        r
    }

    #[test]
    fn firewalld_moves_interface_and_nm_profile_then_reverts() {
        let r = fw_runner();
        let a = applier(&r, &tmp("fw"));
        let mut undo = vec![];
        a.apply("tool.firewall", &Fix::Firewall { level: "standard".into(), allow: vec!["kdeconnect".into(), "localsend".into()] }, &mut undo).unwrap();
        let c = r.calls();
        // El perfil de NM manda: se fija connection.zone; la VPN no se toca.
        assert!(c.contains(&"nmcli connection modify u1 connection.zone public".to_string()), "{c:?}");
        assert!(!c.iter().any(|x| x.contains("u2") && x.contains("modify")));
        // wlo1 estaba en «home»: se mueve a «public» en caliente.
        assert!(c.contains(&"firewall-cmd --zone=public --change-interface wlo1".to_string()));
        // Servicios elegidos, en caliente y permanentes.
        assert!(c.contains(&"firewall-cmd --zone=public --add-service=kdeconnect".to_string()));
        assert!(c.contains(&"firewall-cmd --permanent --zone=public --add-service=kdeconnect".to_string()));
        assert!(c.contains(&"firewall-cmd --zone=public --add-port=53317/tcp".to_string()));
        assert!(a.revert(&undo).is_empty());
        let c = r.calls();
        assert!(c.contains(&"firewall-cmd --zone=home --change-interface wlo1".to_string()), "vuelve a su zona original");
        assert!(c.contains(&"nmcli connection modify u1 connection.zone home".to_string()));
        assert!(c.contains(&"firewall-cmd --zone=public --remove-service=kdeconnect".to_string()));
        assert!(c.contains(&"firewall-cmd --permanent --zone=public --remove-port=53317/udp".to_string()));
    }

    #[test]
    fn firewalld_strict_uses_drop_and_skips_already_allowed() {
        let r = fw_runner();
        r.on("firewall-cmd --zone=drop --query-service=ssh", "yes\n");
        let a = applier(&r, &tmp("fw2"));
        let mut undo = vec![];
        a.apply("k", &Fix::Firewall { level: "strict".into(), allow: vec!["ssh".into()] }, &mut undo).unwrap();
        let c = r.calls();
        assert!(c.contains(&"firewall-cmd --zone=drop --change-interface wlo1".to_string()));
        assert!(!c.iter().any(|x| x.contains("--add-service=ssh")), "ya estaba permitido: no se toca ni se revierte");
        assert!(!undo.iter().any(|u| matches!(u, Undo::FirewallAllow { .. })));
    }

    #[test]
    fn firewalld_enables_service_when_off_and_reverts_it() {
        let r = fw_runner();
        r.fail_on("systemctl is-active firewalld.service");
        let a = applier(&r, &tmp("fw3"));
        let mut undo = vec![];
        a.apply("k", &Fix::Firewall { level: "standard".into(), allow: vec![] }, &mut undo).unwrap();
        assert!(r.calls().contains(&"systemctl enable --now firewalld.service".to_string()));
        a.revert(&undo);
        assert!(r.calls().contains(&"systemctl disable --now firewalld.service".to_string()));
    }

    #[test]
    fn firewall_rejects_unknown_level_and_services() {
        let r = fw_runner();
        let a = applier(&r, &tmp("fw4"));
        assert!(a.apply("k", &Fix::Firewall { level: "todo".into(), allow: vec![] }, &mut vec![]).is_err());
        assert!(a.apply("k", &Fix::Firewall { level: "standard".into(), allow: vec!["telnet; x".into()] }, &mut vec![]).is_err());
        assert!(!r.calls().iter().any(|c| c.contains("change-interface")));
    }

    #[test]
    fn firewall_without_any_backend_explains_what_to_install() {
        let r = MockRunner::new();
        let e = applier(&r, &tmp("fw5")).apply("k", &Fix::Firewall { level: "standard".into(), allow: vec![] }, &mut vec![]).unwrap_err();
        assert!(e.contains("firewalld") && e.contains("ufw"));
    }

    #[test]
    fn ufw_enables_with_deny_incoming_and_reverts_to_previous_state() {
        let r = MockRunner::new();
        r.on("ufw status verbose", "Status: inactive\n");
        let a = applier(&r, &tmp("ufw"));
        let mut undo = vec![];
        a.apply("k", &Fix::Firewall { level: "standard".into(), allow: vec!["ssh".into()] }, &mut undo).unwrap();
        let c = r.calls();
        assert!(c.contains(&"ufw default deny incoming".to_string()));
        assert!(c.contains(&"ufw allow 22/tcp".to_string()));
        assert!(c.contains(&"ufw --force enable".to_string()));
        a.revert(&undo);
        let c = r.calls();
        assert!(c.contains(&"ufw --force delete allow 22/tcp".to_string()));
        assert!(c.contains(&"ufw --force disable".to_string()), "estaba inactivo: vuelve a quedar inactivo");
        // Si ya estaba activo con otros valores por defecto, se restauran y NO se desactiva.
        let r2 = MockRunner::new();
        r2.on("ufw status verbose", "Status: active\nDefault: allow (incoming), allow (outgoing), disabled (routed)\n");
        let a2 = applier(&r2, &tmp("ufw2"));
        let mut undo2 = vec![];
        a2.apply("k", &Fix::Firewall { level: "standard".into(), allow: vec![] }, &mut undo2).unwrap();
        a2.revert(&undo2);
        let c2 = r2.calls();
        assert!(c2.contains(&"ufw default allow incoming".to_string()));
        assert!(!c2.contains(&"ufw --force disable".to_string()));
    }

    #[test]
    fn split_terse_handles_escapes() {
        assert_eq!(split_terse("u:Mi\\:red:802-3-ethernet"), vec!["u", "Mi:red", "802-3-ethernet"]);
        assert_eq!(split_terse("a\\\\b:c"), vec!["a\\b", "c"]);
    }

    #[test]
    fn hostname_roundtrip() {
        let r = MockRunner::new();
        r.on("hostnamectl --static", "fedora\n");
        r.on("hostnamectl --pretty", "\n");
        let a = applier(&r, &tmp("host"));
        let mut undo = vec![];
        a.apply("tool.identity", &Fix::SetHostname { name: "DESKTOP-4F8K2LM".into() }, &mut undo).unwrap();
        assert!(r.calls().contains(&"hostnamectl set-hostname DESKTOP-4F8K2LM".to_string()));
        a.revert(&undo);
        assert!(r.calls().contains(&"hostnamectl set-hostname fedora".to_string()));
        assert!(a.apply("k", &Fix::SetHostname { name: "mal nombre; x".into() }, &mut vec![]).is_err());
        assert!(a.apply("k", &Fix::SetHostname { name: "-empieza-mal".into() }, &mut vec![]).is_err());
    }

    #[test]
    fn browser_policies_written_under_root_and_reverted() {
        let r = MockRunner::new();
        r.on("firefox", "");
        r.on("chromium-browser", "");
        let root = tmp("browsers");
        std::fs::create_dir_all(root.join("etc/firefox/policies")).unwrap();
        std::fs::write(root.join("etc/firefox/policies/policies.json"), r#"{"policies":{"DisableAppUpdate":true}}"#).unwrap();
        let a = applier(&r, &root);
        let mut undo = vec![];
        a.apply("tool.browsers", &Fix::BrowserPolicies { level: "balanced".into(), ddg: true, ublock: true }, &mut undo).unwrap();
        let ff: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(root.join("etc/firefox/policies/policies.json")).unwrap()).unwrap();
        assert_eq!(ff["policies"]["DisableAppUpdate"], true, "se conservó la política existente");
        assert_eq!(ff["policies"]["SearchEngines"]["Default"], "DuckDuckGo");
        assert!(root.join("etc/chromium/policies/managed/silence-privacy.json").exists());
        a.revert(&undo);
        assert_eq!(std::fs::read_to_string(root.join("etc/firefox/policies/policies.json")).unwrap(), r#"{"policies":{"DisableAppUpdate":true}}"#);
        assert!(!root.join("etc/chromium/policies/managed/silence-privacy.json").exists());
    }

    #[test]
    fn browser_policies_refuses_corrupt_policy_without_touching_anything() {
        let r = MockRunner::new();
        r.on("firefox", "");
        r.on("chromium-browser", "");
        let root = tmp("browsers-bad");
        std::fs::create_dir_all(root.join("etc/firefox/policies")).unwrap();
        std::fs::write(root.join("etc/firefox/policies/policies.json"), "{ roto").unwrap();
        let a = applier(&r, &root);
        let e = a.apply_all("tool.browsers", &[&Fix::BrowserPolicies { level: "balanced".into(), ddg: true, ublock: false }]).unwrap_err();
        assert!(e.contains("no es JSON válido"));
        assert_eq!(std::fs::read_to_string(root.join("etc/firefox/policies/policies.json")).unwrap(), "{ roto");
        assert!(!root.join("etc/chromium").exists(), "nada a medias");
    }

    #[test]
    fn firefox_prefs_fix_applies_to_profiles() {
        let r = MockRunner::new();
        let root = tmp("ff");
        let prof = root.join("p1");
        std::fs::create_dir_all(&prof).unwrap();
        let mut a = applier(&r, &root);
        a.ff_dirs = Some(vec![prof.clone()]);
        let mut undo = vec![];
        a.apply("tool.browsers", &Fix::FirefoxPrivacyPrefs { level: Some("maximum".into()) }, &mut undo).unwrap();
        assert!(std::fs::read_to_string(prof.join("user.js")).unwrap().contains("privacy.fingerprintingProtection"));
        a.revert(&undo);
        assert!(!prof.join("user.js").exists());
        assert!(a.apply("k", &Fix::FirefoxPrivacyPrefs { level: Some("todo".into()) }, &mut vec![]).is_err());
    }

    #[test]
    fn journal_replace_semantics_and_revert_entry() {
        let r = MockRunner::new();
        let root = tmp("journal");
        let a = applier(&r, &root);
        let jp = root.join("var/lib/silence/journal.json");
        let fix1 = Fix::WriteFiles { files: vec![FileSpec { path: "/etc/silence-test/a.conf".into(), content: "uno\n".into() }], after: vec![] };
        let fix2 = Fix::WriteFiles { files: vec![FileSpec { path: "/etc/silence-test/a.conf".into(), content: "dos\n".into() }], after: vec![] };
        let o1 = a.run_fixes(&jp, Scope::Root, "tool.dns", "DNS", &[fix1]).unwrap();
        assert!(o1.ok, "{}", o1.message);
        // Reaplicar con la misma clave revierte el anterior y deja uno solo activo.
        let o2 = a.run_fixes(&jp, Scope::Root, "tool.dns", "DNS", &[fix2]).unwrap();
        assert!(o2.ok);
        let j = Journal::load(&jp);
        assert_eq!(j.entries.len(), 2);
        assert_eq!(j.active_for("tool.dns").len(), 1);
        assert_eq!(std::fs::read_to_string(root.join("etc/silence-test/a.conf")).unwrap(), "dos\n");
        // Revertir el activo restaura el estado ORIGINAL (no existía).
        let o3 = a.revert_entry(&jp, o2.entry_id.unwrap());
        assert!(o3.ok, "{}", o3.message);
        assert!(!root.join("etc/silence-test/a.conf").exists());
        assert!(!Journal::load(&jp).is_active("tool.dns"));
        // No se puede revertir dos veces.
        assert!(!a.revert_entry(&jp, o2.entry_id.unwrap()).ok);
        assert!(!a.revert_entry(&jp, 999).ok);
    }

    #[test]
    fn scope_filtering() {
        let r = MockRunner::new();
        let root = tmp("scope");
        let a = applier(&r, &root);
        let jp = root.join("j.json");
        let user_fix = Fix::Gsettings { schema: "a.b".into(), key: "c".into(), value: "false".into() };
        assert!(a.run_fixes(&jp, Scope::Root, "k", "t", &[user_fix.clone()]).is_none(), "una acción de usuario no corre como root");
        let root_fix = Fix::SetHostname { name: "X".into() };
        assert!(a.run_fixes(&jp, Scope::User, "k", "t", &[root_fix]).is_none(), "una acción de root no corre como usuario");
    }
}
