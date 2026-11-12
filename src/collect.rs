//! Colectores: leen el estado real del sistema (solo lectura) y lo normalizan en un `Snapshot`.
//! Cada parser es una función pura para poder probarla con salidas reales de ejemplo.

use crate::model::*;
use crate::sys::Runner;
use regex::Regex;
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

// ───────────────────────── Sistema ─────────────────────────

pub fn parse_os_release(text: &str) -> BTreeMap<String, String> {
    text.lines()
        .filter_map(|l| {
            let l = l.trim();
            if l.starts_with('#') {
                return None;
            }
            let (k, v) = l.split_once('=')?;
            Some((k.trim().to_string(), v.trim().trim_matches('"').trim_matches('\'').to_string()))
        })
        .collect()
}

fn read_trim(path: &str) -> String {
    std::fs::read_to_string(path).map(|s| s.trim().to_string()).unwrap_or_default()
}

fn glob_exists(pattern: &str) -> bool {
    glob::glob(pattern).map(|mut it| it.next().is_some()).unwrap_or(false)
}

pub fn collect_info(r: &dyn Runner) -> SystemInfo {
    let os = parse_os_release(
        &std::fs::read_to_string("/etc/os-release")
            .or_else(|_| std::fs::read_to_string("/usr/lib/os-release"))
            .unwrap_or_default(),
    );
    let init = if Path::new("/run/systemd/system").exists() {
        "systemd"
    } else if Path::new("/run/openrc").exists() {
        "openrc"
    } else if Path::new("/run/runit").exists() || Path::new("/etc/runit").exists() {
        "runit"
    } else if Path::new("/run/s6").exists() {
        "s6"
    } else {
        "desconocido"
    };
    let pkg_manager = [
        ("dpkg-query", "dpkg"),
        ("pacman", "pacman"),
        ("apk", "apk"),
        ("xbps-query", "xbps"),
        ("rpm", "rpm"),
    ]
    .into_iter()
    .find(|(cmd, _)| r.exists(cmd))
    .map(|(_, name)| name.to_string());

    let mut hardware = BTreeSet::new();
    if glob_exists("/sys/class/net/*/wireless") {
        hardware.insert("wifi".to_string());
    }
    if glob_exists("/sys/class/bluetooth/hci*") {
        hardware.insert("bluetooth".to_string());
    }
    if glob_exists("/dev/video*") {
        hardware.insert("camera".to_string());
    }
    if glob_exists("/dev/cdc-wdm*") || glob_exists("/dev/wwan*") || glob_exists("/sys/class/net/ww*") {
        hardware.insert("modem".to_string());
    }

    let user = std::env::var("USER")
        .or_else(|_| std::env::var("LOGNAME"))
        .unwrap_or_default();

    SystemInfo {
        distro_id: os.get("ID").cloned().unwrap_or_default().to_lowercase(),
        distro_name: os.get("PRETTY_NAME").or(os.get("NAME")).cloned().unwrap_or_else(|| "Linux".into()),
        distro_like: os
            .get("ID_LIKE")
            .map(|s| s.split_whitespace().map(|x| x.to_lowercase()).collect())
            .unwrap_or_default(),
        version: os.get("VERSION_ID").cloned().unwrap_or_default(),
        kernel: read_trim("/proc/sys/kernel/osrelease"),
        desktop: std::env::var("XDG_CURRENT_DESKTOP").unwrap_or_default(),
        session_type: std::env::var("XDG_SESSION_TYPE").unwrap_or_default(),
        init: init.to_string(),
        pkg_manager,
        hostname: read_trim("/proc/sys/kernel/hostname"),
        user,
        is_root: unsafe { libc::geteuid() } == 0,
        hardware,
    }
}

// ───────────────────────── systemd ─────────────────────────

/// Salida de `systemctl show`: bloques separados por línea en blanco, `Clave=valor`.
pub fn parse_systemctl_show(text: &str) -> Vec<BTreeMap<String, String>> {
    let mut out = Vec::new();
    let mut cur: BTreeMap<String, String> = BTreeMap::new();
    for line in text.lines() {
        if line.trim().is_empty() {
            if !cur.is_empty() {
                out.push(std::mem::take(&mut cur));
            }
            continue;
        }
        if let Some((k, v)) = line.split_once('=') {
            cur.insert(k.to_string(), v.to_string());
        }
    }
    if !cur.is_empty() {
        out.push(cur);
    }
    out
}

const SHOW_PROPS: [&str; 6] = ["Id", "LoadState", "UnitFileState", "ActiveState", "RequiredBy", "BoundBy"];

fn show_args<'a>(units: &'a [String]) -> Vec<&'a str> {
    let mut args: Vec<&str> = vec!["show", "--no-pager"];
    for p in SHOW_PROPS {
        args.push("-p");
        args.push(p);
    }
    args.extend(units.iter().map(|s| s.as_str()));
    args
}

pub fn collect_units(r: &dyn Runner, wanted: &BTreeSet<String>) -> BTreeMap<String, UnitInfo> {
    let mut map = BTreeMap::new();
    if wanted.is_empty() || !r.exists("systemctl") {
        return map;
    }
    let names: Vec<String> = wanted.iter().cloned().collect();
    let mut required_union = BTreeSet::new();
    for chunk in names.chunks(40) {
        let Some(out) = r.out("systemctl", &show_args(chunk)) else { continue };
        for b in parse_systemctl_show(&out) {
            let Some(id) = b.get("Id") else { continue };
            let load = b.get("LoadState").map(String::as_str).unwrap_or("");
            let required: Vec<String> = b
                .get("RequiredBy")
                .into_iter()
                .chain(b.get("BoundBy"))
                .flat_map(|s| s.split_whitespace().map(str::to_string))
                .collect();
            required_union.extend(required.iter().cloned());
            map.insert(
                id.clone(),
                UnitInfo {
                    name: id.clone(),
                    exists: load != "not-found" && !load.is_empty(),
                    file_state: b.get("UnitFileState").cloned().unwrap_or_default(),
                    active: b.get("ActiveState").cloned().unwrap_or_default(),
                    required_by: required,
                },
            );
        }
    }
    // Solo nos importan los dependientes que están activos ahora mismo.
    if !required_union.is_empty() {
        let req: Vec<String> = required_union.into_iter().collect();
        let mut active = BTreeSet::new();
        for chunk in req.chunks(40) {
            let mut args = vec!["show", "--no-pager", "-p", "Id", "-p", "ActiveState"];
            args.extend(chunk.iter().map(|s| s.as_str()));
            if let Some(out) = r.out("systemctl", &args) {
                for b in parse_systemctl_show(&out) {
                    if b.get("ActiveState").map(String::as_str) == Some("active") {
                        if let Some(id) = b.get("Id") {
                            active.insert(id.clone());
                        }
                    }
                }
            }
        }
        for u in map.values_mut() {
            u.required_by.retain(|n| active.contains(n));
        }
    }
    map
}

/// `systemctl list-units --type=service --state=running --plain --no-legend`
pub fn parse_running_services(text: &str) -> Vec<(String, String)> {
    text.lines()
        .filter_map(|l| {
            let mut it = l.split_whitespace();
            let name = it.next()?;
            if !name.ends_with(".service") {
                return None;
            }
            let _load = it.next()?;
            let _active = it.next()?;
            let _sub = it.next()?;
            Some((name.to_string(), it.collect::<Vec<_>>().join(" ")))
        })
        .collect()
}

// ───────────────────────── Red ─────────────────────────

fn split_host_port(s: &str) -> Option<(String, u16)> {
    let (host, port) = s.rsplit_once(':')?;
    let port = port.parse().ok()?;
    let host = host.trim_start_matches('[').trim_end_matches(']');
    let host = host.split('%').next().unwrap_or(host);
    Some((host.to_string(), port))
}

fn exposure_of(host: &str) -> Exposure {
    if host.starts_with("127.") || host == "::1" {
        Exposure::Loopback
    } else if host == "0.0.0.0" || host == "::" || host == "*" {
        Exposure::AllInterfaces
    } else {
        Exposure::Specific
    }
}

fn parse_proc(users: &str) -> (Option<String>, Option<u32>) {
    // users:(("code",pid=6161,fd=42))
    let re = Regex::new(r#"\("([^"]*)",pid=(\d+)"#).unwrap();
    match re.captures(users) {
        Some(c) => (Some(c[1].to_string()), c[2].parse().ok()),
        None => (None, None),
    }
}

/// `ss -H -tulnp`
pub fn parse_ss_listeners(text: &str) -> Vec<Listener> {
    text.lines()
        .filter_map(|l| {
            let cols: Vec<&str> = l.split_whitespace().collect();
            if cols.len() < 5 {
                return None;
            }
            let proto = cols[0].to_string();
            if proto != "tcp" && proto != "udp" {
                return None;
            }
            let (host, port) = split_host_port(cols[4])?;
            let (process, pid) = cols.get(6).map(|u| parse_proc(u)).unwrap_or((None, None));
            Some(Listener { proto, exposure: exposure_of(&host), addr: host, port, process, pid })
        })
        .collect()
}

/// `ss -H -tnp state established`
pub fn parse_ss_established(text: &str) -> Vec<Connection> {
    text.lines()
        .filter_map(|l| {
            let cols: Vec<&str> = l.split_whitespace().collect();
            // Recv-Q Send-Q Local Peer [Process]
            if cols.len() < 4 {
                return None;
            }
            let (_, lp) = split_host_port(cols[2])?;
            let (rh, rp) = split_host_port(cols[3])?;
            let (process, pid) = cols.get(4).map(|u| parse_proc(u)).unwrap_or((None, None));
            Some(Connection { process, pid, local_port: lp, remote_addr: rh, remote_port: rp })
        })
        .collect()
}

pub fn collect_network(r: &dyn Runner) -> (Vec<Listener>, Vec<Connection>) {
    let l = r.out("ss", &["-H", "-tulnp"]).map(|s| parse_ss_listeners(&s)).unwrap_or_default();
    let c = r
        .out("ss", &["-H", "-tnp", "state", "established"])
        .map(|s| parse_ss_established(&s))
        .unwrap_or_default();
    (l, c)
}

// ───────────────────────── DNS ─────────────────────────

pub fn parse_resolvectl(text: &str) -> DnsInfo {
    let mut info = DnsInfo { resolved_active: true, ..Default::default() };
    let ip = Regex::new(r"^\s*([0-9a-fA-F:.]+(%\w+)?(#\S+)?)\s*$").unwrap();
    let key_line = Regex::new(r"^\s*[A-Za-z][A-Za-z ]*:").unwrap();
    let llmnr_re = Regex::new(r"LLMNR=(\w+)").unwrap();
    let link_re = Regex::new(r"^Link \d+ \((.+)\)").unwrap();
    let mut in_global = false;
    let mut link: Option<String> = None;
    let mut capture_servers = false;
    for line in text.lines() {
        let t = line.trim();
        if t == "Global" {
            in_global = true;
            link = None;
            continue;
        }
        if let Some(c) = link_re.captures(t) {
            in_global = false;
            link = Some(c[1].to_string());
            capture_servers = false;
            continue;
        }
        if t.starts_with("Protocols:") {
            if let Some(c) = llmnr_re.captures(t) {
                let mode = c[1].to_string();
                if in_global {
                    info.llmnr = mode;
                } else if let Some(l) = &link {
                    if mode == "yes" || mode == "resolve" {
                        info.llmnr_links.push(l.clone());
                    }
                }
            }
            if in_global {
                info.dns_over_tls = t.contains("+DNSOverTLS");
                info.mdns = t.contains("+mDNS");
            }
        }
        if in_global && t.starts_with("resolv.conf mode:") {
            info.stub_mode = t.contains("stub");
        }
        if t.starts_with("DNS Servers:") {
            capture_servers = true;
            let rest = t.trim_start_matches("DNS Servers:").trim();
            info.servers.extend(rest.split_whitespace().map(str::to_string));
            continue;
        }
        if capture_servers {
            if key_line.is_match(line) || t.is_empty() {
                capture_servers = false;
            } else if ip.is_match(line) {
                info.servers.push(t.to_string());
            }
        }
    }
    info.servers.sort();
    info.servers.dedup();
    info
}

pub fn collect_dns(r: &dyn Runner) -> DnsInfo {
    match r.out("resolvectl", &["status", "--no-pager"]) {
        Some(t) => parse_resolvectl(&t),
        None => DnsInfo::default(),
    }
}

// ───────────────────────── Almacenamiento ─────────────────────────

#[derive(Debug, Clone)]
struct BlockNode {
    kname: String,
    typ: String,
    mounts: Vec<String>,
    /// true si él o algún ancestro es dispositivo `crypt`.
    under_crypt: bool,
}

fn walk_lsblk(v: &serde_json::Value, parent_crypt: bool, out: &mut Vec<BlockNode>) {
    let Some(arr) = v.as_array() else { return };
    for n in arr {
        let typ = n["type"].as_str().unwrap_or("").to_string();
        let name = n["name"].as_str().unwrap_or("");
        let kname = n["kname"].as_str().unwrap_or(name).to_string();
        let mounts: Vec<String> = n["mountpoints"]
            .as_array()
            .map(|a| a.iter().filter_map(|m| m.as_str().map(str::to_string)).collect())
            .unwrap_or_default();
        let under = parent_crypt || typ == "crypt";
        out.push(BlockNode { kname, typ, mounts, under_crypt: under });
        walk_lsblk(&n["children"], under, out);
    }
}

/// `lsblk -J -o NAME,KNAME,TYPE,FSTYPE,MOUNTPOINTS` + contenido de /proc/swaps.
pub fn parse_storage(lsblk_json: &str, proc_swaps: &str) -> StorageInfo {
    let mut nodes = Vec::new();
    if let Ok(v) = serde_json::from_str::<serde_json::Value>(lsblk_json) {
        walk_lsblk(&v["blockdevices"], false, &mut nodes);
    }
    let root_encrypted = nodes
        .iter()
        .find(|n| n.mounts.iter().any(|m| m == "/"))
        .map(|n| n.under_crypt);

    let mut swaps = Vec::new();
    for line in proc_swaps.lines().skip(1) {
        let cols: Vec<&str> = line.split_whitespace().collect();
        if cols.len() < 2 {
            continue;
        }
        let dev = cols[0].to_string();
        let typ = cols[1].to_string();
        let base = dev.rsplit('/').next().unwrap_or(&dev).to_string();
        if base.starts_with("zram") {
            swaps.push(SwapInfo { device: dev, kind: "zram (solo RAM)".into(), encrypted: Some(true) });
        } else if typ == "file" {
            // Un archivo de swap vive en el sistema de archivos raíz (o el que lo contenga).
            swaps.push(SwapInfo { device: dev, kind: "archivo".into(), encrypted: root_encrypted });
        } else {
            let enc = nodes.iter().find(|n| n.kname == base).map(|n| n.under_crypt);
            swaps.push(SwapInfo { device: dev, kind: "partición".into(), encrypted: enc });
        }
    }
    StorageInfo { root_encrypted, swaps }
}

pub fn collect_storage(r: &dyn Runner) -> StorageInfo {
    let lsblk = r.out("lsblk", &["-J", "-o", "NAME,KNAME,TYPE,FSTYPE,MOUNTPOINTS"]).unwrap_or_default();
    let swaps = std::fs::read_to_string("/proc/swaps").unwrap_or_default();
    parse_storage(&lsblk, &swaps)
}

pub fn parse_secure_boot(text: &str) -> SecureBoot {
    let t = text.to_lowercase();
    if t.contains("doesn't support") || t.contains("not supported") {
        SecureBoot::Unsupported
    } else if t.contains("secureboot enabled") {
        SecureBoot::Enabled
    } else if t.contains("secureboot disabled") {
        SecureBoot::Disabled
    } else {
        SecureBoot::Unknown
    }
}

pub fn collect_secure_boot(r: &dyn Runner) -> SecureBoot {
    if !Path::new("/sys/firmware/efi").exists() {
        return SecureBoot::Unsupported;
    }
    // mokutil escribe el estado también cuando el código de salida es distinto de cero.
    let o = r.run("mokutil", &["--sb-state"]);
    if o.missing {
        return SecureBoot::Unknown;
    }
    parse_secure_boot(&format!("{}{}", o.stdout, o.stderr))
}

// ───────────────────────── Paquetes ─────────────────────────

pub fn parse_packages(pm: &str, text: &str) -> BTreeSet<String> {
    match pm {
        "dpkg" => text
            .lines()
            .filter_map(|l| {
                let (st, name) = l.split_once(' ')?;
                st.starts_with("ii").then(|| name.trim().split(':').next().unwrap_or("").to_string())
            })
            .collect(),
        "xbps" => text
            .lines()
            .filter_map(|l| {
                let mut it = l.split_whitespace();
                let st = it.next()?;
                let nv = it.next()?;
                (st == "ii").then(|| nv.rsplit_once('-').map(|x| x.0).unwrap_or(nv).to_string())
            })
            .collect(),
        "apk" => text
            .lines()
            .map(|l| {
                // nombre-1.2.3-r0 → nombre
                let re = Regex::new(r"-\d").unwrap();
                match re.find(l.trim()) {
                    Some(m) => l.trim()[..m.start()].to_string(),
                    None => l.trim().to_string(),
                }
            })
            .filter(|s| !s.is_empty())
            .collect(),
        _ => text.lines().map(|l| l.trim().to_string()).filter(|s| !s.is_empty()).collect(),
    }
}

pub fn collect_packages(r: &dyn Runner, pm: Option<&str>) -> BTreeSet<String> {
    let Some(pm) = pm else { return BTreeSet::new() };
    let out = match pm {
        "rpm" => r.out("rpm", &["-qa", "--qf", "%{NAME}\n"]),
        "dpkg" => r.out("dpkg-query", &["-W", "-f=${db:Status-Abbrev} ${Package}\n"]),
        "pacman" => r.out("pacman", &["-Qq"]),
        "apk" => r.out("apk", &["info"]),
        "xbps" => r.out("xbps-query", &["-l"]),
        _ => None,
    };
    out.map(|t| parse_packages(pm, &t)).unwrap_or_default()
}

// ───────────────────────── Sondas pedidas por reglas ─────────────────────────

pub fn collect_sysctl(keys: &BTreeSet<String>) -> BTreeMap<String, String> {
    keys.iter()
        .filter_map(|k| {
            let path = format!("/proc/sys/{}", k.replace('.', "/"));
            std::fs::read_to_string(path).ok().map(|v| (k.clone(), v.trim().to_string()))
        })
        .collect()
}

pub fn collect_gsettings(r: &dyn Runner, items: &BTreeSet<(String, String)>) -> BTreeMap<String, String> {
    let mut m = BTreeMap::new();
    if !r.exists("gsettings") {
        return m;
    }
    for (schema, key) in items {
        let o = r.run("gsettings", &["get", schema, key]);
        if o.ok {
            m.insert(format!("{schema} {key}"), o.stdout.trim().to_string());
        }
    }
    m
}

pub const KCONFIG_UNSET: &str = "__silence_unset__";

pub fn kconfig_key(file: &str, group: &str, key: &str) -> String {
    format!("{file}|{group}|{key}")
}

pub fn kreadconfig_cmd(r: &dyn Runner) -> Option<&'static str> {
    ["kreadconfig6", "kreadconfig5"].into_iter().find(|c| r.exists(c))
}

pub fn collect_kconfig(r: &dyn Runner, items: &BTreeSet<(String, String, String)>) -> BTreeMap<String, Option<String>> {
    let mut m = BTreeMap::new();
    let Some(cmd) = kreadconfig_cmd(r) else { return m };
    for (file, group, key) in items {
        let o = r.run(cmd, &["--file", file, "--group", group, "--key", key, "--default", KCONFIG_UNSET]);
        if o.ok {
            let v = o.stdout.trim().to_string();
            m.insert(kconfig_key(file, group, key), if v == KCONFIG_UNSET { None } else { Some(v) });
        }
    }
    m
}

pub fn expand_home(p: &str) -> String {
    if let Some(rest) = p.strip_prefix("~/") {
        if let Ok(h) = std::env::var("HOME") {
            return format!("{h}/{rest}");
        }
    }
    p.to_string()
}

pub fn probe_files(globs: &[String], pattern: &str) -> FileProbe {
    let re = match Regex::new(&format!("(?m){pattern}")) {
        Ok(r) => r,
        Err(_) => return FileProbe::default(),
    };
    let mut probe = FileProbe::default();
    for g in globs {
        let Ok(paths) = glob::glob(&expand_home(g)) else { continue };
        for p in paths.flatten() {
            if !p.is_file() {
                continue;
            }
            let Ok(meta) = p.metadata() else { continue };
            if meta.len() > 1_000_000 {
                continue;
            }
            let Ok(text) = std::fs::read_to_string(&p) else { continue };
            probe.files_checked += 1;
            for m in re.find_iter(&text) {
                let line = text[..m.start()].matches('\n').count() + 1;
                probe.matches.push(format!("{}:{}", p.display(), line));
            }
        }
    }
    probe
}

// ───────────────────────── Evidencia de uso ─────────────────────────

pub fn evidence_bluetooth(r: &dyn Runner, hw: &BTreeSet<String>) -> Evidence {
    if !hw.contains("bluetooth") {
        return Evidence { in_use: Some(false), detail: "Este equipo no tiene adaptador Bluetooth.".into() };
    }
    if !r.exists("bluetoothctl") {
        return Evidence { in_use: None, detail: "No se pudo consultar Bluetooth (falta bluetoothctl).".into() };
    }
    let lines = |o: Option<String>| -> Vec<String> {
        o.unwrap_or_default()
            .lines()
            .filter_map(|l| l.trim().strip_prefix("Device "))
            .map(|l| l.splitn(2, ' ').nth(1).unwrap_or("dispositivo").to_string())
            .collect()
    };
    let paired = lines(r.out("bluetoothctl", &["devices", "Paired"]));
    let connected = lines(r.out("bluetoothctl", &["devices", "Connected"]));
    if !connected.is_empty() {
        return Evidence {
            in_use: Some(true),
            detail: format!("Ahora mismo estás conectado a: {}.", connected.join(", ")),
        };
    }
    if !paired.is_empty() {
        return Evidence {
            in_use: Some(true),
            detail: format!("Tienes {} dispositivo(s) emparejado(s): {}.", paired.len(), paired.join(", ")),
        };
    }
    Evidence { in_use: Some(false), detail: "No hay dispositivos Bluetooth emparejados.".into() }
}

pub fn evidence_printers(r: &dyn Runner) -> Evidence {
    let o = r.run("lpstat", &["-p"]);
    if o.missing {
        return Evidence { in_use: None, detail: "No se pudo consultar impresoras (falta lpstat).".into() };
    }
    let printers: Vec<String> = o
        .stdout
        .lines()
        .filter_map(|l| l.strip_prefix("printer "))
        .map(|l| l.split_whitespace().next().unwrap_or("").to_string())
        .collect();
    if !printers.is_empty() {
        return Evidence {
            in_use: Some(true),
            detail: format!("Tienes impresora(s) configurada(s): {}.", printers.join(", ")),
        };
    }
    if o.ok || o.stdout.contains("No destinations") || o.stderr.contains("No destinations") {
        return Evidence { in_use: Some(false), detail: "No hay impresoras configuradas.".into() };
    }
    Evidence { in_use: None, detail: "El servicio de impresión no está corriendo; no se pudo ver si hay impresoras.".into() }
}

/// Conexiones entrantes hacia un puerto local dado.
pub fn incoming_on(conns: &[Connection], ports: &[u16]) -> usize {
    conns.iter().filter(|c| ports.contains(&c.local_port)).count()
}

pub fn evidence_ssh(conns: &[Connection]) -> Evidence {
    let n = incoming_on(conns, &[22]);
    if n > 0 {
        return Evidence { in_use: Some(true), detail: format!("Hay {n} sesión(es) SSH entrante(s) activa(s) ahora mismo.") };
    }
    let home = std::env::var("HOME").unwrap_or_default();
    let ak = format!("{home}/.ssh/authorized_keys");
    if std::fs::read_to_string(&ak).map(|s| s.lines().any(|l| !l.trim().is_empty() && !l.starts_with('#'))).unwrap_or(false) {
        return Evidence {
            in_use: Some(true),
            detail: "Tienes claves autorizadas en ~/.ssh/authorized_keys: parece que entras a este equipo por SSH.".into(),
        };
    }
    Evidence { in_use: Some(false), detail: "Nadie está conectado por SSH y no hay claves autorizadas en tu cuenta.".into() }
}

pub fn evidence_fileshare(conns: &[Connection]) -> Evidence {
    let n = incoming_on(conns, &[445, 139, 2049]);
    if n > 0 {
        Evidence { in_use: Some(true), detail: format!("Hay {n} conexión(es) activa(s) a tus carpetas compartidas.") }
    } else {
        Evidence { in_use: Some(false), detail: "Nadie está accediendo a carpetas compartidas desde este equipo ahora mismo.".into() }
    }
}

pub fn evidence_modem(r: &dyn Runner, hw: &BTreeSet<String>) -> Evidence {
    if hw.contains("modem") {
        return Evidence { in_use: Some(true), detail: "Se detectó hardware de módem móvil (WWAN/CDC).".into() };
    }
    if let Some(o) = r.out("mmcli", &["-L"]) {
        if o.contains("/Modem/") {
            return Evidence { in_use: Some(true), detail: "ModemManager reporta un módem conectado.".into() };
        }
    }
    Evidence { in_use: Some(false), detail: "No se detectó ningún módem móvil.".into() }
}

// ───────────────────────── Flatpak y autostart ─────────────────────────

/// Interpreta la sección [Context] de `flatpak info --show-permissions` / `flatpak override --show`.
fn context_list(text: &str, key: &str) -> Vec<String> {
    let mut in_ctx = false;
    for l in text.lines() {
        let t = l.trim();
        if t.starts_with('[') {
            in_ctx = t == "[Context]";
            continue;
        }
        if in_ctx {
            if let Some(v) = t.strip_prefix(&format!("{key}=")) {
                return v.split(';').filter(|s| !s.is_empty()).map(str::to_string).collect();
            }
        }
    }
    Vec::new()
}

pub fn broad_permissions(perms: &str, overrides: &str) -> Vec<String> {
    let mut fs = context_list(perms, "filesystems");
    let mut dev = context_list(perms, "devices");
    for o in context_list(overrides, "filesystems") {
        if let Some(neg) = o.strip_prefix('!') {
            fs.retain(|x| x.split(':').next() != Some(neg));
        } else {
            fs.push(o);
        }
    }
    for o in context_list(overrides, "devices") {
        if let Some(neg) = o.strip_prefix('!') {
            dev.retain(|x| x != neg);
        } else {
            dev.push(o);
        }
    }
    let mut broad = Vec::new();
    for f in &fs {
        let base = f.split(':').next().unwrap_or(f);
        let ro = f.ends_with(":ro");
        match base {
            "host" | "host-os" | "host-etc" => broad.push(format!("acceso a todo el sistema de archivos ({base}{})", if ro { ", solo lectura" } else { "" })),
            "home" => broad.push(format!("acceso a toda tu carpeta personal{}", if ro { " (solo lectura)" } else { "" })),
            "/" => broad.push("acceso a la raíz del sistema".into()),
            _ => {}
        }
    }
    if dev.iter().any(|d| d == "all") {
        broad.push("acceso a todos los dispositivos (cámara, micrófono, USB…)".into());
    }
    broad
}

pub fn collect_flatpaks(r: &dyn Runner) -> Vec<FlatpakApp> {
    if !r.exists("flatpak") {
        return Vec::new();
    }
    let Some(list) = r.out("flatpak", &["list", "--app", "--columns=application"]) else { return Vec::new() };
    let ids: Vec<String> = list.lines().map(|l| l.trim().to_string()).filter(|l| !l.is_empty() && l.contains('.')).collect();
    std::thread::scope(|s| {
        let hs: Vec<_> = ids
            .iter()
            .map(|id| {
                s.spawn(move || {
                    let perms = r.out("flatpak", &["info", "--show-permissions", id]).unwrap_or_default();
                    let ov = r.out("flatpak", &["override", "--user", "--show", id]).unwrap_or_default();
                    FlatpakApp { id: id.clone(), broad: broad_permissions(&perms, &ov) }
                })
            })
            .collect();
        hs.into_iter().filter_map(|h| h.join().ok()).collect()
    })
}

pub fn parse_desktop_entry(text: &str) -> Option<(String, String, bool)> {
    let mut in_entry = false;
    let (mut name, mut exec, mut hidden) = (None, None, false);
    for l in text.lines() {
        let t = l.trim();
        if t.starts_with('[') {
            in_entry = t == "[Desktop Entry]";
            continue;
        }
        if !in_entry {
            continue;
        }
        if let Some(v) = t.strip_prefix("Name=") {
            name.get_or_insert(v.to_string());
        } else if let Some(v) = t.strip_prefix("Exec=") {
            exec.get_or_insert(v.to_string());
        } else if t == "Hidden=true" || t == "X-GNOME-Autostart-enabled=false" {
            hidden = true;
        }
    }
    Some((name?, exec.unwrap_or_default(), hidden))
}

pub fn collect_autostart() -> Vec<AutostartEntry> {
    let home = std::env::var("HOME").unwrap_or_default();
    let mut seen: BTreeMap<String, Option<AutostartEntry>> = BTreeMap::new();
    for (dir, system) in [(format!("{home}/.config/autostart"), false), ("/etc/xdg/autostart".to_string(), true)] {
        let Ok(rd) = std::fs::read_dir(&dir) else { continue };
        for e in rd.flatten() {
            let fname = e.file_name().to_string_lossy().to_string();
            if !fname.ends_with(".desktop") || seen.contains_key(&fname) {
                continue; // el del usuario tiene prioridad sobre el del sistema
            }
            let Ok(text) = std::fs::read_to_string(e.path()) else { continue };
            let entry = parse_desktop_entry(&text).and_then(|(name, exec, hidden)| {
                (!hidden).then_some(AutostartEntry { name, exec, system_wide: system })
            });
            seen.insert(fname, entry);
        }
    }
    let mut v: Vec<AutostartEntry> = seen.into_values().flatten().collect();
    v.sort_by(|a, b| a.name.to_lowercase().cmp(&b.name.to_lowercase()));
    v
}

// ───────────────────────── Firewall, MAC (SELinux/AppArmor), NetworkManager ─────────────────────────

/// `firewall-cmd --list-all --zone=X`
pub fn parse_zone_list(text: &str) -> ZoneInfo {
    let mut z = ZoneInfo::default();
    for l in text.lines() {
        let t = l.trim();
        let list = |k: &str| t.strip_prefix(k).map(|r| r.split_whitespace().map(str::to_string).collect::<Vec<_>>());
        if let Some(v) = list("services:") {
            z.services = v;
        } else if let Some(v) = list("ports:") {
            z.ports = v;
        } else if let Some(v) = list("interfaces:") {
            z.interfaces = v;
        }
    }
    z
}

pub fn collect_firewall(r: &dyn Runner) -> FirewallInfo {
    let mut f = FirewallInfo::default();
    if r.exists("firewall-cmd") {
        f.backend = Some("firewalld".into());
        f.active = r.out("firewall-cmd", &["--state"]).map(|s| s.trim() == "running").unwrap_or(false);
        if f.active {
            f.default_zone = r.out("firewall-cmd", &["--get-default-zone"]).map(|s| s.trim().to_string());
            if let Some(z) = r.out("firewall-cmd", &["--get-active-zones"]) {
                for (zone, _ifaces) in crate::apply::parse_active_zones(&z) {
                    let flag = format!("--zone={zone}");
                    if let Some(t) = r.out("firewall-cmd", &["--list-all", &flag]) {
                        f.zones.insert(zone, parse_zone_list(&t));
                    }
                }
            }
        }
    } else if r.exists("ufw") {
        f.backend = Some("ufw".into());
    }
    f
}

pub fn collect_mac() -> MacInfo {
    if let Ok(v) = std::fs::read_to_string("/sys/fs/selinux/enforce") {
        return MacInfo { system: "selinux".into(), enforcing: v.trim() == "1" };
    }
    if let Ok(cfg) = std::fs::read_to_string("/etc/selinux/config") {
        if cfg.lines().any(|l| l.trim().starts_with("SELINUX=disabled") || l.trim().starts_with("SELINUX=permissive")) {
            return MacInfo { system: "selinux".into(), enforcing: false };
        }
    }
    if let Ok(v) = std::fs::read_to_string("/sys/module/apparmor/parameters/enabled") {
        return MacInfo { system: "apparmor".into(), enforcing: v.trim() == "Y" };
    }
    MacInfo { system: "none".into(), enforcing: false }
}

/// `nmcli -t -f UUID,NAME,TYPE,ACTIVE connection show`
pub fn parse_nm_profiles(text: &str) -> Vec<NmProfile> {
    text.lines()
        .filter_map(|l| {
            let f = crate::apply::split_terse(l);
            if f.len() < 4 {
                return None;
            }
            let n = f.len();
            Some(NmProfile { uuid: f[0].clone(), name: f[1..n - 2].join(":"), kind: f[n - 2].clone(), active: f[n - 1] == "yes" })
        })
        .collect()
}

pub fn collect_nm_profiles(r: &dyn Runner) -> Vec<NmProfile> {
    r.out("nmcli", &["-t", "-f", "UUID,NAME,TYPE,ACTIVE", "connection", "show"])
        .map(|t| parse_nm_profiles(&t))
        .unwrap_or_default()
}

/// Claves de sysctl que las herramientas necesitan leer siempre.
pub const TOOL_SYSCTL: [&str; 9] = [
    "net.ipv6.conf.all.disable_ipv6",
    "net.ipv6.conf.default.disable_ipv6",
    "net.ipv4.ip_default_ttl",
    "net.ipv4.tcp_timestamps",
    "net.ipv4.tcp_ecn",
    "net.ipv6.conf.all.hop_limit",
    "net.ipv6.conf.default.hop_limit",
    "net.ipv6.conf.lo.disable_ipv6",
    "net.ipv6.conf.all.use_tempaddr",
];

// ───────────────────────── Orquestación ─────────────────────────

fn referenced(rules: &[Rule]) -> (BTreeSet<String>, BTreeSet<String>, BTreeSet<(String, String)>, BTreeSet<(String, String, String)>) {
    let mut units: BTreeSet<String> = ["firewalld.service", "ufw.service", "nftables.service", "systemd-resolved.service", "NetworkManager.service"]
        .into_iter()
        .map(String::from)
        .collect();
    let mut sysctl = BTreeSet::new();
    let mut gs = BTreeSet::new();
    let mut kc = BTreeSet::new();
    for r in rules {
        units.extend(r.applies.units_active.iter().cloned());
        match &r.detect {
            Detect::Unit { units: u } => units.extend(u.iter().cloned()),
            Detect::Sysctl { key, .. } => {
                sysctl.insert(key.clone());
            }
            Detect::Gsettings { schema, key, .. } => {
                gs.insert((schema.clone(), key.clone()));
            }
            Detect::Kconfig { file, group, key, .. } => {
                kc.insert((file.clone(), group.clone(), key.clone()));
            }
            _ => {}
        }
        if let Fix::DisableUnits { units: u } = &r.fix {
            units.extend(u.iter().cloned());
        }
    }
    (units, sysctl, gs, kc)
}

pub fn collect(r: &dyn Runner, rules: &[Rule]) -> Snapshot {
    let (units, sysctl_keys, gs_items, kc_items) = referenced(rules);
    let info = collect_info(r);
    let pm = info.pkg_manager.clone();
    let hw = info.hardware.clone();
    let systemd = info.init == "systemd";

    let mut snap = Snapshot {
        taken_at: chrono::Utc::now().timestamp(),
        info,
        commands: rules
            .iter()
            .flat_map(|r| r.applies.commands.iter().cloned())
            .filter(|c| r.exists(c))
            .collect(),
        ..Default::default()
    };

    std::thread::scope(|s| {
        let h_units = s.spawn(|| if systemd { collect_units(r, &units) } else { BTreeMap::new() });
        let h_running = s.spawn(|| {
            if !systemd {
                return (Vec::new(), 0usize);
            }
            let running = r
                .out("systemctl", &["list-units", "--type=service", "--state=running", "--plain", "--no-legend", "--no-pager"])
                .map(|t| parse_running_services(&t))
                .unwrap_or_default();
            let enabled = r
                .out("systemctl", &["list-unit-files", "--state=enabled", "--plain", "--no-legend", "--no-pager"])
                .map(|t| t.lines().filter(|l| !l.trim().is_empty()).count())
                .unwrap_or(0);
            (running, enabled)
        });
        let h_pkgs = s.spawn(|| collect_packages(r, pm.as_deref()));
        let h_net = s.spawn(|| collect_network(r));
        let h_dns = s.spawn(|| collect_dns(r));
        let h_storage = s.spawn(|| collect_storage(r));
        let h_sb = s.spawn(|| collect_secure_boot(r));
        let h_flat = s.spawn(|| collect_flatpaks(r));
        let h_gs = s.spawn(|| collect_gsettings(r, &gs_items));
        let h_kc = s.spawn(|| collect_kconfig(r, &kc_items));
        let h_bt = s.spawn(|| evidence_bluetooth(r, &hw));
        let h_pr = s.spawn(|| evidence_printers(r));
        let h_modem = s.spawn(|| evidence_modem(r, &hw));
        let h_ff = s.spawn(crate::firefox::collect_profiles);
        let h_fw = s.spawn(|| collect_firewall(r));
        let h_nm = s.spawn(|| collect_nm_profiles(r));
        let h_br = s.spawn(|| crate::browsers::collect_targets(r));

        snap.units = h_units.join().unwrap_or_default();
        let (running, enabled) = h_running.join().unwrap_or_default();
        snap.running_services = running;
        snap.enabled_unit_files = enabled;
        snap.packages = h_pkgs.join().unwrap_or_default();
        let (l, c) = h_net.join().unwrap_or_default();
        snap.listeners = l;
        snap.connections = c;
        snap.dns = h_dns.join().unwrap_or_default();
        snap.storage = h_storage.join().unwrap_or_default();
        snap.secure_boot = h_sb.join().unwrap_or_default();
        snap.flatpaks = h_flat.join().unwrap_or_default();
        snap.gsettings = h_gs.join().unwrap_or_default();
        snap.kconfig = h_kc.join().unwrap_or_default();
        snap.firefox = h_ff.join().unwrap_or_default();
        snap.firewall = h_fw.join().unwrap_or_default();
        snap.nm_profiles = h_nm.join().unwrap_or_default();
        snap.browsers = h_br.join().unwrap_or_default();
        snap.evidence.insert(EvidenceKind::Bluetooth, h_bt.join().unwrap());
        snap.evidence.insert(EvidenceKind::Printers, h_pr.join().unwrap());
        snap.evidence.insert(EvidenceKind::Modem, h_modem.join().unwrap());
    });

    snap.dns.resolved_active = snap.units.get("systemd-resolved.service").map(|u| u.is_active()).unwrap_or(false);
    let mut all_keys = sysctl_keys.clone();
    all_keys.extend(TOOL_SYSCTL.iter().map(|k| k.to_string()));
    snap.sysctl = collect_sysctl(&all_keys);
    snap.mac = collect_mac();
    snap.evidence.insert(EvidenceKind::Ssh, evidence_ssh(&snap.connections));
    snap.evidence.insert(EvidenceKind::FileShare, evidence_fileshare(&snap.connections));
    snap.autostart = collect_autostart();

    for rule in rules {
        if let Detect::FileRegex { globs, pattern, .. } = &rule.detect {
            snap.file_probes.insert(rule.id.clone(), probe_files(globs, pattern));
        }
    }

    // Honestidad sobre los límites del escaneo.
    if !snap.info.is_root {
        snap.notes.push("Escaneo sin privilegios de administrador: no se ven los procesos de otros usuarios (por ejemplo, qué programa abre cada puerto del sistema) ni las reglas internas del firewall.".into());
    }
    if snap.info.init != "systemd" {
        snap.notes.push(format!("Sistema de init «{}»: el análisis de servicios todavía solo soporta systemd.", snap.info.init));
    }
    if snap.info.pkg_manager.is_none() {
        snap.notes.push("No se reconoció el gestor de paquetes; no se pueden detectar paquetes de telemetría.".into());
    }
    snap
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ss_listeners_real_sample() {
        let s = r#"udp UNCONN 0      0         127.0.0.54:53    0.0.0.0:*
udp UNCONN 0      0      127.0.0.53%lo:53    0.0.0.0:*
udp UNCONN 0      0            0.0.0.0:5353  0.0.0.0:*
udp UNCONN 0      0                  *:1716        *:* users:(("kdeconnectd",pid=2417,fd=15))
tcp LISTEN 0      128          0.0.0.0:22    0.0.0.0:*
tcp LISTEN 0      511        127.0.0.1:10669 0.0.0.0:* users:(("code",pid=6161,fd=42))
tcp LISTEN 0      4096         *:9800        *:* users:(("fluidsynth",pid=1626,fd=4))
tcp LISTEN 0      128             [::]:22       [::]:*
tcp LISTEN 0      4096           [::1]:631      [::]:*
"#;
        let l = parse_ss_listeners(s);
        assert_eq!(l.len(), 9);
        let ssh = l.iter().find(|x| x.port == 22 && x.addr == "0.0.0.0").unwrap();
        assert_eq!(ssh.exposure, Exposure::AllInterfaces);
        assert!(ssh.process.is_none());
        let f = l.iter().find(|x| x.port == 9800).unwrap();
        assert_eq!(f.process.as_deref(), Some("fluidsynth"));
        assert_eq!(f.pid, Some(1626));
        assert_eq!(f.exposure, Exposure::AllInterfaces);
        let lo = l.iter().find(|x| x.port == 53 && x.addr == "127.0.0.53").unwrap();
        assert_eq!(lo.exposure, Exposure::Loopback);
        let cups = l.iter().find(|x| x.port == 631).unwrap();
        assert_eq!(cups.addr, "::1");
        assert_eq!(cups.exposure, Exposure::Loopback);
    }

    #[test]
    fn ss_established() {
        let s = "0 0 192.168.1.5:43210 142.250.1.1:443 users:((\"firefox\",pid=99,fd=3))\n0 0 127.0.0.1:1 127.0.0.1:2\n";
        let c = parse_ss_established(s);
        assert_eq!(c.len(), 2);
        assert_eq!(c[0].process.as_deref(), Some("firefox"));
        assert_eq!(c[0].remote_port, 443);
    }

    #[test]
    fn resolvectl_real_sample() {
        let s = "Global\n         Protocols: LLMNR=resolve -mDNS -DNSOverTLS DNSSEC=no/unsupported\n  resolv.conf mode: stub\n\nLink 2 (wlo1)\n    Current Scopes: DNS LLMNR/IPv4 LLMNR/IPv6\n         Protocols: +DefaultRoute LLMNR=resolve -mDNS -DNSOverTLS\n                    DNSSEC=no/unsupported\nCurrent DNS Server: 1.1.1.1\n       DNS Servers: 1.1.1.1 8.8.8.8\n        DNS Domain: localdomain\n";
        let d = parse_resolvectl(s);
        assert!(d.stub_mode);
        assert!(!d.dns_over_tls);
        assert!(!d.mdns);
        assert_eq!(d.llmnr, "resolve");
        assert_eq!(d.llmnr_links, vec!["wlo1"]);
        assert_eq!(d.servers, vec!["1.1.1.1", "8.8.8.8"]);
    }

    #[test]
    fn resolvectl_dot_enabled() {
        let s = "Global\n         Protocols: -LLMNR -mDNS +DNSOverTLS DNSSEC=no/unsupported\n  resolv.conf mode: stub\n";
        let d = parse_resolvectl(s);
        assert!(d.dns_over_tls);
        assert_eq!(d.llmnr, "");
    }

    #[test]
    fn lsblk_luks_root() {
        let j = r#"{"blockdevices":[{"name":"zram0","kname":"zram0","type":"disk","fstype":"swap","mountpoints":["[SWAP]"]},
        {"name":"nvme0n1","kname":"nvme0n1","type":"disk","fstype":null,"mountpoints":[null],"children":[
          {"name":"nvme0n1p2","kname":"nvme0n1p2","type":"part","fstype":"ext4","mountpoints":["/boot"]},
          {"name":"nvme0n1p3","kname":"nvme0n1p3","type":"part","fstype":"crypto_LUKS","mountpoints":[null],"children":[
            {"name":"luks-1","kname":"dm-0","type":"crypt","fstype":"btrfs","mountpoints":["/home","/"]}]}]}]}"#;
        let swaps = "Filename\tType\tSize\tUsed\tPriority\n/dev/zram0 partition 8388604 0 100\n";
        let s = parse_storage(j, swaps);
        assert_eq!(s.root_encrypted, Some(true));
        assert_eq!(s.swaps.len(), 1);
        assert_eq!(s.swaps[0].encrypted, Some(true));
    }

    #[test]
    fn lsblk_plain_root_and_swap_partition() {
        let j = r#"{"blockdevices":[{"name":"sda","kname":"sda","type":"disk","mountpoints":[null],"children":[
          {"name":"sda1","kname":"sda1","type":"part","fstype":"ext4","mountpoints":["/"]},
          {"name":"sda2","kname":"sda2","type":"part","fstype":"swap","mountpoints":["[SWAP]"]}]}]}"#;
        let swaps = "Filename Type Size Used Priority\n/dev/sda2 partition 2097148 0 -2\n/swapfile file 1000 0 -3\n";
        let s = parse_storage(j, swaps);
        assert_eq!(s.root_encrypted, Some(false));
        assert_eq!(s.swaps[0].encrypted, Some(false));
        assert_eq!(s.swaps[1].kind, "archivo");
        assert_eq!(s.swaps[1].encrypted, Some(false));
    }

    #[test]
    fn systemctl_show_blocks() {
        let t = "Id=cups.service\nLoadState=loaded\nUnitFileState=enabled\nActiveState=active\nRequiredBy=\nBoundBy=\n\nId=nope.service\nLoadState=not-found\nUnitFileState=\nActiveState=inactive\n";
        let b = parse_systemctl_show(t);
        assert_eq!(b.len(), 2);
        assert_eq!(b[1]["LoadState"], "not-found");
    }

    #[test]
    fn units_collection_filters_inactive_dependents() {
        let r = crate::sys::mock::MockRunner::new();
        let wanted: BTreeSet<String> = ["a.service".to_string()].into();
        let args = show_args(&["a.service".to_string()].to_vec()).join(" ");
        r.on("systemctl", "");
        r.on(
            &format!("systemctl {args}"),
            "Id=a.service\nLoadState=loaded\nUnitFileState=enabled\nActiveState=active\nRequiredBy=b.service c.service\nBoundBy=\n",
        );
        r.on(
            "systemctl show --no-pager -p Id -p ActiveState b.service c.service",
            "Id=b.service\nActiveState=active\n\nId=c.service\nActiveState=inactive\n",
        );
        let m = collect_units(&r, &wanted);
        assert_eq!(m["a.service"].required_by, vec!["b.service"]);
        assert!(m["a.service"].is_active() && m["a.service"].is_enabled());
    }

    #[test]
    fn packages_parsers() {
        assert!(parse_packages("rpm", "abrt\nbash\n").contains("abrt"));
        let d = parse_packages("dpkg", "ii  apport\nrc  oldpkg\nii  libc6:amd64\n");
        assert!(d.contains("apport") && !d.contains("oldpkg") && d.contains("libc6"));
        assert!(parse_packages("xbps", "ii avahi-0.8_1 Service\n").contains("avahi"));
        assert!(parse_packages("apk", "busybox-1.36.1-r5\nca-certificates-20230506-r0\n").contains("ca-certificates"));
    }

    #[test]
    fn zone_list_real_sample() {
        let t = "home (active)\n  target: default\n  interfaces: wlo1\n  services: dhcpv6-client mdns samba-client ssh\n  ports: 1025-65535/tcp\n  protocols: \n";
        let z = parse_zone_list(t);
        assert_eq!(z.interfaces, vec!["wlo1"]);
        assert!(z.services.contains(&"ssh".to_string()));
        assert_eq!(z.ports, vec!["1025-65535/tcp"]);
    }

    #[test]
    fn nm_profiles_parser() {
        let p = parse_nm_profiles("u1:Casa\\: wifi:802-11-wireless:yes\nu2:VPN:vpn:no\n");
        assert_eq!(p.len(), 2);
        assert_eq!(p[0].name, "Casa: wifi");
        assert!(p[0].active && !p[1].active);
        assert_eq!(p[0].kind, "802-11-wireless");
    }

    #[test]
    fn os_release() {
        let m = parse_os_release("NAME=\"Fedora Linux\"\nID=fedora\nID_LIKE=\"rhel centos\"\n# c\nVERSION_ID=44\n");
        assert_eq!(m["ID"], "fedora");
        assert_eq!(m["ID_LIKE"], "rhel centos");
    }

    #[test]
    fn flatpak_permissions() {
        let perms = "[Context]\nshared=network;ipc;\nsockets=x11;\ndevices=all;\nfilesystems=host;xdg-download;\n";
        assert_eq!(broad_permissions(perms, "").len(), 2);
        // Un override del usuario que quita `host` lo elimina de la lista.
        let ov = "[Context]\nfilesystems=!host;\n";
        let b = broad_permissions(perms, ov);
        assert_eq!(b.len(), 1);
        assert!(b[0].contains("dispositivos"));
        assert!(broad_permissions("[Context]\nfilesystems=xdg-documents:ro;\n", "").is_empty());
    }

    #[test]
    fn bluetooth_evidence() {
        let r = crate::sys::mock::MockRunner::new();
        r.on("bluetoothctl devices Paired", "Device AA:BB:CC:DD:EE:FF Sony WH-1000XM4\n");
        r.on("bluetoothctl devices Connected", "");
        let hw: BTreeSet<String> = ["bluetooth".to_string()].into();
        let e = evidence_bluetooth(&r, &hw);
        assert_eq!(e.in_use, Some(true));
        assert!(e.detail.contains("Sony"));
        assert_eq!(evidence_bluetooth(&r, &BTreeSet::new()).in_use, Some(false));
    }

    #[test]
    fn printers_evidence() {
        let r = crate::sys::mock::MockRunner::new();
        r.on("lpstat -p", "printer HP_LaserJet is idle.  enabled since Mon\n");
        assert_eq!(evidence_printers(&r).in_use, Some(true));
        let r2 = crate::sys::mock::MockRunner::new();
        r2.on("lpstat -p", "");
        assert_eq!(evidence_printers(&r2).in_use, Some(false));
    }

    #[test]
    fn secure_boot_parse() {
        assert_eq!(parse_secure_boot("SecureBoot enabled"), SecureBoot::Enabled);
        assert_eq!(parse_secure_boot("SecureBoot disabled\nPlatform is in Setup Mode"), SecureBoot::Disabled);
        assert_eq!(parse_secure_boot("This system doesn't support Secure Boot"), SecureBoot::Unsupported);
    }

    #[test]
    fn probe_files_finds_countme() {
        let dir = std::env::temp_dir().join(format!("silence-probe-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("a.repo"), "[fedora]\nname=x\ncountme=1\n").unwrap();
        std::fs::write(dir.join("b.repo"), "[other]\ncountme=0\n").unwrap();
        let p = probe_files(&[format!("{}/*.repo", dir.display())], r"^\s*countme\s*=\s*(1|true)\s*$");
        assert_eq!(p.files_checked, 2);
        assert_eq!(p.matches.len(), 1);
        assert!(p.matches[0].ends_with("a.repo:3"));
        std::fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn desktop_entry() {
        let (n, e, h) = parse_desktop_entry("[Desktop Entry]\nName=Foo\nExec=foo --bar\nHidden=true\n").unwrap();
        assert_eq!((n.as_str(), e.as_str(), h), ("Foo", "foo --bar", true));
    }
}
