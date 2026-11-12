//! Motor: cruza reglas × snapshot → hallazgos. Es puro (sin E/S), por eso se prueba con fixtures.
//! Aquí vive también el «planificador»: evidencia de uso, dependencias y seguridad de cada cambio.

use crate::learn::Learned;
use crate::model::*;
use std::collections::BTreeSet;

pub const BUILTINS: &[&str] = &[
    "dns_over_tls",
    "dns_llmnr",
    "exposed_ports",
    "no_firewall",
    "firewall_zone_open",
    "mac_disabled",
    "hostname_personal",
    "root_unencrypted",
    "swap_unencrypted",
    "secure_boot_off",
    "firefox_telemetry",
    "flatpak_broad",
];

/// Servidores DNS públicos conocidos que admiten DNS-over-TLS.
const DOT_CAPABLE: [&str; 10] = [
    "1.1.1.1", "1.0.0.1", "8.8.8.8", "8.8.4.4", "9.9.9.9", "149.112.112.112", "94.140.14.14", "94.140.15.15",
    "2606:4700:4700::1111", "2001:4860:4860::8888",
];

const GENERIC_HOSTNAMES: [&str; 14] = [
    "", "localhost", "localhost.localdomain", "fedora", "ubuntu", "debian", "arch", "archlinux", "linux", "mint",
    "linuxmint", "manjaro", "opensuse", "nixos",
];

struct Detection {
    applicable: bool,
    fires: bool,
    observed: Vec<String>,
}

impl Detection {
    fn na() -> Self {
        Detection { applicable: false, fires: false, observed: vec![] }
    }
}

pub fn is_generic_hostname(host: &str, distro_id: &str) -> bool {
    let h = host.trim().to_lowercase();
    let windows_style = regex::Regex::new(r"^desktop-[a-z0-9]{7}$").unwrap().is_match(&h);
    h.starts_with("localhost") || GENERIC_HOSTNAMES.contains(&h.as_str()) || (!distro_id.is_empty() && h == distro_id) || windows_style
}

fn applies_ok(rule: &Rule, snap: &Snapshot) -> bool {
    let a = &rule.applies;
    if !a.units_active.iter().all(|u| snap.units.get(u).map(|x| x.is_active()).unwrap_or(false)) {
        return false;
    }
    if !a.commands.iter().all(|c| snap.commands.contains(c)) {
        return false;
    }
    if !a.desktops.is_empty() {
        let cur: Vec<String> = snap.info.desktop.split(':').map(|s| s.to_lowercase()).collect();
        if !a.desktops.iter().any(|d| cur.contains(&d.to_lowercase())) {
            return false;
        }
    }
    if !a.distros.is_empty() {
        let id = &snap.info.distro_id;
        if !a.distros.iter().any(|d| d == id || snap.info.distro_like.contains(d)) {
            return false;
        }
    }
    if !a.hardware.iter().all(|h| snap.info.hardware.contains(h)) {
        return false;
    }
    if a.non_generic_hostname && is_generic_hostname(&snap.info.hostname, &snap.info.distro_id) {
        return false;
    }
    true
}

fn unit_state_text(u: &UnitInfo) -> String {
    let file = match u.file_state.as_str() {
        "enabled" | "enabled-runtime" => "habilitado",
        "static" => "se activa bajo demanda",
        "indirect" => "se activa bajo demanda",
        "disabled" => "deshabilitado",
        "masked" | "masked-runtime" => "enmascarado",
        other if !other.is_empty() => other,
        _ => "—",
    };
    let act = if u.is_active() { "en ejecución" } else { "detenido" };
    format!("{}: {file}, {act}", u.name)
}

fn detect(rule: &Rule, snap: &Snapshot) -> Detection {
    match &rule.detect {
        Detect::Unit { units } => {
            let existing: Vec<&UnitInfo> = units.iter().filter_map(|u| snap.units.get(u)).filter(|u| u.exists).collect();
            if existing.is_empty() {
                return Detection::na();
            }
            let firing: Vec<&&UnitInfo> = existing
                .iter()
                .filter(|u| u.file_state != "masked" && (u.is_enabled() || u.is_active()))
                .collect();
            if firing.is_empty() {
                Detection {
                    applicable: true,
                    fires: false,
                    observed: existing.iter().map(|u| unit_state_text(u)).collect(),
                }
            } else {
                Detection { applicable: true, fires: true, observed: firing.iter().map(|u| unit_state_text(u)).collect() }
            }
        }
        Detect::Package { names } => {
            let found: Vec<String> = names.iter().filter(|n| snap.packages.contains(*n)).cloned().collect();
            Detection { applicable: !found.is_empty(), fires: !found.is_empty(), observed: found.iter().map(|n| format!("Paquete instalado: {n}")).collect() }
        }
        Detect::Sysctl { key, want, op } => {
            let Some(cur) = snap.sysctl.get(key) else { return Detection::na() };
            // Con IPv6 apagado, los ajustes de IPv6 no tienen sentido.
            if key.starts_with("net.ipv6.") && !key.contains("disable_ipv6") && snap.sysctl.get("net.ipv6.conf.all.disable_ipv6").map(String::as_str) == Some("1") {
                return Detection::na();
            }
            let bad = match op {
                CmpOp::Eq => cur != want,
                CmpOp::AtLeast => match (cur.parse::<i64>(), want.parse::<i64>()) {
                    (Ok(c), Ok(w)) => c < w,
                    _ => cur != want,
                },
            };
            let cmp = if *op == CmpOp::AtLeast { "≥ " } else { "" };
            Detection { applicable: true, fires: bad, observed: vec![format!("{key} = {cur}  (recomendado: {cmp}{want})")] }
        }
        Detect::Gsettings { schema, key, want } => {
            let Some(cur) = snap.gsettings.get(&format!("{schema} {key}")) else { return Detection::na() };
            Detection { applicable: true, fires: cur != want, observed: vec![format!("{schema} {key} = {cur}")] }
        }
        Detect::Kconfig { file, group, key, want, missing_is_bad } => {
            let k = crate::collect::kconfig_key(file, group, key);
            let Some(v) = snap.kconfig.get(&k) else { return Detection::na() };
            let (fires, shown) = match v {
                None => (*missing_is_bad, "no definido (valor por defecto)".to_string()),
                Some(v) => (v != want, v.clone()),
            };
            Detection { applicable: true, fires, observed: vec![format!("{file} [{group}] {key} = {shown}")] }
        }
        Detect::FileRegex { fire_when, .. } => {
            let Some(p) = snap.file_probes.get(&rule.id) else { return Detection::na() };
            if p.files_checked == 0 {
                return Detection::na();
            }
            let present = !p.matches.is_empty();
            let fires = (*fire_when == Presence::Present) == present;
            let observed = if present {
                p.matches.iter().take(6).map(|m| format!("Encontrado en {m}")).collect()
            } else {
                vec![format!("No se encontró esta configuración en {} archivo(s) revisado(s).", p.files_checked)]
            };
            Detection { applicable: true, fires, observed }
        }
        Detect::Builtin { name } => builtin(name, snap),
    }
}

/// Listeners TCP/UDP accesibles desde la red (excluye infraestructura conocida).
pub fn exposed_listeners(snap: &Snapshot) -> Vec<&Listener> {
    const INFRA_UDP: [u16; 9] = [53, 67, 68, 123, 323, 546, 547, 5353, 5355];
    let mut seen = BTreeSet::new();
    snap.listeners
        .iter()
        .filter(|l| l.exposure != Exposure::Loopback)
        .filter(|l| l.proto == "tcp" || !INFRA_UDP.contains(&l.port))
        .filter(|l| seen.insert((l.proto.clone(), l.port, l.process.clone())))
        .collect()
}

fn builtin(name: &str, snap: &Snapshot) -> Detection {
    match name {
        "dns_over_tls" => {
            if !snap.dns.resolved_active {
                return Detection::na();
            }
            let mut obs = vec![format!("Cifrado de DNS: {}", if snap.dns.dns_over_tls { "activo" } else { "desactivado" })];
            if !snap.dns.servers.is_empty() {
                obs.push(format!("Servidores DNS actuales: {}", snap.dns.servers.join(", ")));
                let capable: Vec<&String> = snap.dns.servers.iter().filter(|s| DOT_CAPABLE.contains(&s.as_str())).collect();
                if !capable.is_empty() && capable.len() == snap.dns.servers.len() {
                    obs.push("Todos tus servidores DNS admiten DNS-over-TLS: el cifrado funcionaría de inmediato.".into());
                } else if capable.is_empty() {
                    obs.push("Estos servidores quizá no admitan DNS-over-TLS; para cifrado garantizado conviene además elegir uno que sí (1.1.1.1, 9.9.9.9…).".into());
                }
            }
            Detection { applicable: true, fires: !snap.dns.dns_over_tls, observed: obs }
        }
        "dns_llmnr" => {
            if !snap.dns.resolved_active {
                return Detection::na();
            }
            let global = matches!(snap.dns.llmnr.as_str(), "yes" | "resolve");
            let fires = global || !snap.dns.llmnr_links.is_empty();
            let mut obs = Vec::new();
            if global {
                obs.push(format!("LLMNR global: {}", snap.dns.llmnr));
            }
            for l in &snap.dns.llmnr_links {
                obs.push(format!("LLMNR activo en la conexión «{l}»"));
            }
            if obs.is_empty() {
                obs.push("LLMNR desactivado.".into());
            }
            Detection { applicable: true, fires, observed: obs }
        }
        "exposed_ports" => {
            if snap.listeners.is_empty() {
                return Detection::na();
            }
            let ex = exposed_listeners(snap);
            let obs = ex
                .iter()
                .map(|l| {
                    format!(
                        "{} {}  —  {}",
                        l.proto.to_uppercase(),
                        l.port,
                        l.process.clone().unwrap_or_else(|| "proceso del sistema (se necesita ejecutar como administrador para verlo)".into())
                    )
                })
                .collect();
            Detection { applicable: true, fires: !ex.is_empty(), observed: obs }
        }
        "no_firewall" => {
            let ex = exposed_listeners(snap);
            if ex.is_empty() || snap.info.init != "systemd" {
                return Detection::na();
            }
            let active = |n: &str| snap.units.get(n).map(|u| u.is_active()).unwrap_or(false);
            let has = active("firewalld.service") || active("ufw.service") || active("nftables.service");
            let obs = if has {
                vec!["Firewall activo.".to_string()]
            } else {
                vec![
                    format!("{} puerto(s) abierto(s) a la red y ningún firewall detectado.", ex.len()),
                    "Nota: las reglas de nftables/iptables escritas a mano no se ven sin permisos de administrador.".into(),
                ]
            };
            Detection { applicable: true, fires: !has, observed: obs }
        }
        "firewall_zone_open" => {
            if snap.firewall.backend.as_deref() != Some("firewalld") || !snap.firewall.active || snap.firewall.zones.is_empty() {
                return Detection::na();
            }
            const PERMISSIVE: [&str; 7] = ["trusted", "home", "work", "internal", "dmz", "FedoraWorkstation", "FedoraServer"];
            let mut obs = Vec::new();
            let mut fires = false;
            for (zone, info) in &snap.firewall.zones {
                if info.interfaces.is_empty() {
                    continue;
                }
                let open: Vec<String> = info.services.iter().cloned().chain(info.ports.iter().cloned()).collect();
                if PERMISSIVE.contains(&zone.as_str()) {
                    fires = true;
                    obs.push(format!(
                        "{} está en la zona «{zone}»: permite {}",
                        info.interfaces.join(", "),
                        if open.is_empty() { "conexiones entrantes".to_string() } else { open.join(", ") }
                    ));
                } else {
                    obs.push(format!("{} está en la zona «{zone}» (restrictiva).", info.interfaces.join(", ")));
                }
            }
            if obs.is_empty() {
                return Detection::na();
            }
            Detection { applicable: true, fires, observed: obs }
        }
        "mac_disabled" => match snap.mac.system.as_str() {
            "none" | "" => Detection::na(),
            sys => {
                let name = if sys == "selinux" { "SELinux" } else { "AppArmor" };
                Detection {
                    applicable: true,
                    fires: !snap.mac.enforcing,
                    observed: vec![if snap.mac.enforcing { format!("{name} está activo y haciendo cumplir las políticas.") } else { format!("{name} está desactivado o en modo permisivo.") }],
                }
            }
        },
        "hostname_personal" => {
            let user = snap.info.user.to_lowercase();
            if user.len() < 3 || is_generic_hostname(&snap.info.hostname, &snap.info.distro_id) {
                return Detection::na();
            }
            let hit = snap.info.hostname.to_lowercase().contains(&user);
            Detection { applicable: true, fires: hit, observed: vec![format!("Nombre del equipo: {}", snap.info.hostname)] }
        }
        "root_unencrypted" => match snap.storage.root_encrypted {
            None => Detection::na(),
            Some(enc) => Detection {
                applicable: true,
                fires: !enc,
                observed: vec![if enc { "El sistema de archivos raíz está sobre un volumen cifrado (LUKS).".into() } else { "El disco del sistema no está cifrado.".to_string() }],
            },
        },
        "swap_unencrypted" => {
            if snap.storage.swaps.is_empty() {
                return Detection::na();
            }
            let bad: Vec<&SwapInfo> = snap.storage.swaps.iter().filter(|s| s.encrypted == Some(false)).collect();
            let obs = if bad.is_empty() {
                snap.storage.swaps.iter().map(|s| format!("{} ({}): sin riesgo", s.device, s.kind)).collect()
            } else {
                bad.iter().map(|s| format!("{} ({}): sin cifrar", s.device, s.kind)).collect()
            };
            Detection { applicable: true, fires: !bad.is_empty(), observed: obs }
        }
        "secure_boot_off" => match snap.secure_boot {
            SecureBoot::Enabled => Detection { applicable: true, fires: false, observed: vec!["Secure Boot activo.".into()] },
            SecureBoot::Disabled => Detection { applicable: true, fires: true, observed: vec!["Secure Boot está desactivado.".into()] },
            _ => Detection::na(),
        },
        "firefox_telemetry" => {
            if snap.firefox.is_empty() {
                return Detection::na();
            }
            let bad: Vec<&FirefoxProfile> = snap.firefox.iter().filter(|p| !p.bad_prefs.is_empty()).collect();
            let obs = if bad.is_empty() {
                vec!["La telemetría de Firefox ya está desactivada en todos los perfiles.".to_string()]
            } else {
                bad.iter()
                    .map(|p| {
                        let name = p.path.rsplit('/').next().unwrap_or(&p.path);
                        format!("{} — perfil «{name}»: {} ajuste(s) de telemetría sin desactivar", p.flavor, p.bad_prefs.len())
                    })
                    .collect()
            };
            Detection { applicable: true, fires: !bad.is_empty(), observed: obs }
        }
        "flatpak_broad" => {
            if snap.flatpaks.is_empty() {
                return Detection::na();
            }
            let mut obs: Vec<String> = snap
                .flatpaks
                .iter()
                .filter(|a| !a.broad.is_empty())
                .map(|a| format!("{}: {}", a.id, a.broad.join("; ")))
                .collect();
            obs.sort();
            Detection { applicable: true, fires: !obs.is_empty(), observed: if obs.is_empty() { vec!["Ninguna app tiene permisos excesivos.".into()] } else { obs } }
        }
        _ => Detection::na(),
    }
}

/// Unidades que dependen de las que vamos a desactivar y que están activas ahora.
fn blockers_for(rule: &Rule, snap: &Snapshot) -> Vec<String> {
    let Fix::DisableUnits { units } = &rule.fix else { return vec![] };
    let own: BTreeSet<&String> = units.iter().collect();
    let mut out = Vec::new();
    for u in units {
        let Some(info) = snap.units.get(u) else { continue };
        if !info.exists || !(info.is_enabled() || info.is_active()) {
            continue;
        }
        for dep in &info.required_by {
            if !own.contains(dep) && !dep.ends_with(".target") {
                out.push(format!("{dep} (necesita {u})"));
            }
        }
    }
    out.sort();
    out.dedup();
    out
}

fn base_safety(b: Breakage) -> Safety {
    match b {
        Breakage::Nothing => Safety::Safe,
        Breakage::Minor => Safety::Minor,
        Breakage::Notable => Safety::Notable,
    }
}

fn plan(rule: &Rule, snap: &Snapshot) -> (Option<Evidence>, Vec<String>, Safety) {
    let evidence = rule.evidence.and_then(|k| snap.evidence.get(&k).cloned());
    let blockers = blockers_for(rule, snap);
    let safety = if !blockers.is_empty() {
        Safety::InUse
    } else {
        match evidence.as_ref().and_then(|e| e.in_use) {
            Some(true) => Safety::InUse,
            Some(false) => Safety::NoSignsOfUse,
            None => base_safety(rule.breakage),
        }
    };
    (evidence, blockers, safety)
}

fn preselect(rule: &Rule, safety: Safety, learned_blocks: bool) -> bool {
    if !rule.fix.is_auto() || learned_blocks {
        return false;
    }
    match safety {
        Safety::Safe => true,
        Safety::NoSignsOfUse => rule.breakage <= Breakage::Minor,
        Safety::Minor => rule.level == Level::Basic,
        Safety::Notable | Safety::InUse => false,
    }
}

pub fn evaluate(rules: &[Rule], snap: &Snapshot, level: Level, learned: &Learned) -> Report {
    let mut findings = Vec::new();
    let mut hidden = 0usize;
    let mut not_applicable = Vec::new();
    let mut hidden_ids = Vec::new();
    let (mut total_w, mut todo_w) = (0u32, 0u32);

    // Etiquetas de reglas que el usuario ya revirtió (aprendizaje por tipo).
    let reverted_tags: Vec<(&Rule, i64)> = rules
        .iter()
        .filter(|r| learned.reverted_count(&r.id) > 0)
        .map(|r| (r, learned.last_reverted(&r.id).unwrap_or(0)))
        .collect();

    for rule in rules {
        if !applies_ok(rule, snap) {
            not_applicable.push(rule.id.clone());
            continue;
        }
        let det = detect(rule, snap);
        if !det.applicable {
            not_applicable.push(rule.id.clone());
            continue;
        }
        if rule.level > level {
            if det.fires {
                hidden += 1;
                hidden_ids.push(rule.id.clone());
            }
            continue;
        }
        let status = if det.fires { Status::Todo } else { Status::Ok };
        let ignored = learned.is_ignored(&rule.id);
        let (evidence, blockers, safety) = if det.fires { plan(rule, snap) } else { (None, vec![], Safety::Safe) };

        let mut learned_note = None;
        let mut blocks = false;
        if det.fires {
            if learned.reverted_count(&rule.id) > 0 {
                blocks = true;
                learned_note = Some("Aplicaste este cambio y lo revertiste antes. No se preselecciona.".to_string());
            } else if let Some((other, _)) = reverted_tags
                .iter()
                .find(|(o, _)| o.id != rule.id && o.tags.iter().any(|t| rule.tags.contains(t)))
            {
                blocks = true;
                learned_note = Some(format!(
                    "Antes revertiste «{}», que está relacionado con esto. No se preselecciona.",
                    other.title
                ));
            }
        }

        let weight = rule.severity.weight();
        if !ignored {
            total_w += weight;
            if det.fires {
                todo_w += weight;
            }
        }

        findings.push(Finding {
            rule: rule.clone(),
            status,
            observed: det.observed,
            preselect: det.fires && !ignored && preselect(rule, safety, blocks),
            evidence,
            blockers,
            safety,
            learned_note,
            ignored,
        });
    }

    // Primero lo pendiente, ordenado por severidad (más grave primero) y seguridad de aplicar.
    findings.sort_by(|a, b| {
        let key = |f: &Finding| (f.status == Status::Ok, f.ignored, std::cmp::Reverse(f.rule.severity), f.safety, f.rule.id.clone());
        key(a).cmp(&key(b))
    });

    let score = if total_w == 0 { 100 } else { (100.0 * (1.0 - todo_w as f64 / total_w as f64)).round() as u32 };
    Report { findings, score, hidden_by_level: hidden, level: Some(level), not_applicable, hidden_ids }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::collect::KCONFIG_UNSET;
    use std::collections::BTreeMap;

    fn unit(name: &str, state: &str, active: &str) -> UnitInfo {
        UnitInfo { name: name.into(), exists: true, file_state: state.into(), active: active.into(), required_by: vec![] }
    }

    /// Escenario modelado en un Fedora 44 + KDE con disco LUKS, SSH escuchando y DNS sin cifrar.
    fn fedora_kde() -> Snapshot {
        let mut s = Snapshot::default();
        s.info = SystemInfo {
            distro_id: "fedora".into(),
            distro_name: "Fedora Linux 44".into(),
            desktop: "KDE".into(),
            init: "systemd".into(),
            pkg_manager: Some("rpm".into()),
            hostname: "fedora".into(),
            user: "maria".into(),
            hardware: ["wifi", "bluetooth"].iter().map(|x| x.to_string()).collect(),
            ..Default::default()
        };
        s.commands.insert("kreadconfig6".into());
        for u in [
            unit("sshd.service", "enabled", "active"),
            unit("systemd-resolved.service", "enabled", "active"),
            unit("NetworkManager.service", "enabled", "active"),
            unit("firewalld.service", "enabled", "active"),
            unit("bluetooth.service", "enabled", "active"),
            unit("cups.service", "enabled", "active"),
            unit("cups.socket", "enabled", "active"),
            unit("cups-browsed.service", "disabled", "inactive"),
        ] {
            s.units.insert(u.name.clone(), u);
        }
        s.dns = DnsInfo {
            resolved_active: true,
            stub_mode: true,
            llmnr: "resolve".into(),
            llmnr_links: vec!["wlo1".into()],
            servers: vec!["1.1.1.1".into(), "8.8.8.8".into()],
            ..Default::default()
        };
        s.sysctl = BTreeMap::from([
            ("kernel.dmesg_restrict".to_string(), "1".to_string()),
            ("kernel.kptr_restrict".to_string(), "0".to_string()),
            ("kernel.yama.ptrace_scope".to_string(), "0".to_string()),
            ("kernel.unprivileged_bpf_disabled".to_string(), "2".to_string()),
            ("net.ipv4.tcp_timestamps".to_string(), "1".to_string()),
            ("net.ipv6.conf.default.use_tempaddr".to_string(), "0".to_string()),
        ]);
        s.storage = StorageInfo { root_encrypted: Some(true), swaps: vec![SwapInfo { device: "/dev/zram0".into(), kind: "zram".into(), encrypted: Some(true) }] };
        s.secure_boot = SecureBoot::Unsupported;
        s.kconfig.insert(crate::collect::kconfig_key("PlasmaUserFeedback", "Global", "FeedbackLevel"), None);
        let _ = KCONFIG_UNSET;
        s.file_probes.insert("telemetry.fedora_countme".into(), FileProbe { files_checked: 3, matches: vec!["/etc/yum.repos.d/fedora.repo:6".into()] });
        s.file_probes.insert("network.mac_wifi".into(), FileProbe { files_checked: 4, matches: vec!["/usr/lib/NetworkManager/conf.d/22-wifi-mac-addr.conf:8".into()] });
        s.file_probes.insert("network.dhcp_hostname".into(), FileProbe { files_checked: 4, matches: vec![] });
        s.listeners = vec![
            Listener { proto: "tcp".into(), addr: "0.0.0.0".into(), port: 22, process: None, pid: None, exposure: Exposure::AllInterfaces },
            Listener { proto: "tcp".into(), addr: "::".into(), port: 22, process: None, pid: None, exposure: Exposure::AllInterfaces },
            Listener { proto: "tcp".into(), addr: "*".into(), port: 9800, process: Some("fluidsynth".into()), pid: Some(1), exposure: Exposure::AllInterfaces },
            Listener { proto: "tcp".into(), addr: "127.0.0.1".into(), port: 631, process: None, pid: None, exposure: Exposure::Loopback },
            Listener { proto: "udp".into(), addr: "0.0.0.0".into(), port: 5353, process: None, pid: None, exposure: Exposure::AllInterfaces },
        ];
        s.evidence.insert(EvidenceKind::Bluetooth, Evidence { in_use: Some(false), detail: "No hay dispositivos Bluetooth emparejados.".into() });
        s.evidence.insert(EvidenceKind::Printers, Evidence { in_use: Some(false), detail: "No hay impresoras configuradas.".into() });
        s.evidence.insert(EvidenceKind::Ssh, Evidence { in_use: Some(false), detail: "Nadie conectado.".into() });
        s
    }

    fn rules() -> Vec<Rule> {
        crate::rules::load().unwrap()
    }

    fn get<'a>(r: &'a Report, id: &str) -> Option<&'a Finding> {
        r.findings.iter().find(|f| f.rule.id == id)
    }

    #[test]
    fn detects_expected_findings_on_fedora_scenario() {
        let rep = evaluate(&rules(), &fedora_kde(), Level::Paranoid, &Learned::default());
        // Cosas que deben aparecer pendientes:
        for id in [
            "telemetry.fedora_countme", "services.sshd", "services.cups", "services.bluetooth",
            "network.dns_over_tls", "network.llmnr", "network.ipv6_privacy", "network.exposed_ports",
            "hardening.ptrace", "hardening.kptr_restrict", "hardening.tcp_timestamps",
        ] {
            let f = get(&rep, id).unwrap_or_else(|| panic!("falta {id}"));
            assert_eq!(f.status, Status::Todo, "{id}");
        }
        // Ya está bien / no aplica:
        assert_eq!(get(&rep, "storage.root_encrypted").unwrap().status, Status::Ok);
        assert_eq!(get(&rep, "network.mac_wifi").unwrap().status, Status::Ok); // Fedora ya lo trae
        assert_eq!(get(&rep, "hardening.dmesg_restrict").unwrap().status, Status::Ok);
        assert_eq!(get(&rep, "hardening.unprivileged_bpf").unwrap().status, Status::Ok); // 2 ≥ 1
        assert_eq!(get(&rep, "telemetry.kde_feedback").unwrap().status, Status::Ok);
        assert_eq!(get(&rep, "services.cups_browsed").unwrap().status, Status::Ok); // ya deshabilitado
        assert!(get(&rep, "storage.secure_boot").is_none()); // no soportado ⇒ no aplica
        assert!(get(&rep, "telemetry.abrt").is_none()); // no instalado
        assert!(get(&rep, "network.dhcp_hostname").is_none()); // hostname genérico
        assert!(get(&rep, "network.no_firewall").map(|f| f.status == Status::Ok).unwrap_or(true));
        assert!(get(&rep, "desktop.gnome_recent_files").is_none()); // es KDE
    }

    #[test]
    fn level_filtering_hides_and_counts() {
        let basic = evaluate(&rules(), &fedora_kde(), Level::Basic, &Learned::default());
        assert!(get(&basic, "hardening.tcp_timestamps").is_none());
        assert!(basic.hidden_by_level > 0);
        let para = evaluate(&rules(), &fedora_kde(), Level::Paranoid, &Learned::default());
        assert_eq!(para.hidden_by_level, 0);
        assert!(para.findings.len() > basic.findings.len());
    }

    #[test]
    fn evidence_decides_safety() {
        let mut s = fedora_kde();
        // Sin señales de uso de Bluetooth → «NoSignsOfUse», pero la regla es «Notable»: no se preselecciona.
        let rep = evaluate(&rules(), &s, Level::Strict, &Learned::default());
        let bt = get(&rep, "services.bluetooth").unwrap();
        assert_eq!(bt.safety, Safety::NoSignsOfUse);
        assert!(!bt.preselect);

        // Con un dispositivo emparejado → InUse.
        s.evidence.insert(EvidenceKind::Bluetooth, Evidence { in_use: Some(true), detail: "Sony WH-1000XM4".into() });
        let rep = evaluate(&rules(), &s, Level::Strict, &Learned::default());
        assert_eq!(get(&rep, "services.bluetooth").unwrap().safety, Safety::InUse);
        assert!(!get(&rep, "services.bluetooth").unwrap().preselect);

        // SSH con sesión activa → InUse, y nunca preseleccionado.
        s.evidence.insert(EvidenceKind::Ssh, Evidence { in_use: Some(true), detail: "1 sesión".into() });
        let rep = evaluate(&rules(), &s, Level::Basic, &Learned::default());
        let ssh = get(&rep, "services.sshd").unwrap();
        assert_eq!(ssh.safety, Safety::InUse);
        assert!(!ssh.preselect);
    }

    #[test]
    fn dependents_block_disabling() {
        let mut s = fedora_kde();
        s.units.get_mut("cups.service").unwrap().required_by = vec!["cups.socket".into(), "foo-print.service".into(), "multi-user.target".into()];
        let rep = evaluate(&rules(), &s, Level::Strict, &Learned::default());
        let f = get(&rep, "services.cups").unwrap();
        // cups.socket es de la misma regla; el .target se ignora; queda solo foo-print.service.
        assert_eq!(f.blockers.len(), 1);
        assert!(f.blockers[0].starts_with("foo-print.service"));
        assert_eq!(f.safety, Safety::InUse);
    }

    #[test]
    fn learning_blocks_preselection() {
        let s = fedora_kde();
        let rep = evaluate(&rules(), &s, Level::Basic, &Learned::default());
        assert!(get(&rep, "network.llmnr").unwrap().preselect);
        let mut l = Learned::default();
        l.record_reverted("network.llmnr", 100);
        let rep = evaluate(&rules(), &s, Level::Basic, &l);
        let f = get(&rep, "network.llmnr").unwrap();
        assert!(!f.preselect);
        assert!(f.learned_note.is_some());
        // Lo relacionado por etiqueta (dns) también se frena: dns_over_tls comparte «dns».
        let rep = evaluate(&rules(), &s, Level::Strict, &l);
        assert!(get(&rep, "network.dns_over_tls").unwrap().learned_note.is_some());
        assert!(!get(&rep, "network.dns_over_tls").unwrap().preselect);
    }

    #[test]
    fn ignored_rules_leave_score_and_todo() {
        let s = fedora_kde();
        let base = evaluate(&rules(), &s, Level::Basic, &Learned::default());
        let mut l = Learned::default();
        l.set_ignored("services.sshd", true);
        let rep = evaluate(&rules(), &s, Level::Basic, &l);
        assert!(rep.score >= base.score);
        assert!(rep.todo().all(|f| f.rule.id != "services.sshd"));
        assert!(get(&rep, "services.sshd").unwrap().ignored);
    }

    #[test]
    fn score_is_100_when_everything_ok_and_drops_otherwise() {
        let rep = evaluate(&rules(), &Snapshot::default(), Level::Paranoid, &Learned::default());
        assert_eq!(rep.score, 100);
        let rep = evaluate(&rules(), &fedora_kde(), Level::Paranoid, &Learned::default());
        assert!(rep.score < 100 && rep.score > 0, "{}", rep.score);
    }

    #[test]
    fn preselect_only_auto_fixes() {
        let rep = evaluate(&rules(), &fedora_kde(), Level::Paranoid, &Learned::default());
        for f in &rep.findings {
            if f.preselect {
                assert!(f.rule.fix.is_auto(), "{} preseleccionado pero es manual", f.rule.id);
                assert!(f.safety <= Safety::Minor, "{}", f.rule.id);
            }
        }
    }

    #[test]
    fn generic_hostnames() {
        assert!(is_generic_hostname("fedora", "fedora"));
        assert!(is_generic_hostname("localhost.localdomain", ""));
        assert!(!is_generic_hostname("luis-laptop", "fedora"));
    }

    #[test]
    fn personal_hostname_and_dhcp_rule() {
        let mut s = fedora_kde();
        s.info.hostname = "maria-laptop".into();
        let rep = evaluate(&rules(), &s, Level::Strict, &Learned::default());
        assert_eq!(get(&rep, "privacy.hostname_personal").unwrap().status, Status::Todo);
        assert_eq!(get(&rep, "network.dhcp_hostname").unwrap().status, Status::Todo);
    }

    #[test]
    fn firewall_rule() {
        let mut s = fedora_kde();
        s.units.get_mut("firewalld.service").unwrap().active = "inactive".into();
        let rep = evaluate(&rules(), &s, Level::Basic, &Learned::default());
        assert_eq!(get(&rep, "network.no_firewall").unwrap().status, Status::Todo);
    }
}
