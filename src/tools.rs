//! Herramientas: acciones con opciones que el usuario elige (DNS privado, identidad de red, IPv6,
//! navegadores, firewall). Cada una se traduce en un `Plan` = lista de `Fix` tipados.
//!
//! El helper con permisos de administrador solo recibe una *petición* (`ToolRequest`) y construye
//! el plan él mismo; nunca recibe comandos ni rutas del usuario.

use crate::model::*;
use crate::sys::Runner;
use serde::{Deserialize, Serialize};

// ───────────────────────── Proveedores DNS ─────────────────────────

pub struct DnsProvider {
    pub id: &'static str,
    pub name: &'static str,
    pub ips: &'static [&'static str],
    /// Nombre TLS para validar el certificado (DNS-over-TLS).
    pub tls_name: &'static str,
    pub tagline: &'static str,
    pub details: &'static [&'static str],
}

/// Solo IPv4: son las únicas direcciones cuyo certificado pude verificar desde este equipo.
pub const DNS_PROVIDERS: [DnsProvider; 3] = [
    DnsProvider {
        id: "quad9",
        name: "Quad9",
        ips: &["9.9.9.9", "149.112.112.112"],
        tls_name: "dns.quad9.net",
        tagline: "Seguridad: bloquea sitios de malware y phishing",
        details: &[
            "Organización sin ánimo de lucro con sede en Suiza.",
            "Según su política publicada, no registra direcciones IP de quien consulta.",
            "Bloquea dominios maliciosos conocidos.",
        ],
    },
    DnsProvider {
        id: "mullvad",
        name: "Mullvad DNS",
        ips: &["194.242.2.2"],
        tls_name: "dns.mullvad.net",
        tagline: "Privacidad: sin filtrado y sin registro de consultas",
        details: &[
            "Operado por Mullvad VPN AB (Suecia).",
            "Según su política publicada, no registra las consultas.",
            "No filtra ni bloquea nada: resuelve tal cual.",
        ],
    },
    DnsProvider {
        id: "mullvad_adblock",
        name: "Mullvad DNS (bloquea anuncios y rastreadores)",
        ips: &["194.242.2.3"],
        tls_name: "adblock.dns.mullvad.net",
        tagline: "Privacidad + bloqueo de anuncios y rastreadores",
        details: &[
            "Mismo operador y política que Mullvad DNS.",
            "Bloquea dominios de publicidad y de rastreo para todo tu equipo.",
            "Si un sitio legítimo falla, puede ser por el bloqueo: cambia a la versión sin filtrado.",
        ],
    },
];

pub fn provider(id: &str) -> Option<&'static DnsProvider> {
    DNS_PROVIDERS.iter().find(|p| p.id == id)
}

/// Proveedor cuyo conjunto de IPs coincide exactamente con los servidores DNS en uso.
pub fn provider_in_use(servers: &[String]) -> Option<&'static DnsProvider> {
    if servers.is_empty() {
        return None;
    }
    DNS_PROVIDERS.iter().find(|p| servers.iter().all(|s| p.ips.contains(&s.as_str())))
}

// ───────────────────────── Peticiones y planes ─────────────────────────

/// Qué nombre de equipo se anuncia en las redes: ninguno (no se toca), uno tipo Windows o uno de celular.
#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum HostnameStyle {
    #[default]
    Keep,
    Windows,
    Phone,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
#[serde(tag = "tool", rename_all = "snake_case")]
pub enum ToolRequest {
    Dns { provider: String, strict: bool },
    Identity { wifi_mac: bool, ethernet_mac: bool, dhcp_windows: bool, tcp_windows: bool, hostname: HostnameStyle },
    Ipv6Off {},
    Browsers { level: String, ddg: bool, ublock: bool },
    Firewall { level: String, allow: Vec<String> },
    /// Recorta los permisos amplios de una app Flatpak (carpeta personal y/o todos los dispositivos).
    Flatpak { app: String, home: bool, devices: bool },
    /// Bloquea el controlador de las cámaras web USB (surte efecto al reiniciar).
    Camera {},
    /// USBGuard: `setup` (instalar + política + encender), `on` o `off`.
    Usbguard { mode: String },
    /// Redes guardadas: las de confianza (casa) van a la zona `home`; las demás, a la restrictiva `public`.
    TrustedNetworks { trusted: Vec<String>, others: Vec<String> },
}

impl ToolRequest {
    pub fn key(&self) -> &'static str {
        match self {
            ToolRequest::Dns { .. } => KEY_DNS,
            ToolRequest::Identity { .. } => KEY_IDENTITY,
            ToolRequest::Ipv6Off {} => KEY_IPV6,
            ToolRequest::Browsers { .. } => KEY_BROWSERS,
            ToolRequest::Firewall { .. } => KEY_FIREWALL,
            ToolRequest::Flatpak { .. } => KEY_FLATPAK,
            ToolRequest::Camera {} => KEY_CAMERA,
            ToolRequest::Usbguard { .. } => KEY_USBGUARD,
            ToolRequest::TrustedNetworks { .. } => KEY_TRUSTED,
        }
    }
}

pub const KEY_DNS: &str = "tool.dns";
pub const KEY_IDENTITY: &str = "tool.identity";
pub const KEY_IPV6: &str = "tool.ipv6";
pub const KEY_BROWSERS: &str = "tool.browsers";
pub const KEY_FIREWALL: &str = "tool.firewall";
pub const KEY_FLATPAK: &str = "tool.flatpak";
pub const KEY_CAMERA: &str = "tool.camera";
pub const KEY_TRUSTED: &str = "tool.trusted";
pub const KEY_USBGUARD: &str = "tool.usbguard";
pub const TOOL_KEYS: [&str; 9] = [KEY_DNS, KEY_IDENTITY, KEY_IPV6, KEY_BROWSERS, KEY_FIREWALL, KEY_FLATPAK, KEY_CAMERA, KEY_TRUSTED, KEY_USBGUARD];

pub struct Plan {
    pub key: &'static str,
    pub title: String,
    pub fixes: Vec<Fix>,
}

pub struct PlanEnv {
    pub nm_active: bool,
    pub resolved_active: bool,
}

impl PlanEnv {
    pub fn detect(r: &dyn Runner) -> PlanEnv {
        let active = |u: &str| r.run("systemctl", &["is-active", u]).stdout.trim() == "active";
        PlanEnv { nm_active: active("NetworkManager.service"), resolved_active: active("systemd-resolved.service") }
    }
}

/// Nombre de equipo con el formato que Windows asigna por defecto: DESKTOP-XXXXXXX.
pub fn windows_hostname() -> String {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    let s: String = random_bytes(7).iter().map(|b| ALPHABET[*b as usize % ALPHABET.len()] as char).collect();
    format!("DESKTOP-{s}")
}

/// Nombre de equipo con el formato que Android usa por DHCP: android-<16 hex>.
pub fn phone_hostname() -> String {
    let s: String = random_bytes(8).iter().map(|b| format!("{b:02x}")).collect();
    format!("android-{s}")
}

fn random_bytes(n: usize) -> Vec<u8> {
    let mut buf = vec![0u8; n];
    let ok = std::fs::File::open("/dev/urandom").and_then(|mut f| std::io::Read::read_exact(&mut f, &mut buf)).is_ok();
    if !ok {
        let ns = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_nanos()).unwrap_or(1234567);
        for (i, b) in buf.iter_mut().enumerate() {
            *b = (ns >> ((i * 7) % 100)) as u8;
        }
    }
    buf
}

/// Ruta del script de NetworkManager que renueva el nombre en cada conexión.
pub const ROTATE_SCRIPT: &str = "/etc/NetworkManager/dispatcher.d/90-silence-hostname";

/// Script que, al desconectarte de una red, deja un nombre nuevo preparado para la siguiente
/// conexión de ese perfil (igual que la MAC aleatoria). Solo cambia lo que se envía a la red por
/// DHCP; el nombre del sistema no se toca, así que no afecta a las aplicaciones abiertas.
pub fn rotate_script(style: HostnameStyle) -> String {
    let name_cmd = match style {
        HostnameStyle::Phone => r#"NAME="android-$(od -An -N8 -tx1 /dev/urandom | tr -d ' \n')""#,
        _ => r#"NAME="DESKTOP-$(LC_ALL=C tr -dc 'A-Z0-9' </dev/urandom | head -c 7)""#,
    };
    format!(
        "#!/bin/sh\n# Creado por Silence. Nombre de equipo nuevo para la próxima conexión (como la MAC aleatoria).\n\
[ \"$2\" = \"down\" ] || exit 0\n[ -n \"$CONNECTION_UUID\" ] || exit 0\n[ -d \"/sys/class/net/$1/device\" ] || exit 0\n{name_cmd}\n\
nmcli connection modify \"$CONNECTION_UUID\" ipv4.dhcp-hostname \"$NAME\" ipv6.dhcp-hostname \"$NAME\" >/dev/null 2>&1\nexit 0\n"
    )
}

fn types_wifi() -> Vec<String> {
    vec!["802-11-wireless".into()]
}
fn types_eth() -> Vec<String> {
    vec!["802-3-ethernet".into()]
}
fn types_all() -> Vec<String> {
    vec!["802-11-wireless".into(), "802-3-ethernet".into()]
}
fn nmp(name: &str, value: &str) -> NmProp {
    NmProp { name: name.into(), value: value.into() }
}
fn file(path: &str, content: String) -> FileSpec {
    FileSpec { path: path.into(), content }
}

pub fn plan(req: &ToolRequest, env: &PlanEnv) -> Result<Plan, String> {
    match req {
        ToolRequest::Dns { provider: pid, strict } => {
            let p = provider(pid).ok_or_else(|| format!("Proveedor DNS desconocido: {pid}"))?;
            if !env.nm_active || !env.resolved_active {
                return Err("El cambiador de DNS necesita NetworkManager y systemd-resolved activos (lo normal en Fedora, Ubuntu y Mint). Este equipo no los usa todavía.".into());
            }
            let with_name: Vec<String> = p.ips.iter().map(|ip| format!("{ip}#{}", p.tls_name)).collect();
            let tls_nm = if *strict { "2" } else { "1" };
            let tls_resolved = if *strict { "yes" } else { "opportunistic" };
            Ok(Plan {
                key: KEY_DNS,
                title: format!("DNS privado: {}", p.name),
                fixes: vec![
                    Fix::WriteFiles {
                        files: vec![
                            file(
                                "/etc/NetworkManager/conf.d/92-silence-dns.conf",
                                format!("# Creado por Silence. Cifrado DNS por defecto en redes nuevas.\n[connection.92-silence-dns]\nconnection.dns-over-tls={tls_nm}\n"),
                            ),
                            file(
                                "/etc/systemd/resolved.conf.d/92-silence-dns.conf",
                                // FallbackDNS: por defecto systemd usa Google/Cloudflare si falla todo; aquí lo evitamos.
                                format!("# Creado por Silence.\n[Resolve]\nDNSOverTLS={tls_resolved}\nFallbackDNS={}\n", with_name.join(" ")),
                            ),
                        ],
                        after: vec![
                            UnitCmd { verb: UnitVerb::Restart, unit: "systemd-resolved.service".into() },
                            UnitCmd { verb: UnitVerb::Reload, unit: "NetworkManager.service".into() },
                        ],
                    },
                    Fix::NmProfiles {
                        types: types_all(),
                        props: vec![nmp("ipv4.dns", &with_name.join(",")), nmp("ipv4.ignore-auto-dns", "yes"), nmp("ipv6.ignore-auto-dns", "yes")],
                    },
                ],
            })
        }
        ToolRequest::Identity { wifi_mac, ethernet_mac, dhcp_windows, tcp_windows, hostname } => {
            if !(*wifi_mac || *ethernet_mac || *dhcp_windows || *tcp_windows || *hostname != HostnameStyle::Keep) {
                return Err("Elige al menos una opción.".into());
            }
            let needs_nm = *wifi_mac || *ethernet_mac || *dhcp_windows;
            if needs_nm && !env.nm_active {
                return Err("Las opciones de MAC y DHCP necesitan NetworkManager activo.".into());
            }
            let mut fixes = Vec::new();
            if needs_nm {
                let mut conf = String::from("# Creado por Silence. Identidad de red por defecto (también para redes nuevas).\n");
                if *wifi_mac {
                    conf.push_str("\n[connection.91-silence-wifi-mac]\nmatch-device=type:wifi\nwifi.cloned-mac-address=random\n");
                }
                if *ethernet_mac {
                    conf.push_str("\n[connection.91-silence-eth-mac]\nmatch-device=type:ethernet\nethernet.cloned-mac-address=random\n");
                }
                if *dhcp_windows {
                    // Windows: client-id = tipo+MAC, clase de proveedor «MSFT 5.0», DUID-LLT.
                    conf.push_str("\n[connection.91-silence-dhcp]\nipv4.dhcp-client-id=mac\nipv4.dhcp-vendor-class-identifier=MSFT 5.0\nipv6.dhcp-duid=llt\n");
                    if *hostname != HostnameStyle::Keep {
                        conf.push_str("ipv4.dhcp-send-hostname=true\nipv6.dhcp-send-hostname=true\n");
                    }
                }
                fixes.push(Fix::WriteFiles {
                    files: vec![file("/etc/NetworkManager/conf.d/91-silence-identity.conf", conf)],
                    after: vec![UnitCmd { verb: UnitVerb::Reload, unit: "NetworkManager.service".into() }],
                });
                // Las redes ya guardadas pueden tener un valor explícito que ignora el por defecto.
                if *wifi_mac {
                    fixes.push(Fix::NmProfiles { types: types_wifi(), props: vec![nmp("802-11-wireless.cloned-mac-address", "random")] });
                }
                if *ethernet_mac {
                    fixes.push(Fix::NmProfiles { types: types_eth(), props: vec![nmp("802-3-ethernet.cloned-mac-address", "random")] });
                }
            }
            if *tcp_windows {
                // Windows: TTL/hop limit 128, sin marcas de tiempo TCP, sin ECN.
                let s = |k: &str, v: &str| SysctlSetting { key: k.into(), value: v.into() };
                fixes.push(Fix::Sysctl {
                    settings: vec![
                        s("net.ipv4.ip_default_ttl", "128"),
                        s("net.ipv4.tcp_timestamps", "0"),
                        s("net.ipv4.tcp_ecn", "0"),
                        s("net.ipv6.conf.all.hop_limit", "128"),
                        s("net.ipv6.conf.default.hop_limit", "128"),
                    ],
                });
            }
            if *hostname != HostnameStyle::Keep {
                let name = if *hostname == HostnameStyle::Phone { phone_hostname() } else { windows_hostname() };
                if env.nm_active {
                    // Un nombre distinto en cada conexión, igual que la MAC: se guarda en los perfiles
                    // (para la primera vez) y un script lo renueva al desconectarte.
                    fixes.push(Fix::NmProfiles {
                        types: types_all(),
                        props: vec![nmp("ipv4.dhcp-hostname", &name), nmp("ipv6.dhcp-hostname", &name)],
                    });
                    fixes.push(Fix::WriteFiles { files: vec![file(ROTATE_SCRIPT, rotate_script(*hostname))], after: vec![] });
                }
                fixes.push(Fix::SetHostname { name });
            }
            Ok(Plan { key: KEY_IDENTITY, title: "Identidad de red (MAC y huella tipo Windows)".into(), fixes })
        }
        ToolRequest::Ipv6Off {} => {
            let s = |k: &str, v: &str| SysctlSetting { key: k.into(), value: v.into() };
            let mut fixes = vec![Fix::Sysctl {
                // Orden importante: «all» apaga todo, luego se devuelve el loopback (::1) para no
                // romper programas que escuchan en localhost.
                settings: vec![
                    s("net.ipv6.conf.all.disable_ipv6", "1"),
                    s("net.ipv6.conf.default.disable_ipv6", "1"),
                    s("net.ipv6.conf.lo.disable_ipv6", "0"),
                ],
            }];
            if env.nm_active {
                // NetworkManager puede volver a encender IPv6 por interfaz al conectar.
                fixes.push(Fix::NmProfiles { types: types_all(), props: vec![nmp("ipv6.method", "disabled")] });
            }
            Ok(Plan { key: KEY_IPV6, title: "Apagar IPv6".into(), fixes })
        }
        ToolRequest::Browsers { level, ddg, ublock } => {
            if !crate::firefox::level_ok(level) {
                return Err(format!("Nivel desconocido: {level}"));
            }
            Ok(Plan {
                key: KEY_BROWSERS,
                title: {
                    let (base, light) = crate::firefox::split_level(level);
                    format!(
                        "Privacidad de navegadores ({}{})",
                        if base == "maximum" { "Máximo" } else { "Equilibrado" },
                        if light { ", ligero y rápido" } else { "" }
                    )
                },
                fixes: vec![
                    Fix::BrowserPolicies { level: level.clone(), ddg: *ddg, ublock: *ublock },
                    Fix::FirefoxPrivacyPrefs { level: Some(level.clone()) },
                ],
            })
        }
        ToolRequest::Flatpak { app, home, devices } => {
            let mut args = Vec::new();
            if *home {
                args.push("--nofilesystem=home".to_string());
                args.push("--nofilesystem=host".to_string());
            }
            if *devices {
                args.push("--nodevice=all".to_string());
            }
            if args.is_empty() {
                return Err("Elige qué permiso quitar.".into());
            }
            Ok(Plan {
                key: KEY_FLATPAK,
                title: format!("Permisos de {app}"),
                fixes: vec![Fix::FlatpakOverride { app: app.clone(), args }],
            })
        }
        ToolRequest::Usbguard { mode } => {
            let units = vec!["usbguard.service".to_string()];
            let (title, fixes) = match mode.as_str() {
                "setup" => (
                    "Instalar y activar USBGuard",
                    vec![
                        Fix::InstallPackages { names: vec!["usbguard".into()] },
                        Fix::UsbguardPolicy {},
                        Fix::EnableUnits { units },
                    ],
                ),
                "on" => ("Encender USBGuard", vec![Fix::EnableUnits { units }]),
                "off" => ("Apagar USBGuard", vec![Fix::DisableUnits { units }]),
                other => return Err(format!("Acción de USBGuard desconocida: {other}")),
            };
            Ok(Plan { key: KEY_USBGUARD, title: title.into(), fixes })
        }
        ToolRequest::Camera {} => Ok(Plan {
            key: KEY_CAMERA,
            title: "Bloquear la cámara web".into(),
            fixes: vec![Fix::WriteFiles {
                files: vec![file(
                    "/etc/modprobe.d/90-silence-camera.conf",
                    "# Creado por Silence. Bloquea el controlador de las cámaras web USB (uvcvideo).\nblacklist uvcvideo\ninstall uvcvideo /bin/false\n".into(),
                )],
                after: vec![],
            }],
        }),
        ToolRequest::TrustedNetworks { trusted, others } => {
            if !env.nm_active {
                return Err("Las redes de confianza necesitan NetworkManager activo.".into());
            }
            let mut fixes = Vec::new();
            if !trusted.is_empty() {
                fixes.push(Fix::NmProfilesNamed { names: trusted.clone(), props: vec![nmp("connection.zone", "home")] });
            }
            if !others.is_empty() {
                fixes.push(Fix::NmProfilesNamed { names: others.clone(), props: vec![nmp("connection.zone", "public")] });
            }
            if fixes.is_empty() {
                return Err("No hay redes guardadas que configurar.".into());
            }
            Ok(Plan { key: KEY_TRUSTED, title: "Redes de confianza".into(), fixes })
        }
        ToolRequest::Firewall { level, allow } => {
            if level != "standard" && level != "strict" {
                return Err(format!("Nivel de firewall desconocido: {level}"));
            }
            Ok(Plan {
                key: KEY_FIREWALL,
                title: format!("Firewall ({})", if level == "strict" { "estricto" } else { "estándar" }),
                fixes: vec![Fix::Firewall { level: level.clone(), allow: allow.clone() }],
            })
        }
    }
}

// ───────────────────────── Estado para la interfaz ─────────────────────────

pub fn ipv6_off(snap: &Snapshot) -> bool {
    snap.sysctl.get("net.ipv6.conf.all.disable_ipv6").map(String::as_str) == Some("1")
}

pub fn hostname_is_windows_style(host: &str) -> bool {
    regex::Regex::new(r"^DESKTOP-[A-Z0-9]{7}$").unwrap().is_match(host)
}

/// ¿El nombre actual ya es uno de los disfraces de Silence (Windows o celular)?
pub fn hostname_is_phone_style(host: &str) -> bool {
    regex::Regex::new(r"^android-[0-9a-f]{16}$").unwrap().is_match(host)
}

pub fn hostname_is_disguised(host: &str) -> bool {
    hostname_is_windows_style(host) || hostname_is_phone_style(host)
}

pub fn tcp_is_windows_style(snap: &Snapshot) -> bool {
    snap.sysctl.get("net.ipv4.ip_default_ttl").map(String::as_str) == Some("128")
        && snap.sysctl.get("net.ipv4.tcp_timestamps").map(String::as_str) == Some("0")
}

/// Servicios que conviene mantener accesibles, según lo que escucha ahora (para preseleccionar).
pub fn suggested_firewall_allow(snap: &Snapshot) -> Vec<String> {
    let mut v = Vec::new();
    let listening = |name: &str, port: u16| snap.listeners.iter().any(|l| l.process.as_deref().map(|p| p.contains(name)).unwrap_or(false) || l.port == port);
    if snap.listeners.iter().any(|l| l.process.as_deref().map(|p| p.starts_with("kdeconnect")).unwrap_or(false) || (1714..=1764).contains(&l.port)) {
        v.push("kdeconnect".to_string());
    }
    if listening("localsend", 53317) {
        v.push("localsend".to_string());
    }
    if snap.evidence.get(&EvidenceKind::Ssh).and_then(|e| e.in_use) == Some(true) {
        v.push("ssh".to_string());
    }
    v
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::apply::Applier;
    use crate::sys::mock::MockRunner;

    fn env() -> PlanEnv {
        PlanEnv { nm_active: true, resolved_active: true }
    }

    #[test]
    fn dns_provider_details_are_complete() {
        for p in &DNS_PROVIDERS {
            assert!(!p.ips.is_empty() && p.tls_name.contains('.') && !p.details.is_empty());
            assert!(p.ips.iter().all(|ip| ip.parse::<std::net::Ipv4Addr>().is_ok()), "{}", p.id);
        }
        // Lo que pidió el usuario: Quad9 + una alternativa que no sea Google ni Cloudflare.
        assert!(provider("quad9").unwrap().ips.contains(&"9.9.9.9"));
        for p in &DNS_PROVIDERS {
            assert!(!p.ips.iter().any(|ip| ["8.8.8.8", "8.8.4.4", "1.1.1.1", "1.0.0.1"].contains(ip)));
        }
    }

    #[test]
    fn dns_plan_pins_tls_name_and_overrides_fallback() {
        let p = plan(&ToolRequest::Dns { provider: "quad9".into(), strict: false }, &env()).unwrap();
        let Fix::WriteFiles { files, .. } = &p.fixes[0] else { panic!() };
        let resolved = files.iter().find(|f| f.path.contains("resolved.conf.d")).unwrap();
        assert!(resolved.content.contains("FallbackDNS=9.9.9.9#dns.quad9.net 149.112.112.112#dns.quad9.net"));
        assert!(resolved.content.contains("DNSOverTLS=opportunistic"));
        let Fix::NmProfiles { props, .. } = &p.fixes[1] else { panic!() };
        assert!(props.iter().any(|x| x.name == "ipv4.dns" && x.value == "9.9.9.9#dns.quad9.net,149.112.112.112#dns.quad9.net"));
        assert!(props.iter().any(|x| x.name == "ipv4.ignore-auto-dns" && x.value == "yes"), "sin esto el DNS del ISP seguiría en paralelo");
        let strict = plan(&ToolRequest::Dns { provider: "mullvad".into(), strict: true }, &env()).unwrap();
        let Fix::WriteFiles { files, .. } = &strict.fixes[0] else { panic!() };
        assert!(files.iter().any(|f| f.content.contains("DNSOverTLS=yes")));
        assert!(files.iter().any(|f| f.content.contains("connection.dns-over-tls=2")));
    }

    #[test]
    fn dns_plan_refuses_unsupported_systems_and_unknown_providers() {
        let e = plan(&ToolRequest::Dns { provider: "quad9".into(), strict: false }, &PlanEnv { nm_active: false, resolved_active: true }).err().unwrap();
        assert!(e.contains("NetworkManager"));
        assert!(plan(&ToolRequest::Dns { provider: "google".into(), strict: false }, &env()).is_err());
    }

    #[test]
    fn identity_plan_all_options() {
        let p = plan(&ToolRequest::Identity { wifi_mac: true, ethernet_mac: false, dhcp_windows: true, tcp_windows: true, hostname: HostnameStyle::Windows }, &env()).unwrap();
        let Fix::WriteFiles { files, .. } = &p.fixes[0] else { panic!() };
        let c = &files[0].content;
        assert!(c.contains("wifi.cloned-mac-address=random"));
        assert!(!c.contains("ethernet.cloned-mac-address"));
        assert!(c.contains("ipv4.dhcp-vendor-class-identifier=MSFT 5.0"));
        assert!(c.contains("ipv4.dhcp-client-id=mac"));
        assert!(c.contains("ipv4.dhcp-send-hostname=true"));
        let sysctl = p.fixes.iter().find_map(|f| if let Fix::Sysctl { settings } = f { Some(settings) } else { None }).unwrap();
        assert!(sysctl.iter().any(|s| s.key == "net.ipv4.ip_default_ttl" && s.value == "128"));
        assert!(sysctl.iter().any(|s| s.key == "net.ipv4.tcp_timestamps" && s.value == "0"));
        let host = p.fixes.iter().find_map(|f| if let Fix::SetHostname { name } = f { Some(name.clone()) } else { None }).unwrap();
        assert!(hostname_is_windows_style(&host), "{host}");
        assert!(plan(&ToolRequest::Identity { wifi_mac: false, ethernet_mac: false, dhcp_windows: false, tcp_windows: false, hostname: HostnameStyle::Keep }, &env()).is_err());
    }

    #[test]
    fn identity_plan_phone_hostname_rotates_with_connections() {
        let req = ToolRequest::Identity { wifi_mac: false, ethernet_mac: false, dhcp_windows: true, tcp_windows: false, hostname: HostnameStyle::Phone };
        let p = plan(&req, &env()).unwrap();
        let host = p.fixes.iter().find_map(|f| if let Fix::SetHostname { name } = f { Some(name.clone()) } else { None }).unwrap();
        assert!(hostname_is_phone_style(&host) && !hostname_is_windows_style(&host), "{host}");
        assert!(hostname_is_disguised(&host));
        // Perfiles guardados con el nombre inicial + script que lo renueva al desconectar.
        let props = p.fixes.iter().find_map(|f| match f { Fix::NmProfiles { props, .. } if props.iter().any(|x| x.name == "ipv4.dhcp-hostname") => Some(props), _ => None }).unwrap();
        assert!(props.iter().all(|x| x.value == host));
        let script = p.fixes.iter().find_map(|f| match f { Fix::WriteFiles { files, .. } if files[0].path == ROTATE_SCRIPT => Some(files[0].content.clone()), _ => None }).unwrap();
        assert!(script.starts_with("#!/bin/sh
") && script.contains("\"down\"") && script.contains("ipv4.dhcp-hostname") && script.contains("android-"));
        assert!(rotate_script(HostnameStyle::Windows).contains("DESKTOP-"));
        // Sin NetworkManager solo se cambia el nombre del sistema.
        let sin_nm = plan(&req, &PlanEnv { nm_active: false, resolved_active: false }).err().unwrap();
        assert!(sin_nm.contains("NetworkManager"), "{sin_nm}");
        // Sin elegir nombre no se toca el hostname ni se crea el script.
        let keep = ToolRequest::Identity { wifi_mac: true, ethernet_mac: false, dhcp_windows: false, tcp_windows: false, hostname: HostnameStyle::Keep };
        let kp = plan(&keep, &env()).unwrap();
        assert!(!kp.fixes.iter().any(|f| matches!(f, Fix::SetHostname { .. })));
        assert!(!kp.fixes.iter().any(|f| matches!(f, Fix::WriteFiles { files, .. } if files[0].path == ROTATE_SCRIPT)));
    }

    #[test]
    fn flatpak_camera_and_trusted_plans() {
        let p = plan(&ToolRequest::Flatpak { app: "org.videolan.VLC".into(), home: true, devices: true }, &env()).unwrap();
        let Fix::FlatpakOverride { args, .. } = &p.fixes[0] else { panic!() };
        assert!(args.contains(&"--nofilesystem=home".to_string()) && args.contains(&"--nodevice=all".to_string()));
        assert!(!p.fixes[0].needs_root(), "los overrides de Flatpak son de usuario");
        assert!(plan(&ToolRequest::Flatpak { app: "x.y".into(), home: false, devices: false }, &env()).is_err());

        let c = plan(&ToolRequest::Camera {}, &env()).unwrap();
        let Fix::WriteFiles { files, .. } = &c.fixes[0] else { panic!() };
        assert!(files[0].content.contains("blacklist uvcvideo") && files[0].path.starts_with("/etc/modprobe.d/"));

        let t = plan(&ToolRequest::TrustedNetworks { trusted: vec!["Casa".into()], others: vec!["Cafe".into(), "Aeropuerto".into()] }, &env()).unwrap();
        assert_eq!(t.fixes.len(), 2);
        let Fix::NmProfilesNamed { names, props } = &t.fixes[0] else { panic!() };
        assert_eq!((names.clone(), props[0].value.clone()), (vec!["Casa".to_string()], "home".to_string()));
        assert!(plan(&ToolRequest::TrustedNetworks { trusted: vec![], others: vec![] }, &env()).is_err());
        assert!(plan(&ToolRequest::TrustedNetworks { trusted: vec!["Casa".into()], others: vec![] }, &PlanEnv { nm_active: false, resolved_active: false }).is_err());
    }

    #[test]
    fn usbguard_plans() {
        let off = plan(&ToolRequest::Usbguard { mode: "off".into() }, &env()).unwrap();
        assert!(matches!(&off.fixes[0], Fix::DisableUnits { units } if units == &["usbguard.service"]));
        let on = plan(&ToolRequest::Usbguard { mode: "on".into() }, &env()).unwrap();
        assert!(matches!(&on.fixes[0], Fix::EnableUnits { .. }) && on.fixes[0].needs_root());
        let setup = plan(&ToolRequest::Usbguard { mode: "setup".into() }, &env()).unwrap();
        assert!(matches!(setup.fixes[0], Fix::InstallPackages { .. }) && matches!(setup.fixes[1], Fix::UsbguardPolicy {}) && matches!(setup.fixes[2], Fix::EnableUnits { .. }));
        assert!(plan(&ToolRequest::Usbguard { mode: "x".into() }, &env()).is_err());
    }

    #[test]
    fn windows_hostnames_are_random_and_well_formed() {
        let a = windows_hostname();
        let b = windows_hostname();
        assert!(hostname_is_windows_style(&a) && hostname_is_windows_style(&b));
        assert_ne!(a, b);
        assert!(crate::engine::is_generic_hostname(&a, "fedora"), "no debe disparar reglas de hostname personal");
    }

    #[test]
    fn ipv6_plan_keeps_loopback_and_pins_nm() {
        let p = plan(&ToolRequest::Ipv6Off {}, &env()).unwrap();
        let Fix::Sysctl { settings } = &p.fixes[0] else { panic!() };
        let pos = |k: &str| settings.iter().position(|s| s.key == k).unwrap();
        assert!(pos("net.ipv6.conf.all.disable_ipv6") < pos("net.ipv6.conf.lo.disable_ipv6"));
        assert_eq!(settings[pos("net.ipv6.conf.lo.disable_ipv6")].value, "0");
        assert!(matches!(&p.fixes[1], Fix::NmProfiles { props, .. } if props[0].name == "ipv6.method" && props[0].value == "disabled"));
        // Sin NetworkManager solo se usa sysctl.
        let p = plan(&ToolRequest::Ipv6Off {}, &PlanEnv { nm_active: false, resolved_active: false }).unwrap();
        assert_eq!(p.fixes.len(), 1);
    }

    #[test]
    fn every_tool_plan_actually_applies_and_reverts_with_mocks() {
        let r = MockRunner::new();
        r.on("nmcli -t -f UUID,NAME,TYPE connection show", "u1:Casa:802-11-wireless\nu2:Cable:802-3-ethernet\n");
        r.on("nmcli -g ipv4.dns connection show u1", "1.1.1.1,8.8.8.8\n");
        r.on("systemctl is-active NetworkManager.service", "active\n");
        r.on("systemctl is-active systemd-resolved.service", "active\n");
        r.on("sysctl -n net.ipv4.ip_default_ttl", "64\n");
        r.on("sysctl -n net.ipv4.tcp_timestamps", "1\n");
        r.on("sysctl -n net.ipv4.tcp_ecn", "2\n");
        r.on("sysctl -n net.ipv6.conf.all.hop_limit", "64\n");
        r.on("sysctl -n net.ipv6.conf.default.hop_limit", "64\n");
        r.on("sysctl -n net.ipv6.conf.all.disable_ipv6", "0\n");
        r.on("sysctl -n net.ipv6.conf.default.disable_ipv6", "0\n");
        r.on("sysctl -n net.ipv6.conf.lo.disable_ipv6", "0\n");
        r.on("hostnamectl --static", "fedora\n");
        let root = std::env::temp_dir().join(format!("silence-tools-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        let a = Applier { runner: &r, root: root.clone(), now: 1, ff_dirs: None };
        let e = PlanEnv::detect(&r);
        for req in [
            ToolRequest::Dns { provider: "mullvad".into(), strict: false },
            ToolRequest::Identity { wifi_mac: true, ethernet_mac: true, dhcp_windows: true, tcp_windows: true, hostname: HostnameStyle::Windows },
            ToolRequest::Ipv6Off {},
        ] {
            let plan = plan(&req, &e).unwrap();
            let fixes: Vec<&Fix> = plan.fixes.iter().collect();
            let (undo, _) = a.apply_all(plan.key, &fixes).unwrap_or_else(|er| panic!("{:?}: {er}", req));
            assert!(!undo.is_empty());
            assert!(a.revert(&undo).is_empty(), "{:?}", req);
        }
        // Tras revertir todo, no queda ningún archivo nuestro en /etc.
        let leftover: Vec<_> = walk(&root);
        assert!(leftover.is_empty(), "archivos huérfanos: {leftover:?}");
    }

    fn walk(p: &std::path::Path) -> Vec<String> {
        let mut v = vec![];
        if let Ok(rd) = std::fs::read_dir(p) {
            for e in rd.flatten() {
                let path = e.path();
                if path.is_dir() {
                    v.extend(walk(&path));
                } else {
                    v.push(path.display().to_string());
                }
            }
        }
        v
    }

    #[test]
    fn provider_detection() {
        assert_eq!(provider_in_use(&["9.9.9.9".into(), "149.112.112.112".into()]).unwrap().id, "quad9");
        assert!(provider_in_use(&["1.1.1.1".into()]).is_none());
        assert!(provider_in_use(&[]).is_none());
        // Si queda el DNS del ISP mezclado, NO cuenta como protegido.
        assert!(provider_in_use(&["9.9.9.9".into(), "192.168.1.1".into()]).is_none());
    }

    #[test]
    fn suggested_firewall_allow_from_listeners() {
        let mut s = Snapshot::default();
        s.listeners.push(Listener { proto: "tcp".into(), addr: "*".into(), port: 1716, process: Some("kdeconnectd".into()), pid: None, exposure: Exposure::AllInterfaces });
        s.evidence.insert(EvidenceKind::Ssh, Evidence { in_use: Some(true), detail: String::new() });
        let a = suggested_firewall_allow(&s);
        assert!(a.contains(&"kdeconnect".to_string()) && a.contains(&"ssh".to_string()));
        assert!(!a.contains(&"localsend".to_string()));
    }

    #[test]
    fn requests_roundtrip_through_json() {
        let r = ToolRequest::Firewall { level: "strict".into(), allow: vec!["ssh".into()] };
        let j = serde_json::to_string(&r).unwrap();
        assert!(j.contains("\"tool\":\"firewall\""));
        assert_eq!(serde_json::from_str::<ToolRequest>(&j).unwrap(), r);
        assert!(serde_json::from_str::<ToolRequest>(r#"{"tool":"rm_rf"}"#).is_err());
    }
}
