//! Soporte para ejecutar Silence como AppImage.
//!
//! El helper con permisos de administrador solo se lanza desde un binario propiedad de root que
//! nadie más pueda modificar (ver `ops::helper_path_ok`). Un AppImage vive en la carpeta personal y
//! se monta como el usuario, así que no cumple. La solución: la primera vez, y con tu autorización,
//! se copia a `/usr/local/bin/silence` junto con la política de polkit, y desde entonces el helper
//! usa esa copia. Si el AppImage se actualiza, se vuelve a ofrecer la instalación.

use std::path::{Path, PathBuf};
use std::process::Command;

pub const SYSTEM_BIN: &str = "/usr/local/bin/silence";
const POLICY: &str = include_str!("../packaging/org.silence.policy");
const DESKTOP: &str = include_str!("../packaging/silence.desktop");
const ICON: &str = include_str!("../packaging/silence.svg");

/// Script que corre como root. Solo copia archivos; recibe rutas como argumentos posicionales.
const ROOT_SCRIPT: &str = r#"set -e
install -D -m 0755 -o root -g root "$1" /usr/local/bin/silence
install -D -m 0644 -o root -g root "$2" /usr/share/polkit-1/actions/org.silence.policy
install -D -m 0644 -o root -g root "$3" /usr/share/applications/silence.desktop
install -D -m 0644 -o root -g root "$4" /usr/share/icons/hicolor/scalable/apps/silence.svg
if command -v restorecon >/dev/null 2>&1; then restorecon -F /usr/local/bin/silence /usr/share/polkit-1/actions/org.silence.policy || true; fi
if command -v update-desktop-database >/dev/null 2>&1; then update-desktop-database -q /usr/share/applications || true; fi
"#;

/// ¿Estamos dentro de un AppImage?
pub fn is_appimage() -> bool {
    std::env::var_os("APPIMAGE").is_some() && std::env::var_os("APPDIR").is_some()
}

fn same_content(a: &Path, b: &Path) -> bool {
    use std::io::Read;
    let (Ok(ma), Ok(mb)) = (std::fs::metadata(a), std::fs::metadata(b)) else { return false };
    if ma.len() != mb.len() {
        return false;
    }
    let (Ok(mut fa), Ok(mut fb)) = (std::fs::File::open(a), std::fs::File::open(b)) else { return false };
    let (mut ba, mut bb) = (vec![0u8; 1 << 16], vec![0u8; 1 << 16]);
    loop {
        let Ok(na) = fa.read(&mut ba) else { return false };
        let mut got = 0;
        while got < na {
            match fb.read(&mut bb[got..na]) {
                Ok(0) | Err(_) => return false,
                Ok(n) => got += n,
            }
        }
        if na == 0 {
            return true;
        }
        if ba[..na] != bb[..na] {
            return false;
        }
    }
}

/// ¿La copia del sistema es exactamente este programa?
pub fn installed_matches() -> bool {
    let Ok(me) = std::env::current_exe() else { return false };
    same_content(&me, Path::new(SYSTEM_BIN))
}

/// Ejecutable que debe lanzarse con pkexec. En un AppImage, la copia del sistema; si no existe
/// (o es otra versión) se devuelve la ruta actual y el chequeo de seguridad lo rechazará.
pub fn helper_exe() -> PathBuf {
    let me = std::env::current_exe().unwrap_or_else(|_| PathBuf::from("silence"));
    if is_appimage() && installed_matches() {
        return PathBuf::from(SYSTEM_BIN);
    }
    me
}

/// En un AppImage, ¿falta instalar (o actualizar) la copia del sistema?
pub fn needs_install() -> bool {
    is_appimage() && !installed_matches()
}

/// Comandos que se mostrarán antes de pedir permiso.
pub fn preview() -> Vec<String> {
    vec![
        format!("Copiar este programa a {SYSTEM_BIN} (propiedad de root)"),
        "Instalar la política de polkit en /usr/share/polkit-1/actions/org.silence.policy".into(),
        "Añadir la entrada de menú y el ícono de Silence".into(),
    ]
}

/// Copia el programa y la política al sistema. Pide la contraseña de administrador (pkexec).
pub fn install_system() -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt;
    let me = std::env::current_exe().map_err(|e| e.to_string())?;
    let dir = std::env::temp_dir().join(format!("silence-install-{}", std::process::id()));
    std::fs::create_dir(&dir).map_err(|e| format!("No se pudo preparar la instalación: {e}"))?;
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).map_err(|e| e.to_string())?;
    let result = (|| {
        let bin = dir.join("silence");
        std::fs::copy(&me, &bin).map_err(|e| format!("No se pudo copiar el programa: {e}"))?;
        let mut paths = vec![bin];
        for (name, text) in [("policy", POLICY), ("desktop", DESKTOP), ("icon", ICON)] {
            let p = dir.join(name);
            std::fs::write(&p, text).map_err(|e| e.to_string())?;
            paths.push(p);
        }
        let out = Command::new("pkexec")
            .args(["/bin/sh", "-c", ROOT_SCRIPT, "silence-install"])
            .args(&paths)
            .output()
            .map_err(|e| format!("No se pudo pedir permisos de administrador (pkexec): {e}"))?;
        match out.status.code() {
            Some(0) => Ok(()),
            Some(126) | Some(127) => Err("Autorización cancelada o denegada.".into()),
            _ => Err(format!("La instalación falló. {}", String::from_utf8_lossy(&out.stderr).trim())),
        }
    })();
    let _ = std::fs::remove_dir_all(&dir);
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp(name: &str) -> PathBuf {
        let p = std::env::temp_dir().join(format!("silence-selfinst-{}-{name}", std::process::id()));
        let _ = std::fs::remove_file(&p);
        p
    }

    #[test]
    fn content_comparison() {
        let (a, b, c) = (tmp("a"), tmp("b"), tmp("c"));
        let big = vec![7u8; 200_000];
        std::fs::write(&a, &big).unwrap();
        std::fs::write(&b, &big).unwrap();
        let mut other = big.clone();
        other[150_000] = 8;
        std::fs::write(&c, &other).unwrap();
        assert!(same_content(&a, &b));
        assert!(!same_content(&a, &c));
        assert!(!same_content(&a, Path::new("/no/existe")));
    }

    #[test]
    fn embedded_files_match_what_the_script_installs() {
        assert!(POLICY.contains("org.silence.apply") && POLICY.contains(SYSTEM_BIN));
        assert!(DESKTOP.contains("Exec=/usr/local/bin/silence"));
        assert!(ICON.contains("<svg"));
        for dest in ["/usr/local/bin/silence", "org.silence.policy", "silence.desktop", "silence.svg"] {
            assert!(ROOT_SCRIPT.contains(dest), "{dest}");
        }
        assert!(preview().len() == 3);
    }

    #[test]
    fn not_an_appimage_by_default() {
        if std::env::var_os("APPIMAGE").is_none() {
            assert!(!is_appimage() && !needs_install());
        }
    }
}
