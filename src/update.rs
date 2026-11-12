//! Comprobación de actualizaciones contra las versiones publicadas en GitHub.
//!
//! Es la única conexión de red que hace Silence, y solo consulta la última versión publicada
//! (GitHub ve la IP, como con cualquier descarga). No envía nada del sistema. Se puede desactivar.

use crate::sys::Runner;
use serde_json::Value;
use std::path::Path;

pub const CURRENT: &str = env!("CARGO_PKG_VERSION");
pub const REPO: &str = "vezzulab/Silence";
pub const API_URL: &str = "https://api.github.com/repos/vezzulab/Silence/releases/latest";
pub const APPIMAGE_NAME: &str = "Silence-x86_64.AppImage";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Release {
    pub version: String,
    pub name: String,
    pub notes: String,
    pub page_url: String,
    /// Descarga directa del AppImage, si la versión lo incluye.
    pub appimage_url: Option<String>,
}

/// «v1.2.3» → (1, 2, 3). Ignora sufijos como «-beta»; None si no es una versión.
pub fn parse_version(v: &str) -> Option<(u64, u64, u64)> {
    let core = v.trim().trim_start_matches(['v', 'V']).split(['-', '+']).next()?;
    let mut it = core.split('.');
    let a = it.next()?.parse().ok()?;
    let b = it.next().unwrap_or("0").parse().ok()?;
    let c = it.next().unwrap_or("0").parse().ok()?;
    if it.next().is_some() {
        return None;
    }
    Some((a, b, c))
}

pub fn is_newer(current: &str, candidate: &str) -> bool {
    match (parse_version(current), parse_version(candidate)) {
        (Some(c), Some(n)) => n > c,
        _ => false,
    }
}

/// Lee la respuesta de `releases/latest`. Ignora borradores y prelanzamientos.
pub fn parse_release(json: &str) -> Result<Release, String> {
    let v: Value = serde_json::from_str(json).map_err(|_| "Respuesta de GitHub no válida.".to_string())?;
    if v["draft"] == true || v["prerelease"] == true {
        return Err("La última versión es un borrador o prelanzamiento.".into());
    }
    let tag = v["tag_name"].as_str().ok_or("La respuesta no trae el número de versión.")?;
    parse_version(tag).ok_or_else(|| format!("Número de versión no reconocido: {tag}"))?;
    let page_url = v["html_url"].as_str().unwrap_or("").to_string();
    if !page_url.starts_with("https://github.com/") {
        return Err("Enlace de la versión no válido.".into());
    }
    let appimage_url = v["assets"]
        .as_array()
        .into_iter()
        .flatten()
        .find(|a| a["name"] == APPIMAGE_NAME)
        .and_then(|a| a["browser_download_url"].as_str())
        .filter(|u| u.starts_with("https://github.com/"))
        .map(String::from);
    Ok(Release {
        version: tag.trim_start_matches(['v', 'V']).to_string(),
        name: v["name"].as_str().unwrap_or(tag).to_string(),
        notes: v["body"].as_str().unwrap_or("").trim().to_string(),
        page_url,
        appimage_url,
    })
}

/// Consulta la última versión. `Ok(None)` = ya tienes la última.
pub fn check(r: &dyn Runner) -> Result<Option<Release>, String> {
    if !r.exists("curl") {
        return Err("Hace falta «curl» para buscar actualizaciones.".into());
    }
    let o = r.run(
        "curl",
        &["-fsSL", "--max-time", "12", "-H", "Accept: application/vnd.github+json", "-A", "silence-update-check", API_URL],
    );
    if !o.ok {
        return Err("No se pudo conectar con GitHub (¿sin internet?).".into());
    }
    let rel = parse_release(&o.stdout)?;
    Ok(is_newer(CURRENT, &rel.version).then_some(rel))
}

/// Notas de la versión en texto llano y acotadas: sin encabezados, enlaces ni énfasis de Markdown.
pub fn plain_notes(md: &str, max_lines: usize) -> Vec<String> {
    let mut out = Vec::new();
    for raw in md.lines() {
        let mut l = raw.trim().trim_start_matches('#').trim().to_string();
        if l.is_empty() {
            continue;
        }
        if let Some(rest) = l.strip_prefix("- ").or_else(|| l.strip_prefix("* ")) {
            l = format!("• {rest}");
        }
        l = l.replace("**", "").replace('`', "");
        // [texto](url) → texto
        while let (Some(a), Some(b)) = (l.find('['), l.find("](")) {
            let Some(end) = l[b..].find(')') else { break };
            if a >= b {
                break;
            }
            let text = l[a + 1..b].to_string();
            l.replace_range(a..b + end + 1, &text);
        }
        out.push(l);
        if out.len() >= max_lines {
            out.push("…".into());
            break;
        }
    }
    out
}

/// Descarga el AppImage nuevo y reemplaza el actual (una sola operación atómica de renombrado).
/// El programa en ejecución sigue funcionando; la versión nueva se usa al volver a abrirlo.
pub fn replace_appimage(r: &dyn Runner, url: &str, target: &Path) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt;
    if !url.starts_with("https://github.com/") {
        return Err("Enlace de descarga no válido.".into());
    }
    if !r.exists("curl") {
        return Err("Hace falta «curl» para descargar la actualización.".into());
    }
    let tmp = target.with_extension("AppImage.nueva");
    let t = tmp.to_string_lossy().to_string();
    let o = r.run("curl", &["-fsSL", "--max-time", "600", "-A", "silence-update-check", "-o", &t, url]);
    if !o.ok {
        let _ = std::fs::remove_file(&tmp);
        return Err("La descarga falló. Inténtalo de nuevo más tarde.".into());
    }
    let sane = std::fs::read(&tmp).map(|b| b.len() > 1_000_000 && b.starts_with(b"\x7fELF")).unwrap_or(false);
    if !sane {
        let _ = std::fs::remove_file(&tmp);
        return Err("El archivo descargado no parece un AppImage válido; no se reemplazó nada.".into());
    }
    std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o755)).map_err(|e| e.to_string())?;
    std::fs::rename(&tmp, target).map_err(|e| {
        let _ = std::fs::remove_file(&tmp);
        format!("No se pudo reemplazar el AppImage: {e}")
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sys::mock::MockRunner;

    #[test]
    fn versions_compare_numerically() {
        assert_eq!(parse_version("v1.2.3"), Some((1, 2, 3)));
        assert_eq!(parse_version("0.2"), Some((0, 2, 0)));
        assert_eq!(parse_version("1.0.0-beta.1"), Some((1, 0, 0)));
        assert_eq!(parse_version("hola"), None);
        assert_eq!(parse_version("1.2.3.4"), None);
        assert!(is_newer("0.1.0", "v0.2.0") && is_newer("0.9.0", "0.10.0"));
        assert!(!is_newer("0.2.0", "v0.2.0") && !is_newer("1.0.0", "0.9.9") && !is_newer("0.1.0", "basura"));
    }

    const SAMPLE: &str = r###"{"tag_name":"v0.2.0","name":"Silence 0.2","draft":false,"prerelease":false,
        "html_url":"https://github.com/vezzulab/Silence/releases/tag/v0.2.0",
        "body":"## Novedades\n- **Nuevo** modo [pánico](https://x.y/z)\n- Arreglos\n",
        "assets":[{"name":"otro.txt","browser_download_url":"https://github.com/a/otro.txt"},
                  {"name":"Silence-x86_64.AppImage","browser_download_url":"https://github.com/vezzulab/Silence/releases/download/v0.2.0/Silence-x86_64.AppImage"}]}"###;

    #[test]
    fn release_parsing_and_hardening() {
        let r = parse_release(SAMPLE).unwrap();
        assert_eq!(r.version, "0.2.0");
        assert!(r.appimage_url.as_deref().unwrap().ends_with("Silence-x86_64.AppImage"));
        assert!(parse_release(&SAMPLE.replace("\"draft\":false", "\"draft\":true")).is_err());
        assert!(parse_release(&SAMPLE.replace("\"prerelease\":false", "\"prerelease\":true")).is_err());
        assert!(parse_release("no json").is_err());
        // Un enlace que no es de github.com nunca se acepta.
        let evil = SAMPLE.replace("https://github.com/vezzulab/Silence/releases/download", "https://evil.example/releases/download");
        assert!(parse_release(&evil).unwrap().appimage_url.is_none());
        assert!(parse_release(&SAMPLE.replace("https://github.com/vezzulab/Silence/releases/tag", "http://evil.example/tag")).is_err());
    }

    #[test]
    fn notes_become_plain_text() {
        let n = plain_notes("## Novedades\n- **Nuevo** modo [pánico](https://x.y/z)\n\n* `Arreglos`\n", 10);
        assert_eq!(n, vec!["Novedades", "• Nuevo modo pánico", "• Arreglos"]);
        assert_eq!(plain_notes("a\nb\nc\nd", 2), vec!["a", "b", "…"]);
    }

    #[test]
    fn check_reports_only_newer_versions() {
        let r = MockRunner::new();
        r.on("curl --version", "curl 8\n");
        let newer = SAMPLE.replace("v0.2.0", &format!("v{}", "99.0.0"));
        r.on(&format!("curl -fsSL --max-time 12 -H Accept: application/vnd.github+json -A silence-update-check {API_URL}"), &newer);
        assert_eq!(check(&r).unwrap().unwrap().version, "99.0.0");
        let r2 = MockRunner::new();
        r2.on("curl --version", "curl 8\n");
        let same = SAMPLE.replace("v0.2.0", &format!("v{CURRENT}"));
        r2.on(&format!("curl -fsSL --max-time 12 -H Accept: application/vnd.github+json -A silence-update-check {API_URL}"), &same);
        assert!(check(&r2).unwrap().is_none());
        assert!(check(&MockRunner::new()).is_err(), "sin curl");
    }

    #[test]
    fn replace_rejects_foreign_urls_and_garbage() {
        let r = MockRunner::new();
        r.on("curl --version", "curl 8\n");
        let target = std::env::temp_dir().join(format!("silence-upd-{}.AppImage", std::process::id()));
        std::fs::write(&target, "viejo").unwrap();
        assert!(replace_appimage(&r, "https://evil.example/x", &target).is_err());
        assert_eq!(std::fs::read_to_string(&target).unwrap(), "viejo");
        let _ = std::fs::remove_file(&target);
    }
}
