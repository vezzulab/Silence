//! Funciones de privacidad «de usuario»: limpiar metadatos de archivos, borrar rastros locales,
//! auditar extensiones de navegador y revisar llaves SSH. Nada de esto toca el sistema (no hace
//! falta root) y todo lo que borra se muestra antes con su tamaño.

use serde_json::Value;
use std::path::{Path, PathBuf};

// ───────────────────────── Metadatos de archivos ─────────────────────────

/// Quita de un JPEG los bloques con metadatos (EXIF/GPS, XMP, Photoshop, comentarios).
/// Conserva JFIF, el perfil de color (ICC) y Adobe (APP14), que hacen falta para ver bien la imagen.
/// Devuelve None si no parece un JPEG válido.
pub fn strip_jpeg(data: &[u8]) -> Option<Vec<u8>> {
    if data.len() < 4 || data[0] != 0xFF || data[1] != 0xD8 {
        return None;
    }
    let mut out = vec![0xFF, 0xD8];
    let mut i = 2;
    while i + 1 < data.len() {
        if data[i] != 0xFF {
            return None;
        }
        let marker = data[i + 1];
        if marker == 0xFF {
            i += 1; // relleno
            continue;
        }
        // Marcadores sin longitud.
        if marker == 0x01 || (0xD0..=0xD7).contains(&marker) {
            out.extend_from_slice(&data[i..i + 2]);
            i += 2;
            continue;
        }
        if marker == 0xD9 {
            out.extend_from_slice(&data[i..]);
            return Some(out);
        }
        if i + 3 >= data.len() {
            return None;
        }
        let len = u16::from_be_bytes([data[i + 2], data[i + 3]]) as usize;
        if len < 2 || i + 2 + len > data.len() {
            return None;
        }
        if marker == 0xDA {
            // Inicio del escaneo: desde aquí todo es imagen.
            out.extend_from_slice(&data[i..]);
            return Some(out);
        }
        let drop = matches!(marker, 0xE1 | 0xE3..=0xED | 0xEF | 0xFE);
        if !drop {
            out.extend_from_slice(&data[i..i + 2 + len]);
        }
        i += 2 + len;
    }
    None
}

/// Quita de un PNG los fragmentos con texto, fecha y EXIF (tEXt, zTXt, iTXt, eXIf, tIME).
pub fn strip_png(data: &[u8]) -> Option<Vec<u8>> {
    const SIG: [u8; 8] = [0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A];
    if data.len() < 8 || data[..8] != SIG {
        return None;
    }
    let mut out = SIG.to_vec();
    let mut i = 8;
    let mut saw_end = false;
    while i + 12 <= data.len() {
        let len = u32::from_be_bytes([data[i], data[i + 1], data[i + 2], data[i + 3]]) as usize;
        let end = i + 12 + len;
        if end > data.len() {
            return None;
        }
        let kind = &data[i + 4..i + 8];
        if !matches!(kind, b"tEXt" | b"zTXt" | b"iTXt" | b"eXIf" | b"tIME") {
            out.extend_from_slice(&data[i..end]);
        }
        i = end;
        if kind == b"IEND" {
            saw_end = true;
            break;
        }
    }
    saw_end.then_some(out)
}

#[derive(Debug, Clone)]
pub struct CleanResult {
    pub src: String,
    pub out: Option<String>,
    pub message: String,
}

/// Ruta de la copia limpia: «foto.jpg» → «foto.limpio.jpg» (nunca pisa el original).
pub fn clean_name(src: &Path) -> PathBuf {
    let stem = src.file_stem().map(|s| s.to_string_lossy().to_string()).unwrap_or_else(|| "archivo".into());
    let ext = src.extension().map(|e| format!(".{}", e.to_string_lossy())).unwrap_or_default();
    src.with_file_name(format!("{stem}.limpio{ext}"))
}

/// Limpia un archivo y deja una copia al lado. JPEG y PNG se limpian aquí mismo; el resto
/// (PDF, Office, audio, vídeo…) usa `mat2` o `exiftool` si están instalados.
pub fn clean_file(src: &Path, has_cmd: &dyn Fn(&str) -> bool, run: &dyn Fn(&str, &[&str]) -> bool) -> CleanResult {
    let name = src.display().to_string();
    let res = |out: Option<String>, message: &str| CleanResult { src: name.clone(), out, message: message.to_string() };
    if !src.is_file() {
        return res(None, "No es un archivo.");
    }
    let ext = src.extension().map(|e| e.to_string_lossy().to_lowercase()).unwrap_or_default();
    let dst = clean_name(src);
    if dst.exists() {
        return res(None, "Ya existe una copia limpia; no la piso.");
    }
    let native = match ext.as_str() {
        "jpg" | "jpeg" => Some(strip_jpeg as fn(&[u8]) -> Option<Vec<u8>>),
        "png" => Some(strip_png as fn(&[u8]) -> Option<Vec<u8>>),
        _ => None,
    };
    if let Some(f) = native {
        let Ok(bytes) = std::fs::read(src) else { return res(None, "No se pudo leer.") };
        return match f(&bytes) {
            Some(clean) => match std::fs::write(&dst, clean) {
                Ok(()) => res(Some(dst.display().to_string()), "Listo: sin ubicación, cámara ni fechas."),
                Err(e) => res(None, &format!("No se pudo escribir la copia: {e}")),
            },
            None => res(None, "El archivo parece dañado o no es de ese tipo."),
        };
    }
    let (s, d) = (src.display().to_string(), dst.display().to_string());
    if has_cmd("mat2") {
        // mat2 deja «<nombre>.cleaned.<ext>» junto al original; lo renombramos a nuestro formato.
        let cleaned = src.with_file_name(format!(
            "{}.cleaned{}",
            src.file_stem().map(|s| s.to_string_lossy().to_string()).unwrap_or_default(),
            src.extension().map(|e| format!(".{}", e.to_string_lossy())).unwrap_or_default()
        ));
        if run("mat2", &[&s]) && cleaned.exists() && std::fs::rename(&cleaned, &dst).is_ok() {
            return res(Some(d), "Listo (mat2).");
        }
    }
    if has_cmd("exiftool") && run("exiftool", &["-all=", "-o", &d, &s]) && dst.exists() {
        return res(Some(d), "Listo (exiftool).");
    }
    res(None, "Para este tipo de archivo instala «mat2» (recomendado) o «exiftool».")
}

/// Expande una lista de rutas: los archivos tal cual y, de las carpetas, sus archivos
/// (un nivel, sin recursión, para no limpiar sin querer medio disco).
pub fn expand_paths(inputs: &[String]) -> Vec<PathBuf> {
    let mut v = Vec::new();
    for raw in inputs {
        let t = raw.trim().trim_matches('"').trim_matches('\'');
        if t.is_empty() {
            continue;
        }
        let p = PathBuf::from(t.strip_prefix("file://").unwrap_or(t));
        if p.is_dir() {
            if let Ok(rd) = std::fs::read_dir(&p) {
                let mut files: Vec<PathBuf> = rd
                    .flatten()
                    .map(|e| e.path())
                    .filter(|f| f.is_file() && !f.to_string_lossy().contains(".limpio"))
                    .collect();
                files.sort();
                v.extend(files);
            }
        } else {
            v.push(p);
        }
    }
    v
}

// ───────────────────────── Rastros locales ─────────────────────────

#[derive(Debug, Clone)]
pub struct Trace {
    pub id: &'static str,
    pub label: &'static str,
    pub why: &'static str,
    /// Archivos o carpetas (se vacía su contenido; la carpeta se conserva).
    pub paths: Vec<PathBuf>,
    pub bytes: u64,
    pub files: usize,
}

fn size_of(p: &Path) -> (u64, usize) {
    let Ok(md) = std::fs::symlink_metadata(p) else { return (0, 0) };
    if md.file_type().is_symlink() {
        return (0, 1);
    }
    if md.is_file() {
        return (md.len(), 1);
    }
    let mut total = (0u64, 0usize);
    if let Ok(rd) = std::fs::read_dir(p) {
        for e in rd.flatten() {
            let (b, n) = size_of(&e.path());
            total.0 += b;
            total.1 += n;
        }
    }
    total
}

/// Definición de los rastros conocidos, relativos a la carpeta personal.
const TRACE_DEFS: [(&str, &str, &str, &[&str]); 6] = [
    ("recent", "Archivos recientes", "La lista de lo último que abriste (documentos, fotos, vídeos).", &[".local/share/recently-used.xbel", ".local/share/RecentDocuments"]),
    ("thumbs", "Miniaturas de imágenes", "Vistas previas guardadas: delatan qué fotos y vídeos viste, aunque ya los hayas borrado.", &[".cache/thumbnails"]),
    ("shell", "Historial de la terminal", "Cada comando que escribiste, con contraseñas pegadas por error incluidas.", &[".bash_history", ".zsh_history", ".local/share/fish/fish_history", ".python_history", ".lesshst", ".viminfo"]),
    ("clipboard", "Historial del portapapeles", "Todo lo que copiaste: contraseñas, textos privados, enlaces.", &[".local/share/klipper/history2.lst"]),
    ("trash", "Papelera", "Lo que «borraste» sigue ahí hasta que vacíes la papelera.", &[".local/share/Trash/files", ".local/share/Trash/info"]),
    ("crash", "Informes de fallos", "Volcados de memoria de programas que se cerraron; pueden contener datos tuyos.", &[".local/share/abrt", ".local/share/drkonqi/crashes"]),
];

pub fn traces(home: &Path) -> Vec<Trace> {
    TRACE_DEFS
        .iter()
        .map(|(id, label, why, rels)| {
            let paths: Vec<PathBuf> = rels.iter().map(|r| home.join(r)).filter(|p| std::fs::symlink_metadata(p).is_ok()).collect();
            let (bytes, files) = paths.iter().map(|p| size_of(p)).fold((0, 0), |a, b| (a.0 + b.0, a.1 + b.1));
            Trace { id, label, why, paths, bytes, files }
        })
        .collect()
}

pub fn human_size(b: u64) -> String {
    const U: [&str; 4] = ["B", "KB", "MB", "GB"];
    let mut v = b as f64;
    let mut i = 0;
    while v >= 1024.0 && i < U.len() - 1 {
        v /= 1024.0;
        i += 1;
    }
    if i == 0 { format!("{b} B") } else { format!("{v:.1} {}", U[i]) }
}

/// Borra el contenido de un rastro. Nunca sigue enlaces simbólicos ni sale de `home`.
pub fn clean_trace(home: &Path, id: &str) -> Result<usize, String> {
    let t = traces(home).into_iter().find(|t| t.id == id).ok_or_else(|| format!("Rastro desconocido: {id}"))?;
    let home_real = home.canonicalize().map_err(|e| e.to_string())?;
    let mut removed = 0;
    for p in &t.paths {
        let md = std::fs::symlink_metadata(p).map_err(|e| e.to_string())?;
        if md.file_type().is_symlink() {
            std::fs::remove_file(p).map_err(|e| format!("{}: {e}", p.display()))?;
            removed += 1;
            continue;
        }
        // Seguridad: el padre real debe estar dentro de la carpeta personal.
        let parent_real = p.parent().and_then(|d| d.canonicalize().ok()).ok_or_else(|| "ruta inválida".to_string())?;
        if !parent_real.starts_with(&home_real) {
            return Err(format!("Ruta fuera de tu carpeta personal: {}", p.display()));
        }
        if md.is_file() {
            std::fs::remove_file(p).map_err(|e| format!("{}: {e}", p.display()))?;
            removed += 1;
        } else if md.is_dir() {
            for e in std::fs::read_dir(p).map_err(|e| e.to_string())?.flatten() {
                let ep = e.path();
                let emd = std::fs::symlink_metadata(&ep).map_err(|e| e.to_string())?;
                let r = if emd.is_dir() && !emd.file_type().is_symlink() { std::fs::remove_dir_all(&ep) } else { std::fs::remove_file(&ep) };
                r.map_err(|e| format!("{}: {e}", ep.display()))?;
                removed += 1;
            }
        }
    }
    Ok(removed)
}

// ───────────────────────── Extensiones de navegador ─────────────────────────

#[derive(Debug, Clone)]
pub struct Ext {
    pub browser: String,
    pub name: String,
    pub id: String,
    /// Avisos en lenguaje llano. Vacío = pide poco.
    pub risks: Vec<String>,
}

/// Traduce permisos de extensión a avisos comprensibles.
pub fn risks_of(perms: &[String], hosts: &[String]) -> Vec<String> {
    let mut r = Vec::new();
    if hosts.iter().any(|h| matches!(h.as_str(), "<all_urls>" | "*://*/*" | "http://*/*" | "https://*/*" | "*://*/")) {
        r.push("Puede leer y cambiar todas las páginas que visitas".to_string());
    }
    let has = |p: &str| perms.iter().any(|x| x == p);
    if has("webRequest") || has("webRequestBlocking") {
        r.push("Puede ver y modificar el tráfico de tus conexiones".into());
    }
    if has("cookies") {
        r.push("Puede leer tus cookies (sesiones iniciadas)".into());
    }
    if has("history") {
        r.push("Puede leer tu historial de navegación".into());
    }
    if has("clipboardRead") {
        r.push("Puede leer lo que copias".into());
    }
    if has("nativeMessaging") {
        r.push("Puede comunicarse con programas de tu equipo".into());
    }
    if has("tabs") && r.is_empty() {
        r.push("Puede ver las direcciones de tus pestañas abiertas".into());
    }
    r
}

fn str_list(v: Option<&Value>) -> Vec<String> {
    v.and_then(|v| v.as_array()).map(|a| a.iter().filter_map(|x| x.as_str().map(String::from)).collect()).unwrap_or_default()
}

/// Firefox: lee `extensions.json` de cada perfil (solo extensiones instaladas por el usuario).
pub fn firefox_extensions(profile_dir: &Path, browser: &str) -> Vec<Ext> {
    let Ok(text) = std::fs::read_to_string(profile_dir.join("extensions.json")) else { return Vec::new() };
    let Ok(v) = serde_json::from_str::<Value>(&text) else { return Vec::new() };
    let mut out = Vec::new();
    for a in v["addons"].as_array().into_iter().flatten() {
        if a["type"] != "extension" || a["location"] != "app-profile" || a["active"] == false {
            continue;
        }
        let id = a["id"].as_str().unwrap_or("").to_string();
        let name = a["defaultLocale"]["name"].as_str().unwrap_or(&id).to_string();
        let perms = str_list(a["userPermissions"].get("permissions"));
        let hosts = str_list(a["userPermissions"].get("origins"));
        out.push(Ext { browser: browser.into(), name, id, risks: risks_of(&perms, &hosts) });
    }
    out
}

/// Familia Chromium: lee cada `manifest.json` de `Extensions/<id>/<versión>/`.
pub fn chromium_extensions(profile_dir: &Path, browser: &str) -> Vec<Ext> {
    let mut out = Vec::new();
    let Ok(rd) = std::fs::read_dir(profile_dir.join("Extensions")) else { return out };
    for e in rd.flatten() {
        let id = e.file_name().to_string_lossy().to_string();
        let Ok(vers) = std::fs::read_dir(e.path()) else { continue };
        let mut versions: Vec<PathBuf> = vers.flatten().map(|v| v.path()).collect();
        versions.sort();
        let Some(latest) = versions.last() else { continue };
        let Ok(text) = std::fs::read_to_string(latest.join("manifest.json")) else { continue };
        let Ok(m) = serde_json::from_str::<Value>(&text) else { continue };
        let raw_name = m["name"].as_str().unwrap_or(&id).to_string();
        let name = if let Some(key) = raw_name.strip_prefix("__MSG_").and_then(|s| s.strip_suffix("__")) {
            localized_name(latest, key).unwrap_or_else(|| id.clone())
        } else {
            raw_name
        };
        let perms = str_list(m.get("permissions"));
        let mut hosts = str_list(m.get("host_permissions"));
        hosts.extend(perms.iter().filter(|p| p.contains("://") || *p == "<all_urls>").cloned());
        out.push(Ext { browser: browser.into(), name, id, risks: risks_of(&perms, &hosts) });
    }
    out
}

fn localized_name(dir: &Path, key: &str) -> Option<String> {
    for loc in ["es", "es_419", "en", "en_US"] {
        let Ok(t) = std::fs::read_to_string(dir.join("_locales").join(loc).join("messages.json")) else { continue };
        let Ok(v) = serde_json::from_str::<Value>(&t) else { continue };
        let lower = key.to_lowercase();
        if let Some(obj) = v.as_object() {
            if let Some(m) = obj.iter().find(|(k, _)| k.to_lowercase() == lower) {
                if let Some(s) = m.1["message"].as_str() {
                    return Some(s.to_string());
                }
            }
        }
    }
    None
}

/// Todas las extensiones de los navegadores que se encuentren en la carpeta personal.
pub fn audit_extensions(home: &Path) -> Vec<Ext> {
    let mut all = Vec::new();
    for (dir, flavor) in crate::firefox::profile_dirs() {
        all.extend(firefox_extensions(&dir, flavor));
    }
    for (rel, label) in [
        (".config/chromium", "Chromium"),
        (".config/google-chrome", "Google Chrome"),
        (".config/BraveSoftware/Brave-Browser", "Brave"),
        (".config/microsoft-edge", "Microsoft Edge"),
    ] {
        let root = home.join(rel);
        let Ok(rd) = std::fs::read_dir(&root) else { continue };
        for e in rd.flatten() {
            let n = e.file_name().to_string_lossy().to_string();
            if n == "Default" || n.starts_with("Profile ") {
                all.extend(chromium_extensions(&e.path(), label));
            }
        }
    }
    // Las que más piden, primero.
    all.sort_by(|a, b| b.risks.len().cmp(&a.risks.len()).then(a.name.cmp(&b.name)));
    all
}

// ───────────────────────── Llaves SSH ─────────────────────────

/// Revisa ~/.ssh: permisos demasiado abiertos y llaves privadas sin contraseña.
pub fn ssh_audit(home: &Path) -> Vec<String> {
    use std::os::unix::fs::PermissionsExt;
    let dir = home.join(".ssh");
    let mut out = Vec::new();
    let Ok(md) = std::fs::metadata(&dir) else { return out };
    if md.permissions().mode() & 0o077 != 0 {
        out.push("La carpeta ~/.ssh es accesible por otros usuarios. Arréglalo con: chmod 700 ~/.ssh".to_string());
    }
    let Ok(rd) = std::fs::read_dir(&dir) else { return out };
    for e in rd.flatten() {
        let p = e.path();
        let Ok(text) = std::fs::read_to_string(&p) else { continue };
        let first = text.lines().next().unwrap_or("");
        if !first.starts_with("-----BEGIN") || !first.contains("PRIVATE KEY") {
            continue;
        }
        let name = p.file_name().unwrap_or_default().to_string_lossy().to_string();
        if std::fs::metadata(&p).map(|m| m.permissions().mode() & 0o077 != 0).unwrap_or(false) {
            out.push(format!("La llave «{name}» es legible por otros usuarios. Arréglalo con: chmod 600 ~/.ssh/{name}"));
        }
        if let Some(msg) = unprotected_key(&text) {
            out.push(format!("La llave «{name}» {msg}. Ponle contraseña con: ssh-keygen -p -f ~/.ssh/{name}"));
        }
    }
    out
}

/// ¿La llave privada está sin contraseña? None si está protegida o no se puede saber.
fn unprotected_key(text: &str) -> Option<&'static str> {
    if text.contains("ENCRYPTED") {
        return None; // PEM antiguo o PKCS#8 cifrado
    }
    if text.contains("BEGIN OPENSSH PRIVATE KEY") {
        // El formato OpenSSH guarda el nombre del cifrado en claro justo tras la cabecera.
        let body: String = text.lines().filter(|l| !l.starts_with("-----")).collect();
        let bytes = decode_b64(&body)?;
        let magic = b"openssh-key-v1\0";
        if !bytes.starts_with(magic) {
            return None;
        }
        let rest = &bytes[magic.len()..];
        let len = u32::from_be_bytes(rest.get(..4)?.try_into().ok()?) as usize;
        let cipher = rest.get(4..4 + len)?;
        return (cipher == b"none").then_some("no tiene contraseña");
    }
    Some("no tiene contraseña")
}

fn decode_b64(s: &str) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    let (mut buf, mut bits) = (0u32, 0);
    for c in s.bytes() {
        let v = match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a' + 26,
            b'0'..=b'9' => c - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            b'=' | b'\n' | b'\r' | b' ' => continue,
            _ => return None,
        } as u32;
        buf = (buf << 6) | v;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((buf >> bits) as u8);
            buf &= (1 << bits) - 1;
        }
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp(name: &str) -> PathBuf {
        let p = std::env::temp_dir().join(format!("silence-extras-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&p);
        std::fs::create_dir_all(&p).unwrap();
        p
    }

    fn jpeg_with_exif() -> Vec<u8> {
        let mut v = vec![0xFF, 0xD8];
        v.extend([0xFF, 0xE0, 0x00, 0x04, b'J', b'F']); // JFIF (se conserva)
        v.extend([0xFF, 0xE1, 0x00, 0x08, b'E', b'x', b'i', b'f', 0, 0]); // EXIF (se quita)
        v.extend([0xFF, 0xFE, 0x00, 0x05, b'h', b'i', b'!']); // comentario (se quita)
        v.extend([0xFF, 0xE2, 0x00, 0x04, b'I', b'C']); // ICC (se conserva)
        v.extend([0xFF, 0xDA, 0x00, 0x02, 1, 2, 3, 0xFF, 0xD9]); // imagen
        v
    }

    #[test]
    fn jpeg_exif_removed_and_color_kept() {
        let out = strip_jpeg(&jpeg_with_exif()).unwrap();
        assert!(!out.windows(4).any(|w| w == b"Exif"));
        assert!(!out.windows(3).any(|w| w == b"hi!"));
        assert!(out.windows(2).any(|w| w == [0xFF, 0xE0]) && out.windows(2).any(|w| w == [0xFF, 0xE2]));
        assert!(out.ends_with(&[0xFF, 0xD9]) && out.starts_with(&[0xFF, 0xD8]));
        assert!(strip_jpeg(b"no soy un jpeg").is_none());
        assert!(strip_jpeg(&[0xFF, 0xD8, 0xFF, 0xE1, 0xFF, 0xFF]).is_none(), "longitud mentirosa");
    }

    fn png_chunk(kind: &[u8; 4], data: &[u8]) -> Vec<u8> {
        let mut c = (data.len() as u32).to_be_bytes().to_vec();
        c.extend(kind);
        c.extend(data);
        c.extend([0, 0, 0, 0]); // CRC (no se verifica)
        c
    }

    #[test]
    fn png_text_chunks_removed() {
        let mut v = vec![0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A];
        v.extend(png_chunk(b"IHDR", &[0; 13]));
        v.extend(png_chunk(b"tEXt", b"Author\0Luis"));
        v.extend(png_chunk(b"eXIf", b"GPS"));
        v.extend(png_chunk(b"IDAT", &[1, 2, 3]));
        v.extend(png_chunk(b"IEND", &[]));
        let out = strip_png(&v).unwrap();
        assert!(!out.windows(4).any(|w| w == b"tEXt" || w == b"eXIf"));
        assert!(out.windows(4).any(|w| w == b"IDAT") && out.windows(4).any(|w| w == b"IEND"));
        assert!(strip_png(&v[..v.len() - 5]).is_none(), "sin IEND");
    }

    #[test]
    fn clean_file_never_overwrites_and_reports_unsupported() {
        let d = tmp("clean");
        let f = d.join("foto.jpg");
        std::fs::write(&f, jpeg_with_exif()).unwrap();
        let none = |_: &str| false;
        let norun = |_: &str, _: &[&str]| false;
        let r = clean_file(&f, &none, &norun);
        assert_eq!(r.out.as_deref(), Some(d.join("foto.limpio.jpg").to_str().unwrap()), "{}", r.message);
        assert!(std::fs::read(&f).unwrap() == jpeg_with_exif(), "el original no se toca");
        assert!(clean_file(&f, &none, &norun).out.is_none(), "no pisa una copia existente");
        let pdf = d.join("a.pdf");
        std::fs::write(&pdf, b"%PDF").unwrap();
        let r = clean_file(&pdf, &none, &norun);
        assert!(r.out.is_none() && r.message.contains("mat2"));
        assert_eq!(clean_name(Path::new("/x/y/archivo")).to_str().unwrap(), "/x/y/archivo.limpio");
    }

    #[test]
    fn expand_paths_folder_one_level_skips_clean_copies() {
        let d = tmp("expand");
        std::fs::write(d.join("a.jpg"), b"x").unwrap();
        std::fs::write(d.join("a.limpio.jpg"), b"x").unwrap();
        std::fs::create_dir_all(d.join("sub")).unwrap();
        std::fs::write(d.join("sub/b.jpg"), b"x").unwrap();
        let v = expand_paths(&[d.display().to_string(), "  ".into()]);
        assert_eq!(v, vec![d.join("a.jpg")]);
    }

    #[test]
    fn traces_measure_and_clean_inside_home_only() {
        let h = tmp("traces");
        std::fs::create_dir_all(h.join(".cache/thumbnails/large")).unwrap();
        std::fs::write(h.join(".cache/thumbnails/large/a.png"), vec![0u8; 2048]).unwrap();
        std::fs::write(h.join(".bash_history"), "ls\nsecreto\n").unwrap();
        std::fs::write(h.join(".zsh_history"), "x").unwrap();
        let t = traces(&h);
        let thumbs = t.iter().find(|t| t.id == "thumbs").unwrap();
        assert_eq!((thumbs.bytes, thumbs.files), (2048, 1));
        assert_eq!(t.iter().find(|t| t.id == "shell").unwrap().files, 2);
        assert_eq!(t.iter().find(|t| t.id == "trash").unwrap().files, 0);
        assert!(clean_trace(&h, "shell").is_ok());
        assert!(!h.join(".bash_history").exists() && !h.join(".zsh_history").exists());
        assert!(clean_trace(&h, "thumbs").is_ok());
        assert!(h.join(".cache/thumbnails").is_dir(), "la carpeta se conserva");
        assert_eq!(std::fs::read_dir(h.join(".cache/thumbnails")).unwrap().count(), 0);
        assert!(clean_trace(&h, "nada").is_err());
    }

    #[test]
    fn trace_cleaning_does_not_follow_symlinks() {
        let h = tmp("symlink");
        let outside = tmp("outside");
        std::fs::write(outside.join("importante.txt"), "no me borres").unwrap();
        std::fs::create_dir_all(h.join(".cache/thumbnails")).unwrap();
        std::os::unix::fs::symlink(&outside, h.join(".cache/thumbnails/enlace")).unwrap();
        clean_trace(&h, "thumbs").unwrap();
        assert!(outside.join("importante.txt").exists(), "solo se quita el enlace, no su destino");
        assert!(!h.join(".cache/thumbnails/enlace").exists());
    }

    #[test]
    fn extension_risks_in_plain_language() {
        let r = risks_of(&["cookies".into(), "tabs".into()], &["<all_urls>".into()]);
        assert!(r.iter().any(|x| x.contains("todas las páginas")) && r.iter().any(|x| x.contains("cookies")));
        assert!(risks_of(&["storage".into()], &[]).is_empty());
        assert_eq!(risks_of(&["tabs".into()], &[]).len(), 1);
    }

    #[test]
    fn firefox_and_chromium_extensions_parsed() {
        let p = tmp("ff");
        std::fs::write(
            p.join("extensions.json"),
            r#"{"addons":[
              {"id":"ublock@x","type":"extension","location":"app-profile","active":true,"defaultLocale":{"name":"uBlock"},"userPermissions":{"permissions":["webRequest"],"origins":["<all_urls>"]}},
              {"id":"tema@x","type":"theme","location":"app-profile","active":true},
              {"id":"builtin@x","type":"extension","location":"app-builtin","active":true},
              {"id":"off@x","type":"extension","location":"app-profile","active":false}]}"#,
        )
        .unwrap();
        let v = firefox_extensions(&p, "Firefox");
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].name, "uBlock");
        assert_eq!(v[0].risks.len(), 2);

        let c = tmp("cr");
        let ver = c.join("Extensions/abcdef/1.0_0");
        std::fs::create_dir_all(ver.join("_locales/en")).unwrap();
        std::fs::write(ver.join("manifest.json"), r#"{"name":"__MSG_appName__","permissions":["history","https://*/*"]}"#).unwrap();
        std::fs::write(ver.join("_locales/en/messages.json"), r#"{"appName":{"message":"Mi extensión"}}"#).unwrap();
        let v = chromium_extensions(&c, "Chromium");
        assert_eq!(v[0].name, "Mi extensión");
        assert!(v[0].risks.iter().any(|x| x.contains("historial")) && v[0].risks.iter().any(|x| x.contains("todas las páginas")));
    }

    #[test]
    fn ssh_audit_flags_open_permissions_and_unprotected_keys() {
        use std::os::unix::fs::PermissionsExt;
        let h = tmp("ssh");
        let d = h.join(".ssh");
        std::fs::create_dir_all(&d).unwrap();
        std::fs::set_permissions(&d, std::fs::Permissions::from_mode(0o755)).unwrap();
        std::fs::write(d.join("id_rsa"), "-----BEGIN RSA PRIVATE KEY-----\nMIIE\n-----END RSA PRIVATE KEY-----\n").unwrap();
        std::fs::set_permissions(d.join("id_rsa"), std::fs::Permissions::from_mode(0o644)).unwrap();
        std::fs::write(d.join("cifrada"), "-----BEGIN RSA PRIVATE KEY-----\nProc-Type: 4,ENCRYPTED\nMIIE\n-----END RSA PRIVATE KEY-----\n").unwrap();
        std::fs::set_permissions(d.join("cifrada"), std::fs::Permissions::from_mode(0o600)).unwrap();
        std::fs::write(d.join("id_rsa.pub"), "ssh-rsa AAAA").unwrap();
        let a = ssh_audit(&h);
        assert!(a.iter().any(|x| x.contains("chmod 700")));
        assert!(a.iter().any(|x| x.contains("id_rsa") && x.contains("chmod 600")));
        assert!(a.iter().any(|x| x.contains("id_rsa") && x.contains("no tiene contraseña")));
        assert!(!a.iter().any(|x| x.contains("cifrada")));
        assert!(!a.iter().any(|x| x.contains(".pub")));
    }

    #[test]
    fn openssh_key_cipher_detected() {
        // Cabecera mínima del formato OpenSSH: "openssh-key-v1\0" + len + cifrado.
        let enc = |cipher: &str| {
            let mut raw = b"openssh-key-v1\0".to_vec();
            raw.extend((cipher.len() as u32).to_be_bytes());
            raw.extend(cipher.as_bytes());
            raw.extend([0u8; 8]);
            let t = b64(&raw);
            format!("-----BEGIN OPENSSH PRIVATE KEY-----\n{t}\n-----END OPENSSH PRIVATE KEY-----\n")
        };
        assert!(unprotected_key(&enc("none")).is_some());
        assert!(unprotected_key(&enc("aes256-ctr")).is_none());
    }

    fn b64(data: &[u8]) -> String {
        const A: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut s = String::new();
        for ch in data.chunks(3) {
            let n = (ch[0] as u32) << 16 | (*ch.get(1).unwrap_or(&0) as u32) << 8 | *ch.get(2).unwrap_or(&0) as u32;
            for i in 0..4 {
                if i <= ch.len() { s.push(A[((n >> (18 - 6 * i)) & 63) as usize] as char) } else { s.push('=') }
            }
        }
        s
    }

    #[test]
    fn human_sizes() {
        assert_eq!(human_size(10), "10 B");
        assert_eq!(human_size(2048), "2.0 KB");
        assert_eq!(human_size(5 * 1024 * 1024), "5.0 MB");
    }
}
