//! Privacidad de Firefox: detección en prefs.js/user.js y aplicación reversible mediante un
//! bloque marcado en user.js (así revertir quita solo lo nuestro y respeta lo que ya hubiera).
//!
//! Todas las preferencias de este archivo se verificaron como existentes en Firefox 159 (las que
//! ya fueron eliminadas por Mozilla —p. ej. `network.predictor.enabled`— se dejaron fuera a propósito,
//! porque una preferencia inexistente falla en silencio y da una falsa sensación de privacidad).

use crate::model::FirefoxProfile;
use regex::Regex;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

pub const BEGIN: &str = "// >>> silence:begin (gestionado por Silence, no editar dentro del bloque)";
pub const END: &str = "// <<< silence:end";
const LEVEL_PREFIX: &str = "// nivel: ";

type Pref = (&'static str, &'static str);

/// Telemetría y contenido patrocinado. Todas valen `true` por defecto, así que si no aparecen en
/// el perfil se consideran activas.
pub const TELEMETRY: [Pref; 7] = [
    ("datareporting.healthreport.uploadEnabled", "false"),
    ("datareporting.usage.uploadEnabled", "false"),
    ("toolkit.telemetry.unified", "false"),
    ("app.shield.optoutstudies.enabled", "false"),
    ("browser.newtabpage.activity-stream.telemetry", "false"),
    ("browser.newtabpage.activity-stream.showSponsored", "false"),
    ("browser.newtabpage.activity-stream.showSponsoredTopSites", "false"),
];

/// Equilibrado: no debería romper ningún sitio.
const BALANCED: [Pref; 9] = [
    ("browser.urlbar.suggest.quicksuggest.sponsored", "false"),
    ("extensions.htmlaboutaddons.recommendations.enabled", "false"),
    ("browser.discovery.enabled", "false"),
    ("app.normandy.enabled", "false"),
    ("privacy.globalprivacycontrol.enabled", "true"),
    ("network.dns.disablePrefetch", "true"),
    ("network.prefetch-next", "false"),
    ("media.peerconnection.ice.default_address_only", "true"),
    ("browser.newtabpage.activity-stream.feeds.section.topstories", "false"),
];

/// Máximo: añade protección estricta contra rastreo. Algún sitio puede requerir una excepción.
const MAXIMUM: [Pref; 13] = [
    ("browser.contentblocking.category", "\"strict\""),
    ("privacy.trackingprotection.enabled", "true"),
    ("privacy.query_stripping.enabled", "true"),
    ("privacy.fingerprintingProtection", "true"),
    ("network.cookie.cookieBehavior", "5"),
    ("dom.security.https_only_mode", "true"),
    ("browser.safebrowsing.downloads.remote.enabled", "false"),
    ("browser.urlbar.suggest.quicksuggest.nonsponsored", "false"),
    ("browser.search.suggest.enabled", "false"),
    ("browser.urlbar.suggest.searches", "false"),
    ("network.http.referer.XOriginTrimmingPolicy", "2"),
    ("beacon.enabled", "false"),
    ("browser.urlbar.speculativeConnect.enabled", "false"),
];

/// Ligero y rápido (opcional, se suma a cualquier nivel). Todas verificadas en Firefox 159.
/// `dom.ipc.processCount` baja de 8 a 4 procesos de pestañas: menos RAM a cambio de algo menos de
/// aislamiento entre pestañas muy cargadas.
const LIGHT: [Pref; 7] = [
    ("browser.sessionstore.interval", "60000"),
    ("dom.ipc.processCount", "4"),
    ("browser.newtabpage.activity-stream.showWeather", "false"),
    ("browser.vpn_promo.enabled", "false"),
    ("browser.preferences.moreFromMozilla", "false"),
    ("browser.aboutwelcome.enabled", "false"),
    ("browser.urlbar.suggest.trending", "false"),
];

/// Separa «balanced+light» en («balanced», true).
pub fn split_level(level: &str) -> (&str, bool) {
    match level.strip_suffix("+light") {
        Some(base) => (base, true),
        None => (level, false),
    }
}

pub fn level_ok(level: &str) -> bool {
    matches!(split_level(level).0, "balanced" | "maximum")
}

/// Preferencias a escribir. `None` = solo telemetría (lo que usa la regla de telemetría).
pub fn prefs_for(level: Option<&str>) -> Vec<Pref> {
    let mut v: Vec<Pref> = TELEMETRY.to_vec();
    let (base, light) = match level {
        Some(l) => {
            let (b, li) = split_level(l);
            (Some(b), li)
        }
        None => (None, false),
    };
    if matches!(base, Some("balanced") | Some("maximum")) {
        v.extend(BALANCED);
    }
    if base == Some("maximum") {
        v.extend(MAXIMUM);
    }
    if light {
        v.extend(LIGHT);
    }
    v
}

fn home() -> String {
    std::env::var("HOME").unwrap_or_default()
}

/// (raíz de perfiles, descripción)
pub fn roots() -> Vec<(PathBuf, &'static str)> {
    let h = home();
    vec![
        (PathBuf::from(format!("{h}/.mozilla/firefox")), "Firefox"),
        (PathBuf::from(format!("{h}/.var/app/org.mozilla.firefox/.mozilla/firefox")), "Firefox (Flatpak)"),
        (PathBuf::from(format!("{h}/snap/firefox/common/.mozilla/firefox")), "Firefox (Snap)"),
    ]
}

pub fn profile_dirs() -> Vec<(PathBuf, &'static str)> {
    let mut v = Vec::new();
    for (root, flavor) in roots() {
        let Ok(rd) = std::fs::read_dir(&root) else { continue };
        for e in rd.flatten() {
            let p = e.path();
            if p.is_dir() && p.join("prefs.js").is_file() {
                v.push((p, flavor));
            }
        }
    }
    v.sort();
    v
}

pub fn parse_prefs(text: &str) -> BTreeMap<String, String> {
    let re = Regex::new(r#"user_pref\(\s*"([^"]+)"\s*,\s*(.+?)\s*\)\s*;"#).unwrap();
    re.captures_iter(text).map(|c| (c[1].to_string(), c[2].to_string())).collect()
}

/// Preferencias de telemetría que siguen sin estar desactivadas. `user.js` manda sobre `prefs.js`.
pub fn bad_prefs(prefs_js: &str, user_js: &str) -> Vec<String> {
    let mut eff = parse_prefs(prefs_js);
    eff.extend(parse_prefs(user_js));
    TELEMETRY
        .iter()
        .filter(|(name, want)| eff.get(*name).map(String::as_str) != Some(*want))
        .map(|(name, _)| name.to_string())
        .collect()
}

/// Política de empresa/distribución que ya desactiva la telemetría para todos los perfiles.
pub fn policy_disables_telemetry() -> bool {
    let re = Regex::new(r#""DisableTelemetry"\s*:\s*true"#).unwrap();
    [
        "/etc/firefox/policies/policies.json",
        "/usr/lib64/firefox/distribution/policies.json",
        "/usr/lib/firefox/distribution/policies.json",
        "/usr/lib/firefox-esr/distribution/policies.json",
    ]
    .iter()
    .any(|p| std::fs::read_to_string(p).map(|t| re.is_match(&t)).unwrap_or(false))
}

pub fn collect_profiles() -> Vec<FirefoxProfile> {
    if policy_disables_telemetry() {
        return Vec::new();
    }
    profile_dirs()
        .into_iter()
        .map(|(dir, flavor)| {
            let prefs = std::fs::read_to_string(dir.join("prefs.js")).unwrap_or_default();
            let user = std::fs::read_to_string(dir.join("user.js")).unwrap_or_default();
            FirefoxProfile {
                path: dir.display().to_string(),
                flavor: flavor.to_string(),
                bad_prefs: bad_prefs(&prefs, &user),
            }
        })
        .collect()
}

/// Nivel de endurecimiento escrito por Silence en un user.js ("telemetry", "balanced", "maximum").
pub fn block_level(user_js: &str) -> Option<String> {
    extract_block(user_js)?
        .lines()
        .find_map(|l| l.strip_prefix(LEVEL_PREFIX))
        .map(|s| s.trim().to_string())
}

pub fn render_block(level: Option<&str>) -> String {
    let mut seen = BTreeMap::new();
    let mut order = Vec::new();
    for (n, v) in prefs_for(level) {
        if seen.insert(n, v).is_none() {
            order.push(n);
        }
    }
    let mut s = String::new();
    s.push_str(BEGIN);
    s.push('\n');
    s.push_str(&format!("{LEVEL_PREFIX}{}\n", level.unwrap_or("telemetry")));
    for n in order {
        s.push_str(&format!("user_pref(\"{n}\", {});\n", seen[n]));
    }
    s.push_str(END);
    s.push('\n');
    s
}

/// Devuelve el bloque de Silence (con marcadores) si existe.
pub fn extract_block(text: &str) -> Option<String> {
    let mut out = String::new();
    let mut inside = false;
    let mut found = false;
    for line in text.lines() {
        if line.trim() == BEGIN {
            inside = true;
            found = true;
        }
        if inside {
            out.push_str(line);
            out.push('\n');
            if line.trim() == END {
                inside = false;
            }
        }
    }
    found.then_some(out)
}

/// Quita el bloque de Silence (si existe) y devuelve el resto intacto.
pub fn strip_block(text: &str) -> String {
    let mut out = Vec::new();
    let mut inside = false;
    for line in text.lines() {
        if line.trim() == BEGIN {
            inside = true;
            continue;
        }
        if inside {
            if line.trim() == END {
                inside = false;
            }
            continue;
        }
        out.push(line);
    }
    let mut s = out.join("\n");
    if !s.is_empty() {
        s.push('\n');
    }
    s
}

/// `block` = texto completo del bloque (con marcadores) a colocar al final.
pub fn with_block_text(existing: &str, block: &str) -> String {
    let mut base = strip_block(existing);
    if !base.is_empty() && !base.ends_with("\n\n") {
        base.push('\n');
    }
    base + block
}

pub fn with_block(existing: &str, level: Option<&str>) -> String {
    with_block_text(existing, &render_block(level))
}

/// Aplica el bloque a `user.js` de un perfil.
/// Devuelve (el archivo no existía, bloque de Silence que había antes).
pub fn apply_to_profile(dir: &Path, level: Option<&str>) -> std::io::Result<(bool, Option<String>)> {
    let path = dir.join("user.js");
    let existing = std::fs::read_to_string(&path);
    let created = existing.is_err();
    let text = existing.unwrap_or_default();
    let previous = extract_block(&text);
    std::fs::write(&path, with_block(&text, level))?;
    Ok((created, previous))
}

/// Quita el bloque actual y, si había uno previo, lo restaura. Si el archivo queda vacío, lo
/// elimina. Devuelve true si lo eliminó.
pub fn revert_profile(dir: &Path, previous_block: Option<&str>) -> std::io::Result<bool> {
    let path = dir.join("user.js");
    let Ok(text) = std::fs::read_to_string(&path) else { return Ok(false) };
    let rest = match previous_block {
        Some(b) => with_block_text(&text, b),
        None => strip_block(&text),
    };
    if rest.trim().is_empty() {
        std::fs::remove_file(&path)?;
        Ok(true)
    } else {
        std::fs::write(&path, rest)?;
        Ok(false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_missing_and_set_prefs() {
        let prefs = "user_pref(\"datareporting.healthreport.uploadEnabled\", false);\nuser_pref(\"app.shield.optoutstudies.enabled\", true);\n";
        let bad = bad_prefs(prefs, "");
        assert!(!bad.contains(&"datareporting.healthreport.uploadEnabled".to_string()));
        assert!(bad.contains(&"app.shield.optoutstudies.enabled".to_string()));
        assert!(bad.contains(&"toolkit.telemetry.unified".to_string())); // ausente = activa
        let user = "user_pref(\"app.shield.optoutstudies.enabled\", false);";
        assert!(!bad_prefs(prefs, user).contains(&"app.shield.optoutstudies.enabled".to_string()));
    }

    #[test]
    fn block_roundtrip_preserves_user_content() {
        let original = "// mis cosas\nuser_pref(\"privacy.resistFingerprinting\", true);\n";
        let applied = with_block(original, None);
        assert!(applied.contains(BEGIN) && applied.contains(END));
        assert!(applied.contains("privacy.resistFingerprinting"));
        assert_eq!(with_block(&applied, None).matches(BEGIN).count(), 1);
        assert_eq!(strip_block(&applied).trim(), original.trim());
        assert!(bad_prefs("", &applied).is_empty());
    }

    #[test]
    fn light_adds_speed_prefs_on_top_of_any_level() {
        let b = prefs_for(Some("balanced")).len();
        assert_eq!(prefs_for(Some("balanced+light")).len(), b + LIGHT.len());
        assert_eq!(prefs_for(Some("maximum+light")).len(), prefs_for(Some("maximum")).len() + LIGHT.len());
        assert!(level_ok("maximum+light") && !level_ok("todo+light") && !level_ok("+light"));
        assert!(render_block(Some("balanced+light")).contains("browser.sessionstore.interval"));
        assert!(!render_block(Some("balanced")).contains("browser.sessionstore.interval"));
        assert_eq!(block_level(&render_block(Some("balanced+light"))).as_deref(), Some("balanced+light"));
    }

    #[test]
    fn levels_are_nested_and_tagged() {
        let t = prefs_for(None).len();
        let b = prefs_for(Some("balanced")).len();
        let m = prefs_for(Some("maximum")).len();
        assert!(t < b && b < m);
        assert_eq!(block_level(&render_block(Some("maximum"))).as_deref(), Some("maximum"));
        assert_eq!(block_level(&render_block(None)).as_deref(), Some("telemetry"));
        let blk = render_block(Some("maximum"));
        assert!(blk.contains("\"browser.contentblocking.category\", \"strict\""));
        assert!(blk.contains("network.cookie.cookieBehavior\", 5"));
        // Ninguna preferencia se repite dentro del bloque.
        let names: Vec<&str> = blk.lines().filter_map(|l| l.strip_prefix("user_pref(\"")).collect();
        let uniq: std::collections::BTreeSet<_> = names.iter().collect();
        assert_eq!(names.len(), uniq.len());
    }

    #[test]
    fn no_pref_removed_by_mozilla_is_used() {
        for removed in ["network.predictor.enabled", "extensions.pocket.enabled", "browser.ping-centre.telemetry", "browser.newtabpage.activity-stream.feeds.telemetry"] {
            assert!(!render_block(Some("maximum")).contains(removed), "{removed}");
        }
    }

    #[test]
    fn apply_and_revert_on_disk() {
        let dir = std::env::temp_dir().join(format!("silence-ff-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        // Sin user.js: se crea y al revertir se elimina.
        let (created, prev) = apply_to_profile(&dir, Some("balanced")).unwrap();
        assert!(created && prev.is_none());
        assert!(revert_profile(&dir, prev.as_deref()).unwrap());
        assert!(!dir.join("user.js").exists());
        // Con user.js propio: se conserva.
        std::fs::write(dir.join("user.js"), "user_pref(\"a.b\", 1);\n").unwrap();
        let (created, prev) = apply_to_profile(&dir, None).unwrap();
        assert!(!created);
        assert!(!revert_profile(&dir, prev.as_deref()).unwrap());
        assert_eq!(std::fs::read_to_string(dir.join("user.js")).unwrap().trim(), "user_pref(\"a.b\", 1);");
        // Un bloque previo (regla de telemetría) se restaura al revertir el endurecimiento.
        let (_, prev1) = apply_to_profile(&dir, None).unwrap();
        assert!(prev1.is_none());
        let (_, prev2) = apply_to_profile(&dir, Some("maximum")).unwrap();
        assert_eq!(block_level(prev2.as_deref().unwrap()).as_deref(), Some("telemetry"));
        revert_profile(&dir, prev2.as_deref()).unwrap();
        assert_eq!(block_level(&std::fs::read_to_string(dir.join("user.js")).unwrap()).as_deref(), Some("telemetry"));
        std::fs::remove_dir_all(dir).ok();
    }
}
