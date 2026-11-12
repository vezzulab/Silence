//! Políticas de navegador a nivel de sistema (mecanismo oficial de Firefox y de la familia Chromium).
//!
//! • Firefox lee /etc/firefox/policies/policies.json (verificado: MOZ_SYSTEM_POLICIES=true en Fedora).
//!   `SearchEngines.Default` se aplica una vez por cambio de política, así que NO bloquea al usuario
//!   si después quiere otro buscador.
//! • Chrome/Chromium/Edge/Brave leen todos los .json de su carpeta `policies/managed`.
//!   Esas políticas sí quedan bloqueadas en los ajustes del navegador hasta que se revierten.

use crate::model::{BrowserTarget, FileSpec};
use crate::sys::Runner;
use serde_json::{json, Map, Value};
use std::path::Path;

pub struct Target {
    pub name: &'static str,
    pub kind: &'static str,
    pub bins: &'static [&'static str],
    /// Firefox: archivo policies.json. Chromium: carpeta `managed`.
    pub path: &'static str,
}

pub const TARGETS: [Target; 5] = [
    Target { name: "Firefox", kind: "firefox", bins: &["firefox", "firefox-esr"], path: "/etc/firefox/policies/policies.json" },
    Target { name: "Chromium", kind: "chromium", bins: &["chromium-browser", "chromium"], path: "/etc/chromium/policies/managed" },
    Target { name: "Google Chrome", kind: "chromium", bins: &["google-chrome-stable", "google-chrome"], path: "/etc/opt/chrome/policies/managed" },
    Target { name: "Microsoft Edge", kind: "chromium", bins: &["microsoft-edge-stable", "microsoft-edge"], path: "/etc/opt/edge/policies/managed" },
    Target { name: "Brave", kind: "chromium", bins: &["brave-browser", "brave"], path: "/etc/brave/policies/managed" },
];

pub const CHROMIUM_FILE: &str = "silence-privacy.json";
pub const UBLOCK_ID: &str = "uBlock0@raymondhill.net";
pub const UBLOCK_URL: &str = "https://addons.mozilla.org/firefox/downloads/latest/ublock-origin/latest.xpi";

pub fn installed(r: &dyn Runner, t: &Target) -> bool {
    t.bins.iter().any(|b| r.exists(b))
}

pub fn chromium_file_path(t: &Target) -> String {
    format!("{}/{}", t.path, CHROMIUM_FILE)
}

/// Políticas de Chromium. Todos los nombres se verificaron como existentes en Chromium instalado.
pub fn chromium_policy(level: &str, ddg: bool) -> Value {
    let (level, light) = crate::firefox::split_level(level);
    let mut m = Map::new();
    let mut set = |k: &str, v: Value| {
        m.insert(k.to_string(), v);
    };
    // Equilibrado: sin impacto visible.
    set("MetricsReportingEnabled", json!(false));
    set("UrlKeyedAnonymizedDataCollectionEnabled", json!(false));
    set("PrivacySandboxPromptEnabled", json!(false));
    set("PrivacySandboxAdTopicsEnabled", json!(false));
    set("PrivacySandboxSiteEnabledAdsEnabled", json!(false));
    set("PrivacySandboxAdMeasurementEnabled", json!(false));
    set("BackgroundModeEnabled", json!(false));
    set("PromotionalTabsEnabled", json!(false));
    set("ShoppingListEnabled", json!(false));
    set("MediaRecommendationsEnabled", json!(false));
    set("SpellCheckServiceEnabled", json!(false));
    set("NetworkPredictionOptions", json!(2));
    set("WebRtcIPHandling", json!("default_public_interface_only"));
    // Máximo: puede requerir ajustes en algunos sitios o servicios.
    if level == "maximum" {
        set("BlockThirdPartyCookies", json!(true));
        set("SearchSuggestEnabled", json!(false));
        set("SyncDisabled", json!(true));
        set("PasswordLeakDetectionEnabled", json!(false));
        set("AutofillCreditCardEnabled", json!(false));
    }
    // Ligero y rápido: libera RAM de pestañas inactivas y evita avisos y descargas innecesarias.
    if light {
        set("HighEfficiencyModeEnabled", json!(true));
        set("DefaultBrowserSettingEnabled", json!(false));
        set("AlternateErrorPagesEnabled", json!(false));
        set("DomainReliabilityAllowed", json!(false));
        set("PaymentMethodQueryEnabled", json!(false));
        set("GenAILocalFoundationalModelSettings", json!(1));
    }
    if ddg {
        set("DefaultSearchProviderEnabled", json!(true));
        set("DefaultSearchProviderName", json!("DuckDuckGo"));
        set("DefaultSearchProviderKeyword", json!("ddg"));
        set("DefaultSearchProviderSearchURL", json!("https://duckduckgo.com/?q={searchTerms}"));
        set("DefaultSearchProviderSuggestURL", json!("https://duckduckgo.com/ac/?q={searchTerms}&type=list"));
    }
    Value::Object(m)
}

/// Fusiona nuestras políticas en un policies.json existente (o crea uno). Si el existente no es
/// JSON válido devuelve error en lugar de pisarlo.
pub fn firefox_policy_merge(existing: Option<&str>, ddg: bool, ublock: bool) -> Result<String, String> {
    let mut root: Value = match existing {
        Some(t) if !t.trim().is_empty() => {
            serde_json::from_str(t).map_err(|e| format!("El policies.json existente no es JSON válido ({e}); no se toca."))?
        }
        _ => json!({}),
    };
    let obj = root.as_object_mut().ok_or("El policies.json existente no es un objeto JSON; no se toca.")?;
    let pol = obj.entry("policies").or_insert_with(|| json!({}));
    let pol = pol.as_object_mut().ok_or("El campo «policies» existente no es un objeto; no se toca.")?;
    if ddg {
        let se = pol.entry("SearchEngines").or_insert_with(|| json!({}));
        if let Some(se) = se.as_object_mut() {
            se.insert("Default".into(), json!("DuckDuckGo"));
        }
    }
    if ublock {
        let ext = pol.entry("ExtensionSettings").or_insert_with(|| json!({}));
        if let Some(ext) = ext.as_object_mut() {
            ext.insert(
                UBLOCK_ID.into(),
                // «normal_installed»: se instala solo, pero el usuario puede desactivarlo o quitarlo.
                json!({ "installation_mode": "normal_installed", "install_url": UBLOCK_URL }),
            );
        }
    }
    serde_json::to_string_pretty(&root).map(|s| s + "\n").map_err(|e| e.to_string())
}

/// Archivos de política a escribir para los navegadores instalados.
/// `read` lee un archivo existente (para fusionar el de Firefox).
pub fn plan_files(
    r: &dyn Runner,
    level: &str,
    ddg: bool,
    ublock: bool,
    read: &dyn Fn(&str) -> Option<String>,
) -> Result<(Vec<FileSpec>, Vec<String>), String> {
    if !crate::firefox::level_ok(level) {
        return Err(format!("Nivel desconocido: {level}"));
    }
    let mut files = Vec::new();
    let mut names = Vec::new();
    for t in &TARGETS {
        if !installed(r, t) {
            continue;
        }
        if t.kind == "firefox" {
            if ddg || ublock {
                let content = firefox_policy_merge(read(t.path).as_deref(), ddg, ublock)?;
                files.push(FileSpec { path: t.path.to_string(), content });
                names.push(t.name.to_string());
            }
        } else {
            let content = serde_json::to_string_pretty(&chromium_policy(level, ddg)).map_err(|e| e.to_string())? + "\n";
            files.push(FileSpec { path: chromium_file_path(t), content });
            names.push(t.name.to_string());
        }
    }
    Ok((files, names))
}

pub fn collect_targets(r: &dyn Runner) -> Vec<BrowserTarget> {
    TARGETS
        .iter()
        .map(|t| {
            let installed = installed(r, t);
            let applied = if t.kind == "firefox" {
                std::fs::read_to_string(t.path)
                    .map(|s| s.contains("DuckDuckGo") || s.contains(UBLOCK_ID))
                    .unwrap_or(false)
            } else {
                Path::new(&chromium_file_path(t)).is_file()
            };
            BrowserTarget {
                name: t.name.into(),
                kind: t.kind.into(),
                policy_path: if t.kind == "firefox" { t.path.into() } else { chromium_file_path(t) },
                installed,
                search_policy_applied: applied,
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sys::mock::MockRunner;

    #[test]
    fn chromium_light_is_optional_and_keeps_level() {
        let l = chromium_policy("balanced+light", false);
        assert_eq!(l["HighEfficiencyModeEnabled"], json!(true));
        assert!(l.get("BlockThirdPartyCookies").is_none());
        assert!(chromium_policy("balanced", false).get("HighEfficiencyModeEnabled").is_none());
        assert_eq!(chromium_policy("maximum+light", false)["BlockThirdPartyCookies"], json!(true));
    }

    #[test]
    fn chromium_levels() {
        let b = chromium_policy("balanced", true);
        assert_eq!(b["MetricsReportingEnabled"], json!(false));
        assert_eq!(b["DefaultSearchProviderName"], json!("DuckDuckGo"));
        assert!(b.get("BlockThirdPartyCookies").is_none(), "equilibrado no debe bloquear cookies de terceros");
        assert!(b.get("SyncDisabled").is_none());
        let m = chromium_policy("maximum", false);
        assert_eq!(m["BlockThirdPartyCookies"], json!(true));
        assert!(m.get("DefaultSearchProviderName").is_none());
        // La política renombrada: nunca la vieja.
        assert!(b.get("WebRtcIPHandlingPolicy").is_none() && b.get("WebRtcIPHandling").is_some());
    }

    #[test]
    fn firefox_merge_preserves_existing_policies() {
        let existing = r#"{"policies":{"DisableAppUpdate":true,"SearchEngines":{"Remove":["Bing"]}}}"#;
        let out = firefox_policy_merge(Some(existing), true, true).unwrap();
        let v: Value = serde_json::from_str(&out).unwrap();
        assert_eq!(v["policies"]["DisableAppUpdate"], json!(true));
        assert_eq!(v["policies"]["SearchEngines"]["Remove"], json!(["Bing"]));
        assert_eq!(v["policies"]["SearchEngines"]["Default"], json!("DuckDuckGo"));
        assert_eq!(v["policies"]["ExtensionSettings"][UBLOCK_ID]["installation_mode"], json!("normal_installed"));
        // sin archivo previo
        let v: Value = serde_json::from_str(&firefox_policy_merge(None, true, false).unwrap()).unwrap();
        assert!(v["policies"].get("ExtensionSettings").is_none());
    }

    #[test]
    fn firefox_merge_refuses_corrupt_file() {
        assert!(firefox_policy_merge(Some("{ esto no es json"), true, true).is_err());
        assert!(firefox_policy_merge(Some("[1,2]"), true, true).is_err());
        assert!(firefox_policy_merge(Some(r#"{"policies": 5}"#), true, true).is_err());
    }

    #[test]
    fn plan_only_for_installed_browsers() {
        let r = MockRunner::new();
        r.on("firefox", "");
        r.on("chromium-browser", "");
        let (files, names) = plan_files(&r, "balanced", true, true, &|_| None).unwrap();
        assert_eq!(names, vec!["Firefox", "Chromium"]);
        assert!(files.iter().any(|f| f.path == "/etc/firefox/policies/policies.json"));
        assert!(files.iter().any(|f| f.path == "/etc/chromium/policies/managed/silence-privacy.json"));
        assert!(files.iter().all(|f| f.path.starts_with("/etc/")));
        // Sin ddg ni ublock, Firefox no necesita política de sistema.
        let (files, names) = plan_files(&r, "balanced", false, false, &|_| None).unwrap();
        assert_eq!(names, vec!["Chromium"]);
        assert_eq!(files.len(), 1);
        // Nivel inválido
        assert!(plan_files(&r, "todo", true, true, &|_| None).is_err());
        // Ninguno instalado
        let (f, n) = plan_files(&MockRunner::new(), "balanced", true, true, &|_| None).unwrap();
        assert!(f.is_empty() && n.is_empty());
    }
}
