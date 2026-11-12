//! Carga y validación del catálogo de reglas (embebido en el binario).
//!
//! Las reglas son datos, no código: lo único que puede ejecutarse como root son las acciones
//! tipadas de `Fix`, nunca cadenas arbitrarias. `validate` es la barrera que lo garantiza.

use crate::model::*;
use regex::Regex;
use std::collections::BTreeSet;

const FILES: [(&str, &str); 7] = [
    ("telemetry", include_str!("../rules/telemetry.yaml")),
    ("services", include_str!("../rules/services.yaml")),
    ("network", include_str!("../rules/network.yaml")),
    ("storage", include_str!("../rules/storage.yaml")),
    ("desktop", include_str!("../rules/desktop.yaml")),
    ("hardening", include_str!("../rules/hardening.yaml")),
    ("browser", include_str!("../rules/browser.yaml")),
];

pub fn load() -> Result<Vec<Rule>, String> {
    let mut all = Vec::new();
    for (name, text) in FILES {
        let mut v: Vec<Rule> = serde_yaml_ng::from_str(text).map_err(|e| format!("rules/{name}.yaml: {e}"))?;
        all.append(&mut v);
    }
    let errs = validate(&all);
    if errs.is_empty() { Ok(all) } else { Err(errs.join("\n")) }
}

pub fn find<'a>(rules: &'a [Rule], id: &str) -> Option<&'a Rule> {
    rules.iter().find(|r| r.id == id)
}

fn name_ok(s: &str) -> bool {
    Regex::new(r"^[A-Za-z0-9:_.@\-]+$").unwrap().is_match(s)
}

pub fn validate(rules: &[Rule]) -> Vec<String> {
    let mut errs = Vec::new();
    let mut ids = BTreeSet::new();
    let sysctl_key = Regex::new(r"^[a-z0-9_]+(\.[a-z0-9_]+)+$").unwrap();
    let value_ok = Regex::new(r"^[A-Za-z0-9_.\-]+$").unwrap();
    let id_ok = Regex::new(r"^[a-z0-9_]+\.[a-z0-9_]+$").unwrap();
    for r in rules {
        let id = &r.id;
        if !id_ok.is_match(id) {
            errs.push(format!("{id}: id inválido"));
        }
        if !ids.insert(id.clone()) {
            errs.push(format!("{id}: id duplicado"));
        }
        for (k, v) in [("title", &r.title), ("what", &r.what), ("why", &r.why), ("breaks", &r.breaks)] {
            if v.trim().is_empty() {
                errs.push(format!("{id}: falta {k}"));
            }
        }
        for u in &r.applies.units_active {
            if !name_ok(u) {
                errs.push(format!("{id}: unidad inválida en applies: {u}"));
            }
        }
        for h in &r.applies.hardware {
            if !["wifi", "bluetooth", "camera", "modem"].contains(&h.as_str()) {
                errs.push(format!("{id}: hardware desconocido {h}"));
            }
        }
        match &r.detect {
            Detect::Unit { units } => {
                if units.is_empty() || !units.iter().all(|u| name_ok(u)) {
                    errs.push(format!("{id}: detect.units inválido"));
                }
            }
            Detect::Package { names } => {
                if names.is_empty() || !names.iter().all(|n| name_ok(n)) {
                    errs.push(format!("{id}: detect.names inválido"));
                }
            }
            Detect::Sysctl { key, want, .. } => {
                if !sysctl_key.is_match(key) || !value_ok.is_match(want) {
                    errs.push(format!("{id}: detect sysctl inválido"));
                }
            }
            Detect::Gsettings { schema, key, .. } => {
                if !name_ok(schema) || !name_ok(key) {
                    errs.push(format!("{id}: detect gsettings inválido"));
                }
            }
            Detect::Kconfig { file, group, key, .. } => {
                if !name_ok(file) || !name_ok(group) || !name_ok(key) {
                    errs.push(format!("{id}: detect kconfig inválido"));
                }
            }
            Detect::FileRegex { globs, pattern, .. } => {
                if globs.is_empty() {
                    errs.push(format!("{id}: file_regex sin globs"));
                }
                if Regex::new(&format!("(?m){pattern}")).is_err() {
                    errs.push(format!("{id}: regex inválida"));
                }
            }
            Detect::Builtin { name } => {
                if !crate::engine::BUILTINS.contains(&name.as_str()) {
                    errs.push(format!("{id}: builtin desconocido {name}"));
                }
            }
        }
        match &r.fix {
            Fix::DisableUnits { units } => {
                if units.is_empty() || !units.iter().all(|u| name_ok(u)) {
                    errs.push(format!("{id}: fix.units inválido"));
                }
            }
            Fix::Sysctl { settings } => {
                if settings.is_empty() {
                    errs.push(format!("{id}: fix sysctl vacío"));
                }
                for s in settings {
                    if !sysctl_key.is_match(&s.key) || !value_ok.is_match(&s.value) {
                        errs.push(format!("{id}: fix sysctl inválido {}", s.key));
                    }
                }
            }
            Fix::WriteFiles { files, after } => {
                if files.is_empty() {
                    errs.push(format!("{id}: write_files vacío"));
                }
                for f in files {
                    if !f.path.starts_with("/etc/") || f.path.contains("..") || f.path.contains('\0') || f.path.ends_with('/') {
                        errs.push(format!("{id}: ruta no permitida {}", f.path));
                    }
                    if f.content.trim().is_empty() {
                        errs.push(format!("{id}: archivo sin contenido {}", f.path));
                    }
                }
                for a in after {
                    if !name_ok(&a.unit) {
                        errs.push(format!("{id}: unidad inválida en after: {}", a.unit));
                    }
                }
            }
            Fix::Gsettings { schema, key, value } => {
                if !name_ok(schema) || !name_ok(key) || !value_ok.is_match(value) {
                    errs.push(format!("{id}: fix gsettings inválido"));
                }
            }
            Fix::Kwrite { file, group, key, value } => {
                if !name_ok(file) || !name_ok(group) || !name_ok(key) || !value_ok.is_match(value) {
                    errs.push(format!("{id}: fix kwrite inválido"));
                }
            }
            Fix::FirefoxPrivacyPrefs { .. } => {}
            Fix::Firewall { level, allow } => {
                if level != "standard" && level != "strict" {
                    errs.push(format!("{id}: nivel de firewall inválido"));
                }
                if !allow.iter().all(|a| crate::apply::FW_ALLOW.contains(&a.as_str())) {
                    errs.push(format!("{id}: servicio de firewall no permitido"));
                }
            }
            Fix::EnableUnits { .. } | Fix::InstallPackages { .. } | Fix::UsbguardPolicy {} | Fix::NmProfiles { .. } | Fix::NmProfilesNamed { .. } | Fix::FlatpakOverride { .. } | Fix::SetHostname { .. } | Fix::BrowserPolicies { .. } => {
                errs.push(format!("{id}: esta acción solo puede usarse desde herramientas internas"));
            }
            Fix::Manual { steps } => {
                if steps.is_empty() {
                    errs.push(format!("{id}: manual sin pasos"));
                }
            }
        }
    }
    errs
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn catalog_loads_and_validates() {
        let rules = load().unwrap_or_else(|e| panic!("catálogo inválido:\n{e}"));
        assert!(rules.len() >= 30, "solo {} reglas", rules.len());
    }

    #[test]
    fn every_category_and_level_is_used() {
        let rules = load().unwrap();
        for c in Category::ALL {
            assert!(rules.iter().any(|r| r.category == c), "sin reglas en {c:?}");
        }
        for l in Level::ALL {
            assert!(rules.iter().any(|r| r.level == l), "sin reglas de nivel {l:?}");
        }
    }

    #[test]
    fn validation_rejects_dangerous_paths_and_units() {
        let mut rules = load().unwrap();
        let mut bad = rules.iter().find(|r| matches!(r.fix, Fix::WriteFiles { .. })).unwrap().clone();
        bad.id = "x.bad".into();
        bad.fix = Fix::WriteFiles {
            files: vec![FileSpec { path: "/etc/../root/.ssh/authorized_keys".into(), content: "x".into() }],
            after: vec![],
        };
        rules.push(bad);
        assert!(validate(&rules).iter().any(|e| e.contains("ruta no permitida")));

        let mut rules = load().unwrap();
        let mut bad = rules.iter().find(|r| matches!(r.fix, Fix::DisableUnits { .. })).unwrap().clone();
        bad.id = "x.bad2".into();
        bad.fix = Fix::DisableUnits { units: vec!["a.service; rm -rf /".into()] };
        rules.push(bad);
        assert!(validate(&rules).iter().any(|e| e.contains("fix.units")));
    }

    #[test]
    fn auto_fixes_never_target_files_outside_etc() {
        for r in load().unwrap() {
            if let Fix::WriteFiles { files, .. } = &r.fix {
                assert!(files.iter().all(|f| f.path.starts_with("/etc/")));
            }
        }
    }
}
