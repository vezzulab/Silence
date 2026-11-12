//! Operaciones de alto nivel que usan la interfaz y la línea de comandos: aplicar reglas y
//! herramientas (con permisos de administrador solo cuando hace falta, vía pkexec), revertir y
//! consultar el historial.

use crate::apply::{Applier, Journal, JournalEntry, Outcome, Scope};
use crate::model::*;
use crate::sys::{Runner, RealRunner};
use crate::tools::{self, PlanEnv, ToolRequest};
use std::path::{Path, PathBuf};
use std::process::Command;

pub fn user_journal_path() -> PathBuf {
    crate::learn::data_dir().join("journal.json")
}

pub fn root_journal_path() -> PathBuf {
    PathBuf::from(crate::apply::ROOT_JOURNAL)
}

/// Historial combinado (usuario + sistema), más reciente primero.
pub fn history() -> Vec<JournalEntry> {
    let mut v = Journal::load(&user_journal_path()).entries;
    v.extend(Journal::load(&root_journal_path()).entries);
    v.sort_by(|a, b| b.ts.cmp(&a.ts).then(b.id.cmp(&a.id)));
    v
}

pub fn active_keys() -> std::collections::BTreeSet<String> {
    history().into_iter().filter(|e| !e.reverted).map(|e| e.key).collect()
}

fn err_outcome(key: &str, title: &str, msg: impl Into<String>) -> Outcome {
    Outcome { key: key.into(), title: title.into(), ok: false, message: msg.into(), entry_id: None }
}

/// Seguridad: pkexec daría permisos de administrador al binario que se le indique. Si ese binario (o
/// alguna carpeta que lo contiene) pudiera modificarlo tu usuario, cualquier programa tuyo podría
/// reemplazarlo y obtener administrador cuando apruebes un cambio. Por eso solo se acepta una ruta
/// propiedad de root y no escribible por otros.
/// `SILENCE_ALLOW_UNSAFE_HELPER=1` lo omite (solo para desarrollo).
pub fn helper_path_ok(exe: &Path) -> Result<(), String> {
    use std::os::unix::fs::MetadataExt;
    if std::env::var("SILENCE_ALLOW_UNSAFE_HELPER").as_deref() == Ok("1") {
        return Ok(());
    }
    let msg = |p: &Path| {
        format!(
            "Por seguridad, Silence solo pide permisos de administrador cuando está instalado en una ubicación del sistema (propiedad de root y no modificable por tu usuario). «{}» no cumple. Instálalo con: sudo ./packaging/install.sh",
            p.display()
        )
    };
    let real = std::fs::canonicalize(exe).map_err(|e| format!("No se pudo resolver la ruta del programa: {e}"))?;
    let mut cur: Option<&Path> = Some(real.as_path());
    while let Some(p) = cur {
        let m = std::fs::metadata(p).map_err(|e| format!("No se pudo leer {}: {e}", p.display()))?;
        if m.uid() != 0 || m.mode() & 0o022 != 0 {
            return Err(msg(&real));
        }
        cur = p.parent();
    }
    Ok(())
}

/// Ejecuta el helper con pkexec y lee su resultado (JSON en stdout).
pub fn run_helper(exe: &Path, args: &[String]) -> Result<Vec<Outcome>, String> {
    helper_path_ok(exe)?;
    let out = Command::new("pkexec")
        .arg(exe)
        .arg("--helper")
        .args(args)
        .output()
        .map_err(|e| format!("No se pudo pedir permisos de administrador (pkexec): {e}"))?;
    match out.status.code() {
        Some(126) | Some(127) => return Err("Autorización cancelada o denegada.".into()),
        _ => {}
    }
    let stdout = String::from_utf8_lossy(&out.stdout);
    serde_json::from_str::<Vec<Outcome>>(stdout.trim()).map_err(|_| {
        let e = String::from_utf8_lossy(&out.stderr);
        format!("El helper no devolvió un resultado válido. {}", e.trim())
    })
}

pub fn exe_path() -> PathBuf {
    std::env::current_exe().unwrap_or_else(|_| PathBuf::from("silence"))
}

/// Aplica reglas del catálogo. Las acciones de usuario corren aquí; las de administrador, en un
/// único pkexec para pedir la contraseña una sola vez.
pub fn apply_rules(rules: &[Rule], ids: &[String]) -> Vec<Outcome> {
    let runner = RealRunner { timeout: std::time::Duration::from_secs(30) };
    let a = Applier::new(&runner);
    let mut out = Vec::new();
    let mut root_ids = Vec::new();
    for id in ids {
        let Some(rule) = crate::rules::find(rules, id) else {
            out.push(err_outcome(id, id, "Regla desconocida."));
            continue;
        };
        if !rule.fix.is_auto() {
            out.push(err_outcome(id, &rule.title, "Este cambio es manual."));
            continue;
        }
        if rule.fix.needs_root() {
            root_ids.push(id.clone());
        } else if let Some(o) = a.run_fixes(&user_journal_path(), Scope::User, id, &rule.title, std::slice::from_ref(&rule.fix)) {
            out.push(o);
        }
    }
    if !root_ids.is_empty() {
        let mut args = vec!["rules".to_string()];
        args.extend(root_ids.iter().cloned());
        match run_helper(&exe_path(), &args) {
            Ok(mut v) => out.append(&mut v),
            Err(e) => {
                for id in &root_ids {
                    let t = crate::rules::find(rules, id).map(|r| r.title.clone()).unwrap_or_default();
                    out.push(err_outcome(id, &t, e.clone()));
                }
            }
        }
    }
    out
}

/// Aplica una herramienta: la parte de usuario aquí, la de administrador vía pkexec.
pub fn apply_tool(req: &ToolRequest) -> Vec<Outcome> {
    let runner = RealRunner { timeout: std::time::Duration::from_secs(30) };
    let env = PlanEnv::detect(&runner);
    let plan = match tools::plan(req, &env) {
        Ok(p) => p,
        Err(e) => return vec![err_outcome(req.key(), req.key(), e)],
    };
    let a = Applier::new(&runner);
    let mut out = Vec::new();
    if let Some(o) = a.run_fixes(&user_journal_path(), Scope::User, plan.key, &plan.title, &plan.fixes) {
        out.push(o);
    }
    if plan.fixes.iter().any(|f| f.needs_root()) {
        let json = serde_json::to_string(req).unwrap_or_default();
        match run_helper(&exe_path(), &["tool".to_string(), json]) {
            Ok(mut v) => out.append(&mut v),
            Err(e) => out.push(err_outcome(plan.key, &plan.title, e)),
        }
    }
    out
}

/// Revierte una entrada del historial (la de administrador pide permisos).
pub fn revert_entry(e: &JournalEntry) -> Outcome {
    match e.scope {
        Scope::User => {
            let runner = RealRunner { timeout: std::time::Duration::from_secs(30) };
            Applier::new(&runner).revert_entry(&user_journal_path(), e.id)
        }
        Scope::Root => match run_helper(&exe_path(), &["revert".to_string(), e.id.to_string()]) {
            Ok(mut v) if !v.is_empty() => v.remove(0),
            Ok(_) => err_outcome(&e.key, &e.title, "Sin respuesta del helper."),
            Err(m) => err_outcome(&e.key, &e.title, m),
        },
    }
}

/// Revierte todos los cambios activos con esa clave (usuario y administrador).
pub fn revert_key(key: &str) -> Vec<Outcome> {
    let entries: Vec<JournalEntry> = history().into_iter().filter(|e| e.key == key && !e.reverted).collect();
    let (root, user): (Vec<_>, Vec<_>) = entries.into_iter().partition(|e| e.scope == Scope::Root);
    let mut out: Vec<Outcome> = user.iter().map(revert_entry).collect();
    if !root.is_empty() {
        let ids: Vec<String> = root.iter().map(|e| e.id.to_string()).collect();
        let mut args = vec!["revert".to_string()];
        args.extend(ids);
        match run_helper(&exe_path(), &args) {
            Ok(mut v) => out.append(&mut v),
            Err(m) => out.push(err_outcome(key, key, m)),
        }
    }
    out
}

/// Reconecta las redes activas para que apliquen MAC/DNS nuevos (no requiere administrador).
pub fn reconnect_active(profiles: &[NmProfile]) -> Vec<String> {
    let r = RealRunner::default();
    profiles
        .iter()
        .filter(|p| p.active && (p.kind == "802-11-wireless" || p.kind == "802-3-ethernet"))
        .map(|p| {
            let o = r.run("nmcli", &["connection", "up", "uuid", &p.uuid]);
            if o.ok { format!("Reconectado: {}", p.name) } else { format!("No se pudo reconectar {}: {}", p.name, o.stderr.trim()) }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn helper_refuses_user_writable_binaries() {
        let dir = std::env::temp_dir().join(format!("silence-helper-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let fake = dir.join("silence");
        std::fs::write(&fake, "#!/bin/sh\n").unwrap();
        let e = helper_path_ok(&fake).unwrap_err();
        assert!(e.contains("install.sh"), "{e}");
        // Un binario del sistema (root, no escribible) sí se acepta.
        assert!(helper_path_ok(Path::new("/usr/bin/true")).is_ok());
        std::fs::remove_dir_all(dir).ok();
    }
}
