//! Punto de entrada del helper que corre como administrador (vía pkexec).
//!
//! Superficie mínima y deliberada: solo acepta ids de reglas del catálogo embebido, una petición
//! de herramienta tipada (JSON → `ToolRequest`) o el número de una entrada del diario. Nunca
//! comandos, rutas ni contenido provenientes de quien lo invoca.

use crate::apply::{Applier, Outcome, Scope};
use crate::sys::RealRunner;
use crate::tools::{self, PlanEnv, ToolRequest};

fn fail(key: &str, msg: impl Into<String>) -> Outcome {
    Outcome { key: key.into(), title: key.into(), ok: false, message: msg.into(), entry_id: None }
}

pub fn run(args: &[String]) -> i32 {
    if unsafe { libc::geteuid() } != 0 {
        eprintln!("Este modo solo funciona con permisos de administrador (lo lanza Silence mediante pkexec).");
        return 2;
    }
    let runner = RealRunner { timeout: std::time::Duration::from_secs(60) };
    let a = Applier::new(&runner);
    let jp = crate::ops::root_journal_path();
    let mut out: Vec<Outcome> = Vec::new();

    match args.first().map(String::as_str) {
        Some("rules") => {
            let rules = match crate::rules::load() {
                Ok(r) => r,
                Err(e) => {
                    println!("{}", serde_json::to_string(&vec![fail("catalog", e)]).unwrap());
                    return 1;
                }
            };
            for id in &args[1..] {
                match crate::rules::find(&rules, id) {
                    None => out.push(fail(id, "Regla desconocida.")),
                    Some(r) if !r.fix.is_auto() || !r.fix.needs_root() => out.push(fail(id, "Esta regla no se aplica como administrador.")),
                    Some(r) => {
                        if let Some(o) = a.run_fixes(&jp, Scope::Root, id, &r.title, std::slice::from_ref(&r.fix)) {
                            out.push(o);
                        }
                    }
                }
            }
        }
        Some("tool") => match args.get(1).map(|j| serde_json::from_str::<ToolRequest>(j)) {
            Some(Ok(req)) => match tools::plan(&req, &PlanEnv::detect(&runner)) {
                Ok(plan) => {
                    if let Some(o) = a.run_fixes(&jp, Scope::Root, plan.key, &plan.title, &plan.fixes) {
                        out.push(o);
                    }
                }
                Err(e) => out.push(fail(req.key(), e)),
            },
            _ => out.push(fail("tool", "Petición de herramienta no válida.")),
        },
        Some("revert") => {
            for id in &args[1..] {
                match id.parse::<u64>() {
                    Ok(n) => out.push(a.revert_entry(&jp, n)),
                    Err(_) => out.push(fail(id, "Identificador no válido.")),
                }
            }
        }
        _ => {
            eprintln!("uso: silence --helper (rules ID… | tool JSON | revert N…)");
            return 2;
        }
    }
    println!("{}", serde_json::to_string(&out).unwrap_or_else(|_| "[]".into()));
    if out.iter().all(|o| o.ok) { 0 } else { 1 }
}
