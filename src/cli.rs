//! Línea de comandos: `silence scan`, `silence check` (Guardián), `silence rules`.

use crate::learn::Learned;
use crate::model::*;
use crate::sys::{RealRunner, Runner};

fn scan(level: Level) -> (Vec<Rule>, Snapshot, Report) {
    let rules = crate::rules::load().expect("catálogo de reglas inválido");
    let snap = crate::collect::collect(&RealRunner::default(), &rules);
    let learned = Learned::load();
    let report = crate::engine::evaluate(&rules, &snap, level, &learned);
    (rules, snap, report)
}

fn parse_level(args: &[String]) -> Level {
    args.windows(2)
        .find(|w| w[0] == "--level")
        .and_then(|w| Level::from_id(&w[1]))
        .unwrap_or_else(|| Learned::load().level.unwrap_or(Level::Basic))
}

pub fn scan_cmd(args: &[String]) -> i32 {
    let level = parse_level(args);
    let (_, snap, report) = scan(level);
    if args.iter().any(|a| a == "--json") {
        println!("{}", serde_json::to_string_pretty(&report).unwrap_or_default());
        return 0;
    }
    if args.iter().any(|a| a == "--markdown") {
        println!("{}", crate::report::markdown(&report, &snap, !args.iter().any(|a| a == "--no-redact")));
        return 0;
    }
    println!("Silence · {} · perfil {} · puntaje {}/100\n", snap.info.distro_name, level.label(), report.score);
    for f in report.todo() {
        println!("[{:<5}] [{}] {}", f.rule.severity.label(), f.safety.label(), f.rule.title);
        for o in &f.observed {
            println!("         · {o}");
        }
        if let Some(e) = &f.evidence {
            println!("         ↳ {}", e.detail);
        }
    }
    println!("\nYa está bien: {} · Ocultas por el perfil: {}", report.ok().count(), report.hidden_by_level);
    for n in &snap.notes {
        println!("Nota: {n}");
    }
    0
}

/// Guardián: avisa si algo aplicado fue deshecho. Código de salida 3 si hay deriva.
pub fn check_cmd() -> i32 {
    let level = Learned::load().level.unwrap_or(Level::Basic);
    let (_, snap, report) = scan(level);
    let drift = crate::report::drift(&report, &snap, &crate::ops::history());
    if drift.is_empty() {
        println!("Todo en orden: nada de lo que aplicaste fue deshecho.");
        return 0;
    }
    for d in &drift {
        println!("• {d}");
    }
    let r = RealRunner::default();
    if r.exists("notify-send") {
        let _ = r.run("notify-send", &["-a", "Silence", "Silence: cambios deshechos", &drift.join("\n")]);
    }
    3
}

pub fn rules_cmd() -> i32 {
    let rules = crate::rules::load().expect("catálogo inválido");
    for r in &rules {
        println!("{:<34} {:<9} {:<5} {}", r.id, r.level.label(), r.severity.label(), r.title);
    }
    println!("\n{} reglas.", rules.len());
    0
}
