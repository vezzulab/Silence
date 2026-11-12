//! Exportación del reporte (con redacción de datos personales) y detección de «deriva» (Guardián).

use crate::apply::JournalEntry;
use crate::model::*;
use crate::tools;
use regex::Regex;

/// Sustituye nombre de usuario, hostname, IPs y MACs por marcadores.
pub fn redact(text: &str, snap: &Snapshot) -> String {
    let mut s = text.to_string();
    for (needle, rep) in [(&snap.info.user, "<usuario>"), (&snap.info.hostname, "<equipo>")] {
        if needle.len() >= 3 {
            s = s.replace(needle.as_str(), rep);
        }
    }
    let mac = Regex::new(r"(?i)\b([0-9a-f]{2}:){5}[0-9a-f]{2}\b").unwrap();
    let ip4 = Regex::new(r"\b\d{1,3}(\.\d{1,3}){3}\b").unwrap();
    s = mac.replace_all(&s, "<mac>").into_owned();
    // Se conservan las IPs de los proveedores DNS públicos que Silence ofrece (no son datos tuyos).
    let known: Vec<&str> = tools::DNS_PROVIDERS.iter().flat_map(|p| p.ips.iter().copied()).collect();
    ip4.replace_all(&s, |c: &regex::Captures| {
        let ip = c[0].to_string();
        if known.contains(&ip.as_str()) || ip == "0.0.0.0" || ip.starts_with("127.") { ip } else { "<ip>".to_string() }
    })
    .into_owned()
}

pub fn markdown(report: &Report, snap: &Snapshot, redact_personal: bool) -> String {
    let mut m = String::new();
    m.push_str("# Reporte de Silence\n\n");
    m.push_str(&format!("- Sistema: {} · kernel {}\n", snap.info.distro_name, snap.info.kernel));
    m.push_str(&format!("- Escritorio: {} ({})\n", snap.info.desktop, snap.info.session_type));
    m.push_str(&format!("- Perfil: {} · Puntaje de exposición: **{}/100** (heurístico)\n\n", report.level.map(Level::label).unwrap_or("-"), report.score));
    m.push_str("## Pendiente\n\n");
    for f in report.todo() {
        m.push_str(&format!("### {} — {} ({})\n\n", f.rule.title, f.rule.severity.label(), f.safety.label()));
        m.push_str(&format!("{}\n\n**Por qué importa:** {}\n\n**Qué se rompe si lo cambias:** {}\n\n", f.rule.what, f.rule.why, f.rule.breaks));
        for o in &f.observed {
            m.push_str(&format!("- Detectado: {o}\n"));
        }
        if let Some(e) = &f.evidence {
            m.push_str(&format!("- Evidencia de uso: {}\n", e.detail));
        }
        m.push_str(&format!("\nCómo arreglarlo:\n\n```\n{}\n```\n\n", f.rule.fix.preview().join("\n")));
    }
    m.push_str("## Ya está bien\n\n");
    for f in report.ok() {
        m.push_str(&format!("- {}\n", f.rule.title));
    }
    if !snap.notes.is_empty() {
        m.push_str("\n## Límites de este escaneo\n\n");
        for n in &snap.notes {
            m.push_str(&format!("- {n}\n"));
        }
    }
    if redact_personal { redact(&m, snap) } else { m }
}

/// Cambios que aplicaste y que el sistema ya no refleja (p. ej., una actualización los deshizo).
pub fn drift(report: &Report, snap: &Snapshot, history: &[JournalEntry]) -> Vec<String> {
    let mut out = Vec::new();
    for e in history.iter().filter(|e| !e.reverted) {
        if let Some(f) = report.findings.iter().find(|f| f.rule.id == e.key) {
            if f.status == Status::Todo {
                out.push(format!("«{}» fue aplicado pero vuelve a detectarse como pendiente.", f.rule.title));
            }
        }
        match e.key.as_str() {
            tools::KEY_IPV6 if !tools::ipv6_off(snap) => out.push("IPv6 estaba apagado por Silence pero vuelve a estar activo.".into()),
            tools::KEY_DNS if tools::provider_in_use(&snap.dns.servers).is_none() => {
                out.push("El DNS privado ya no es el que usa el sistema (¿una red nueva o una actualización?).".into())
            }
            tools::KEY_IDENTITY if e.undo.iter().any(|u| matches!(u, crate::apply::Undo::Hostname { .. })) && !tools::hostname_is_disguised(&snap.info.hostname) => {
                out.push("El nombre de equipo estilo Windows ya no está activo.".into())
            }
            _ => {}
        }
    }
    out.sort();
    out.dedup();
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn snap() -> Snapshot {
        let mut s = Snapshot::default();
        s.info.user = "maria".into();
        s.info.hostname = "maria-laptop".into();
        s
    }

    #[test]
    fn redaction_hides_personal_data_but_keeps_public_dns() {
        let r = redact("maria en maria-laptop, mac aa:bb:cc:dd:ee:ff, ip 192.168.1.50, dns 9.9.9.9, lo 127.0.0.1", &snap());
        assert!(!r.contains("maria") && !r.contains("aa:bb") && !r.contains("192.168"));
        assert!(r.contains("9.9.9.9") && r.contains("127.0.0.1"));
        assert!(r.contains("<usuario>") && r.contains("<mac>") && r.contains("<ip>"));
    }

    #[test]
    fn drift_detects_undone_changes() {
        use crate::apply::{JournalEntry, Scope};
        let entry = |key: &str| JournalEntry { id: 1, ts: 1, key: key.into(), title: "t".into(), scope: Scope::Root, undo: vec![], reverted: false, reverted_ts: None, notes: vec![] };
        let mut s = snap();
        s.sysctl.insert("net.ipv6.conf.all.disable_ipv6".into(), "0".into());
        let d = drift(&Report::default(), &s, &[entry(tools::KEY_IPV6)]);
        assert!(d.iter().any(|x| x.contains("IPv6")));
        s.sysctl.insert("net.ipv6.conf.all.disable_ipv6".into(), "1".into());
        assert!(drift(&Report::default(), &s, &[entry(tools::KEY_IPV6)]).is_empty());
        // Un cambio ya revertido nunca es deriva.
        let mut e = entry(tools::KEY_IPV6);
        e.reverted = true;
        s.sysctl.insert("net.ipv6.conf.all.disable_ipv6".into(), "0".into());
        assert!(drift(&Report::default(), &s, &[e]).is_empty());
    }
}
