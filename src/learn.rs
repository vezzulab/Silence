//! Aprendizaje local: recuerda qué aplicaste, qué revertiste y qué ignoraste, y lo usa para
//! no volver a insistirte con lo que ya te dio problemas. Nada sale de tu equipo.

use crate::model::Level;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::PathBuf;

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct RuleHistory {
    pub applied: u32,
    pub reverted: u32,
    pub ignored: bool,
    pub last_applied: Option<i64>,
    pub last_reverted: Option<i64>,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct Learned {
    pub level: Option<Level>,
    /// Muestra las pestañas técnicas (Recomendaciones, Catálogo, Análisis).
    #[serde(default)]
    pub advanced: bool,
    /// Si es true, no se consulta GitHub al abrir la app (por defecto sí se consulta).
    #[serde(default)]
    pub no_update_check: bool,
    pub rules: BTreeMap<String, RuleHistory>,
}

pub fn data_dir() -> PathBuf {
    if let Ok(x) = std::env::var("XDG_DATA_HOME") {
        if !x.is_empty() {
            return PathBuf::from(x).join("silence");
        }
    }
    PathBuf::from(std::env::var("HOME").unwrap_or_else(|_| ".".into())).join(".local/share/silence")
}

impl Learned {
    pub fn path() -> PathBuf {
        data_dir().join("learned.json")
    }

    pub fn load() -> Self {
        std::fs::read_to_string(Self::path())
            .ok()
            .and_then(|t| serde_json::from_str(&t).ok())
            .unwrap_or_default()
    }

    pub fn save(&self) {
        let p = Self::path();
        if let Some(d) = p.parent() {
            let _ = std::fs::create_dir_all(d);
        }
        if let Ok(t) = serde_json::to_string_pretty(self) {
            let _ = std::fs::write(p, t);
        }
    }

    fn entry(&mut self, id: &str) -> &mut RuleHistory {
        self.rules.entry(id.to_string()).or_default()
    }

    pub fn record_applied(&mut self, id: &str, now: i64) {
        let e = self.entry(id);
        e.applied += 1;
        e.last_applied = Some(now);
    }

    pub fn record_reverted(&mut self, id: &str, now: i64) {
        let e = self.entry(id);
        e.reverted += 1;
        e.last_reverted = Some(now);
    }

    pub fn set_ignored(&mut self, id: &str, v: bool) {
        self.entry(id).ignored = v;
    }

    pub fn is_ignored(&self, id: &str) -> bool {
        self.rules.get(id).map(|h| h.ignored).unwrap_or(false)
    }

    pub fn reverted_count(&self, id: &str) -> u32 {
        self.rules.get(id).map(|h| h.reverted).unwrap_or(0)
    }

    pub fn last_reverted(&self, id: &str) -> Option<i64> {
        self.rules.get(id).and_then(|h| h.last_reverted)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn counters() {
        let mut l = Learned::default();
        l.record_applied("a", 1);
        l.record_reverted("a", 2);
        l.set_ignored("b", true);
        assert_eq!(l.reverted_count("a"), 1);
        assert_eq!(l.last_reverted("a"), Some(2));
        assert!(l.is_ignored("b") && !l.is_ignored("a"));
        let j = serde_json::to_string(&l).unwrap();
        let l2: Learned = serde_json::from_str(&j).unwrap();
        assert_eq!(l2.rules["a"].applied, 1);
    }
}
