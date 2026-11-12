//! Ejecución de comandos del sistema detrás de un trait, para poder probar todo con mocks.

use std::io::Read;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

#[derive(Debug, Clone, Default)]
pub struct CmdOut {
    pub ok: bool,
    pub code: Option<i32>,
    pub stdout: String,
    pub stderr: String,
    /// El programa no existe.
    pub missing: bool,
    pub timed_out: bool,
}

pub trait Runner: Send + Sync {
    fn run(&self, prog: &str, args: &[&str]) -> CmdOut;
    fn exists(&self, prog: &str) -> bool;

    /// Atajo: stdout si salió bien.
    fn out(&self, prog: &str, args: &[&str]) -> Option<String> {
        let o = self.run(prog, args);
        if o.ok { Some(o.stdout) } else { None }
    }
}

pub struct RealRunner {
    pub timeout: Duration,
}

impl Default for RealRunner {
    fn default() -> Self {
        RealRunner { timeout: Duration::from_secs(8) }
    }
}

const EXTRA_BIN_DIRS: [&str; 4] = ["/usr/sbin", "/usr/bin", "/sbin", "/bin"];

fn find_in_path(prog: &str) -> Option<std::path::PathBuf> {
    use std::os::unix::fs::PermissionsExt;
    if prog.contains('/') {
        let p = std::path::PathBuf::from(prog);
        return p.is_file().then_some(p);
    }
    let path = std::env::var("PATH").unwrap_or_default();
    path.split(':')
        .chain(EXTRA_BIN_DIRS)
        .map(|d| std::path::Path::new(d).join(prog))
        .find(|p| p.metadata().map(|m| m.is_file() && m.permissions().mode() & 0o111 != 0).unwrap_or(false))
}

impl Runner for RealRunner {
    fn exists(&self, prog: &str) -> bool {
        find_in_path(prog).is_some()
    }

    fn run(&self, prog: &str, args: &[&str]) -> CmdOut {
        let Some(path) = find_in_path(prog) else {
            return CmdOut { missing: true, stderr: format!("{prog}: no encontrado"), ..Default::default() };
        };
        let mut child = match Command::new(path)
            .args(args)
            .env("LC_ALL", "C")
            .env("LANG", "C")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
        {
            Ok(c) => c,
            Err(e) => return CmdOut { stderr: e.to_string(), ..Default::default() },
        };
        let mut so = child.stdout.take().expect("stdout piped");
        let mut se = child.stderr.take().expect("stderr piped");
        let h_out = std::thread::spawn(move || {
            let mut b = Vec::new();
            let _ = so.read_to_end(&mut b);
            b
        });
        let h_err = std::thread::spawn(move || {
            let mut b = Vec::new();
            let _ = se.read_to_end(&mut b);
            b
        });
        let start = Instant::now();
        let mut timed_out = false;
        let status = loop {
            match child.try_wait() {
                Ok(Some(st)) => break Some(st),
                Ok(None) => {
                    if start.elapsed() > self.timeout {
                        let _ = child.kill();
                        let _ = child.wait();
                        timed_out = true;
                        break None;
                    }
                    std::thread::sleep(Duration::from_millis(5));
                }
                Err(_) => break None,
            }
        };
        let stdout = String::from_utf8_lossy(&h_out.join().unwrap_or_default()).into_owned();
        let stderr = String::from_utf8_lossy(&h_err.join().unwrap_or_default()).into_owned();
        CmdOut {
            ok: status.map(|s| s.success()).unwrap_or(false),
            code: status.and_then(|s| s.code()),
            stdout,
            stderr,
            missing: false,
            timed_out,
        }
    }
}

#[cfg(test)]
pub mod mock {
    use super::*;
    use std::collections::HashMap;
    use std::sync::Mutex;

    /// Runner de pruebas: respuestas enlatadas por "prog arg1 arg2" y registro de llamadas.
    #[derive(Default)]
    pub struct MockRunner {
        pub responses: Mutex<HashMap<String, CmdOut>>,
        pub calls: Mutex<Vec<String>>,
        pub fail_prefixes: Mutex<Vec<String>>,
    }

    impl MockRunner {
        pub fn new() -> Self {
            Self::default()
        }
        pub fn on(&self, cmd: &str, stdout: &str) -> &Self {
            self.responses
                .lock()
                .unwrap()
                .insert(cmd.to_string(), CmdOut { ok: true, code: Some(0), stdout: stdout.into(), ..Default::default() });
            self
        }
        pub fn fail_on(&self, prefix: &str) {
            self.fail_prefixes.lock().unwrap().push(prefix.to_string());
        }
        pub fn calls(&self) -> Vec<String> {
            self.calls.lock().unwrap().clone()
        }
    }

    impl Runner for MockRunner {
        fn exists(&self, prog: &str) -> bool {
            self.responses.lock().unwrap().keys().any(|k| k.split(' ').next() == Some(prog))
        }
        fn run(&self, prog: &str, args: &[&str]) -> CmdOut {
            let key = if args.is_empty() { prog.to_string() } else { format!("{prog} {}", args.join(" ")) };
            self.calls.lock().unwrap().push(key.clone());
            if self.fail_prefixes.lock().unwrap().iter().any(|p| key.starts_with(p)) {
                return CmdOut { ok: false, code: Some(1), stderr: "simulated failure".into(), ..Default::default() };
            }
            match self.responses.lock().unwrap().get(&key) {
                Some(o) => o.clone(),
                // Por defecto los comandos "de escritura" (systemctl, sysctl -w…) salen bien y sin salida.
                None => CmdOut { ok: true, code: Some(0), ..Default::default() },
            }
        }
    }
}
