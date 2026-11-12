use silence::{cli, gui, helper};

const HELP: &str = "Silence — privacidad y protección para Linux

Uso:
  silence                 abre la interfaz gráfica
  silence scan [--level basic|strict|paranoid] [--json|--markdown]
  silence check           Guardián: avisa si algo que aplicaste fue deshecho (salida 3)
  silence rules           lista el catálogo de reglas
";

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let code = match args.first().map(String::as_str) {
        Some("--helper") => helper::run(&args[1..]),
        Some("scan") => cli::scan_cmd(&args[1..]),
        Some("check") => cli::check_cmd(),
        Some("rules") => cli::rules_cmd(),
        Some("--version") | Some("-V") => {
            println!("silence {}", env!("CARGO_PKG_VERSION"));
            0
        }
        Some("--help") | Some("-h") => {
            print!("{HELP}");
            0
        }
        _ => gui::run(),
    };
    std::process::exit(code);
}
