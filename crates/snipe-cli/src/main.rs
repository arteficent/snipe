//! Headless Snipe: scan, search, export and dry-run plans/leftover scans.

use snipe_engine::{Engine, ScanEvent, export, traces, uninstall};
use std::process::ExitCode;

const USAGE: &str = "\
Usage: snipe-cli <command>

  scan                         Scan and print a summary per collector
  list [text]                  List items (optionally filtered) with their ids
  export --format csv|json --out <file>
  plan <id>                    Show the uninstall plan for an item (no changes)
  leftovers <id>               Dry-run leftover scan for an item (no changes)
  threats [min-score]          List untrusted / suspicious items (default score >= 40)
  --version                    Print the version
";

fn scan(engine: &mut Engine, verbose: bool) {
    engine.scan(&mut |event| {
        if !verbose {
            return;
        }
        match event {
            ScanEvent::Batch { collector, items, elapsed_ms } => {
                println!("{collector:<13} {:>6} items  {elapsed_ms:>6} ms", items.len())
            }
            ScanEvent::Failed { collector, error, .. } => println!("{collector:<13} {error}"),
            ScanEvent::Finished { total, elapsed_ms } => println!("{total} items in {elapsed_ms} ms"),
            ScanEvent::Started { elevated, .. } => {
                println!("Scanning ({})", if elevated { "administrator" } else { "standard user" })
            }
        }
    });
}

fn run(args: &[String]) -> Result<(), String> {
    let mut engine = Engine::new();
    match args.first().map(String::as_str) {
        Some("--version" | "-V" | "version") => println!("snipe-cli {}", env!("CARGO_PKG_VERSION")),
        Some("scan") => scan(&mut engine, true),
        Some("list") => {
            scan(&mut engine, false);
            let needle = args.get(1).map(|s| s.to_lowercase()).unwrap_or_default();
            let mut items = engine.items();
            items.sort_by_key(|i| i.name.to_lowercase());
            for i in items.iter().filter(|i| i.name.to_lowercase().contains(&needle)) {
                println!("{}  {:<10} {:<9} {}  {}", i.id, i.kind.as_str(), format!("{:?}", i.protection), i.name, i.version.as_deref().unwrap_or(""));
            }
        }
        Some("export") => {
            let get = |flag: &str| args.iter().position(|a| a == flag).and_then(|p| args.get(p + 1)).cloned();
            let format = get("--format").unwrap_or_else(|| "csv".into());
            let out = get("--out").ok_or("--out <file> is required")?;
            scan(&mut engine, false);
            let items = engine.items();
            let text = match format.as_str() {
                "csv" => export::to_csv(&items),
                "json" => export::to_json(&items),
                _ => return Err("format must be csv or json".into()),
            };
            std::fs::write(&out, text).map_err(|e| e.to_string())?;
            println!("Wrote {} items to {out}", items.len());
        }
        Some("plan") => {
            let id = args.get(1).ok_or("plan <id>")?;
            scan(&mut engine, false);
            let item = engine.get(id).ok_or("unknown id")?;
            println!("{}", serde_json::to_string_pretty(&uninstall::plan(item)).map_err(|e| e.to_string())?);
        }
        Some("leftovers") => {
            let id = args.get(1).ok_or("leftovers <id>")?;
            scan(&mut engine, false);
            let item = engine.get(id).ok_or("unknown id")?.clone();
            for l in traces::find(&item, &engine.items()) {
                println!("{:>3} {} {}  ({})", l.score, if l.preselected { "[x]" } else { "[ ]" }, l.display, l.reasons.join("; "));
            }
        }
        Some("threats") => {
            let min: u8 = args.get(1).and_then(|s| s.parse().ok()).unwrap_or(snipe_core::risk::UNTRUSTED);
            scan(&mut engine, false);
            let mut items: Vec<_> = engine.items().into_iter().filter(|i| i.risk >= min).collect();
            items.sort_by_key(|i| std::cmp::Reverse(i.risk));
            for i in &items {
                println!("{:>3}  {}  {:<9} {}  [{}]", i.risk, i.id, i.kind.as_str(), i.name, i.executable.as_deref().unwrap_or(""));
                println!("       {}", i.risk_reasons.join("; "));
            }
            println!("{} item(s) with risk >= {min}", items.len());
        }
        _ => return Err(USAGE.into()),
    }
    Ok(())
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match run(&args) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("{e}");
            ExitCode::FAILURE
        }
    }
}
