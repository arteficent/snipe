//! Quick smoke test: `cargo run -p snipe-collectors --example scan --release`
fn main() {
    let collectors = snipe_collectors::all();
    snipe_collectors::scan_parallel(&collectors, |out| match out.result {
        Ok(items) => {
            let flagged: Vec<_> = items.iter().filter(|i| i.risk >= snipe_core::risk::UNTRUSTED).collect();
            println!(
                "{:<13} {:>5} items, {:>3} flagged in {:?}",
                out.collector.id(),
                items.len(),
                flagged.len(),
                out.elapsed
            );
            for item in flagged.iter().take(5) {
                println!("    [{:>3}] {} — {}", item.risk, item.name, item.risk_reasons.join("; "));
            }
        }
        Err(e) if out.skipped => println!("{:<13} skipped: {e}", out.collector.id()),
        Err(e) => println!("{:<13} FAILED: {e}", out.collector.id()),
    });
}
