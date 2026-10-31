// Hide the console window in release builds.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod commands;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.get(1).map(String::as_str) == Some("--broker") {
        let pipe = args.get(2).cloned().unwrap_or_default();
        let pid = args.get(3).and_then(|p| p.parse().ok()).unwrap_or(0);
        let code = match snipe_engine::broker::serve(&pipe, pid) {
            Ok(()) => 0,
            Err(e) => {
                eprintln!("broker: {e}");
                1
            }
        };
        std::process::exit(code);
    }

    tauri::Builder::default()
        .manage(commands::AppState::default())
        .invoke_handler(tauri::generate_handler![
            commands::load_cache,
            commands::session,
            commands::start_admin,
            commands::scan,
            commands::plan,
            commands::restore_point,
            commands::execute,
            commands::leftovers,
            commands::clean,
            commands::history,
            commands::undo,
            commands::terminate,
            commands::threat,
            commands::defender_scan,
            commands::export_inventory,
            commands::open_location,
        ])
        .run(tauri::generate_context!())
        .expect("error while running Snipe");
}
