// Mock Tauri IPC with fictional demo data, used to take README / website screenshots in a plain
// browser (no real system data is shown). See README "Screenshots".
(() => {
  const callbacks = new Map();
  let nextCallback = 1;
  let nextId = 1;
  const USER = "DESKTOP-DEMO\\alex";
  const HOME = "C:\\Users\\alex";

  const trusted = (signer) => ({ status: "trusted", signer });
  const unsigned = { status: "unsigned", signer: null };

  function item(kind, name, o = {}) {
    const id = (nextId++).toString(16).padStart(16, "0");
    return {
      id,
      kind,
      name,
      version: o.version ?? null,
      publisher: o.publisher ?? null,
      installLocation: o.location ?? null,
      installDate: o.date ?? null,
      sizeBytes: o.size ?? null,
      scope: o.user ? "user" : "machine",
      user: o.user ? USER : (o.account ?? null),
      arch: o.arch ?? "x64",
      protection: o.protection ?? "removable",
      hidden: o.hidden ?? false,
      manager: o.manager ?? null,
      uninstall: o.uninstall ?? [],
      registry: null,
      executable: o.exe ?? null,
      signature: o.signature ?? null,
      risk: o.risk ?? 0,
      riskReasons: o.reasons ?? [],
      source: o.source ?? `demo:${id}`,
      details: o.details ?? [],
    };
  }

  const MB = 1024 * 1024;
  const GB = 1024 * MB;
  const cmd = (command) => [{ type: "command", command, quiet: false }];

  const items = [
    item("win32", "Mozilla Firefox (x64 en-US)", {
      version: "131.0.3", publisher: "Mozilla", location: "C:\\Program Files\\Mozilla Firefox", date: "2026-10-02",
      size: 262 * MB, exe: "C:\\Program Files\\Mozilla Firefox\\firefox.exe", signature: trusted("Mozilla Corporation"),
      uninstall: cmd('"C:\\Program Files\\Mozilla Firefox\\uninstall\\helper.exe"'),
      details: [["Website", "https://www.mozilla.org"], ["Registry key", "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\Mozilla Firefox 131.0.3 (x64 en-US)"]],
    }),
    item("win32", "Microsoft Visual Studio Code (User)", {
      version: "1.105.1", publisher: "Microsoft Corporation", location: `${HOME}\\AppData\\Local\\Programs\\Microsoft VS Code`,
      date: "2026-10-18", size: 412 * MB, user: true, exe: `${HOME}\\AppData\\Local\\Programs\\Microsoft VS Code\\Code.exe`,
      signature: trusted("Microsoft Corporation"), uninstall: cmd(`"${HOME}\\AppData\\Local\\Programs\\Microsoft VS Code\\unins000.exe"`),
    }),
    item("win32", "7-Zip 24.08 (x64)", {
      version: "24.08", publisher: "Igor Pavlov", location: "C:\\Program Files\\7-Zip", date: "2026-08-14", size: 5.8 * MB,
      exe: "C:\\Program Files\\7-Zip\\7zFM.exe", signature: unsigned, risk: 35, reasons: ["not digitally signed"],
      uninstall: cmd('"C:\\Program Files\\7-Zip\\Uninstall.exe"'),
    }),
    item("win32", "Git", {
      version: "2.51.0", publisher: "The Git Development Community", location: "C:\\Program Files\\Git", date: "2026-09-21",
      size: 338 * MB, exe: "C:\\Program Files\\Git\\git-bash.exe", signature: trusted("Johannes Schindelin"),
      uninstall: cmd('"C:\\Program Files\\Git\\unins000.exe"'),
    }),
    item("msi", "Node.js", {
      version: "22.11.0", publisher: "Node.js Foundation", location: "C:\\Program Files\\nodejs", date: "2026-09-02", size: 98 * MB,
      exe: "C:\\Program Files\\nodejs\\node.exe", signature: trusted("OpenJS Foundation"),
      uninstall: [{ type: "msi", productCode: "{4F2A1C3E-9D7B-4E51-A0C2-7B6D3E8F1A20}" }],
    }),
    item("msi", "Microsoft Visual C++ 2015-2022 Redistributable (x64) - 14.44.35211", {
      version: "14.44.35211.0", publisher: "Microsoft Corporation", date: "2026-07-30", size: 20 * MB, protection: "shared",
      uninstall: [{ type: "msi", productCode: "{1D8E6291-B0D5-35EC-8441-6616F567A0F7}" }],
    }),
    item("win32", "Python 3.13.2 (64-bit)", {
      version: "3.13.2", publisher: "Python Software Foundation", location: `${HOME}\\AppData\\Local\\Programs\\Python\\Python313`,
      date: "2026-06-11", size: 104 * MB, user: true, exe: `${HOME}\\AppData\\Local\\Programs\\Python\\Python313\\python.exe`,
      signature: trusted("Python Software Foundation"), uninstall: cmd("MsiExec.exe /X{8B1E4C0D-3A6F-4D2E-9F51-0C7A2B3E4D51}"),
    }),
    item("win32", "Docker Desktop", {
      version: "4.48.0", publisher: "Docker Inc.", location: "C:\\Program Files\\Docker\\Docker", date: "2026-10-09", size: 1.9 * GB,
      exe: "C:\\Program Files\\Docker\\Docker\\Docker Desktop.exe", signature: trusted("Docker Inc"),
      uninstall: cmd('"C:\\Program Files\\Docker\\Docker\\Docker Desktop Installer.exe" uninstall'),
    }),
    item("win32", "Spotify", {
      version: "1.2.74.477", publisher: "Spotify AB", location: `${HOME}\\AppData\\Roaming\\Spotify`, date: "2026-10-20", size: 389 * MB,
      user: true, exe: `${HOME}\\AppData\\Roaming\\Spotify\\Spotify.exe`, signature: trusted("Spotify AB"),
      uninstall: cmd(`"${HOME}\\AppData\\Roaming\\Spotify\\Spotify.exe" /uninstall`),
    }),
    item("win32", "VLC media player", {
      version: "3.0.21", publisher: "VideoLAN", location: "C:\\Program Files\\VideoLAN\\VLC", date: "2026-05-27", size: 168 * MB,
      exe: "C:\\Program Files\\VideoLAN\\VLC\\vlc.exe", signature: trusted("VideoLAN"), uninstall: cmd('"C:\\Program Files\\VideoLAN\\VLC\\uninstall.exe"'),
    }),
    item("win32", "Notepad++ (64-bit x64)", {
      version: "8.8.5", publisher: "Notepad++ Team", location: "C:\\Program Files\\Notepad++", date: "2026-09-30", size: 16 * MB,
      exe: "C:\\Program Files\\Notepad++\\notepad++.exe", signature: trusted("Notepad++"), uninstall: cmd('"C:\\Program Files\\Notepad++\\uninstall.exe"'),
    }),
    item("win32", "PDF Converter Pro", {
      version: "2.1.0", publisher: "PDFTools Ltd", location: `${HOME}\\AppData\\Local\\Programs\\PDF Converter Pro`, date: "2026-10-27",
      size: 74 * MB, user: true, exe: `${HOME}\\AppData\\Local\\Programs\\PDF Converter Pro\\pdfconv.exe`, signature: unsigned, risk: 50,
      reasons: ["not digitally signed", "runs from a user-writable folder"],
      uninstall: cmd(`"${HOME}\\AppData\\Local\\Programs\\PDF Converter Pro\\uninst.exe"`),
    }),
    item("appx", "Windows Terminal", { version: "1.23.12811.0", publisher: "Microsoft Corporation", user: true, date: "2026-10-12", signature: trusted("Microsoft Corporation"), uninstall: [{ type: "appx", packageFullName: "Microsoft.WindowsTerminal_1.23.12811.0_x64__8wekyb3d8bbwe" }] }),
    item("appx", "WhatsApp", { version: "2.2541.4.0", publisher: "WhatsApp Inc.", user: true, date: "2026-10-22", signature: trusted("WhatsApp Inc."), uninstall: [{ type: "appx", packageFullName: "5319275A.WhatsAppDesktop_2.2541.4.0_x64__cv1g1gvanyjgm" }] }),
    item("appx", "Calculator", { version: "11.2508.4.0", publisher: "Microsoft Corporation", user: true, protection: "system", signature: trusted("Microsoft Corporation"), uninstall: [{ type: "appx", packageFullName: "Microsoft.WindowsCalculator_11.2508.4.0_x64__8wekyb3d8bbwe" }] }),
    item("feature", "Microsoft-Windows-Subsystem-Linux", { publisher: "Microsoft Corporation", protection: "system", uninstall: [{ type: "feature", name: "Microsoft-Windows-Subsystem-Linux" }] }),
    item("feature", "VirtualMachinePlatform", { publisher: "Microsoft Corporation", protection: "system", uninstall: [{ type: "feature", name: "VirtualMachinePlatform" }] }),
    item("update", "Package_for_KB5066835", { version: "26100.6899.1.11", publisher: "Microsoft Corporation", date: "2026-10-14", protection: "system", uninstall: [{ type: "update", package: "Package_for_KB5066835~31bf3856ad364e35~amd64~~26100.6899.1.11" }] }),
    item("driver", "NVIDIA GeForce RTX 4060 Laptop GPU (oem42.inf)", { version: "32.0.15.8157", publisher: "NVIDIA", date: "2026-09-18", protection: "shared", uninstall: [{ type: "driver", inf: "oem42.inf" }] }),
    item("service", "Docker Desktop Service", { publisher: "Docker Inc.", account: "LocalSystem", exe: "C:\\Program Files\\Docker\\Docker\\com.docker.service", signature: trusted("Docker Inc"), uninstall: [{ type: "service", name: "com.docker.service" }], details: [["State", "Running"], ["Start type", "Automatic"]] }),
    item("service", "Windows Update", { account: "LocalSystem", protection: "locked", hidden: true, exe: "C:\\Windows\\system32\\wuaueng.dll", signature: trusted("Microsoft Windows"), details: [["State", "Running"], ["Service name", "wuauserv"]] }),
    item("service", "Update Helper Service", {
      account: "LocalSystem", exe: "C:\\ProgramData\\SysCache\\svchost.exe", signature: unsigned, risk: 95,
      reasons: ["not digitally signed", "uses the name of a Windows system file outside the Windows folder", "runs from a user-writable folder", "the file is hidden", "starts automatically"],
      uninstall: [{ type: "service", name: "UpdHelperSvc" }], details: [["State", "Running"], ["Start type", "Automatic"], ["Image path", "C:\\ProgramData\\SysCache\\svchost.exe -k netsvc"]],
    }),
    item("task", "SyncCheck", {
      user: true, exe: "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", signature: trusted("Microsoft Windows"), risk: 55,
      reasons: ["runs an encoded PowerShell command", "hides its window"], uninstall: [{ type: "task", path: "\\SyncCheck" }],
      details: [["Action", "powershell.exe -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQA..."], ["State", "Ready"]],
    }),
    item("task", "Adobe Acrobat Update Task", { publisher: "Adobe Inc.", exe: "C:\\Program Files (x86)\\Common Files\\Adobe\\ARM\\1.0\\AdobeARM.exe", signature: trusted("Adobe Inc."), uninstall: [{ type: "task", path: "\\Adobe Acrobat Update Task" }] }),
    item("startup", "Spotify", { user: true, exe: `${HOME}\\AppData\\Roaming\\Spotify\\Spotify.exe`, signature: trusted("Spotify AB"), uninstall: [{ type: "registryValue", key: { key: "HKU\\S-1-5-21-1001\\Software\\Microsoft\\Windows\\CurrentVersion\\Run", wow32: false }, value: "Spotify" }] }),
    item("startup", "Windows Defender notification", { protection: "system", exe: "C:\\Windows\\system32\\SecurityHealthSystray.exe", signature: trusted("Microsoft Windows") }),
    item("startup", "svchost", {
      user: true, exe: `${HOME}\\AppData\\Roaming\\SysUpd\\svchost.exe`, signature: unsigned, risk: 100,
      reasons: ["not digitally signed", "uses the name of a Windows system file outside the Windows folder", "runs from a user-writable folder", "the file is hidden", "starts automatically"],
      uninstall: [{ type: "registryValue", key: { key: "HKU\\S-1-5-21-1001\\Software\\Microsoft\\Windows\\CurrentVersion\\Run", wow32: false }, value: "svchost" }],
      details: [["Command", `${HOME}\\AppData\\Roaming\\SysUpd\\svchost.exe --silent`], ["Enabled", "yes"]],
    }),
    item("process", "firefox.exe", { user: true, exe: "C:\\Program Files\\Mozilla Firefox\\firefox.exe", location: "C:\\Program Files\\Mozilla Firefox", signature: trusted("Mozilla Corporation"), details: [["PID", "8420"]] }),
    item("process", "Code.exe", { user: true, exe: `${HOME}\\AppData\\Local\\Programs\\Microsoft VS Code\\Code.exe`, signature: trusted("Microsoft Corporation"), details: [["PID", "11032"]] }),
    item("process", "explorer.exe", { user: true, protection: "system", hidden: true, exe: "C:\\Windows\\explorer.exe", signature: trusted("Microsoft Windows"), details: [["PID", "5144"]] }),
    item("process", "svchost.exe", { account: "NT AUTHORITY\\SYSTEM", protection: "locked", hidden: true, exe: "C:\\Windows\\System32\\svchost.exe", signature: trusted("Microsoft Windows"), details: [["PID", "1264"]] }),
    item("process", "invoice_2026.pdf.exe", {
      user: true, exe: `${HOME}\\Downloads\\invoice_2026.pdf.exe`, location: `${HOME}\\Downloads`, signature: unsigned, risk: 90,
      reasons: ["not digitally signed", "disguised with a double file extension", "runs from a user-writable folder"], details: [["PID", "9312"]],
    }),
    item("package", "typescript", { version: "5.9.3", publisher: "Microsoft Corp.", manager: "npm", user: true, location: `${HOME}\\AppData\\Roaming\\npm\\node_modules\\typescript`, uninstall: [{ type: "packageManager", manager: "npm", name: "typescript", tool: null }] }),
    item("package", "requests", { version: "2.32.5", publisher: "Kenneth Reitz", manager: "pip", user: true, uninstall: [{ type: "packageManager", manager: "pip", name: "requests", tool: "python.exe" }] }),
    item("package", "ripgrep", { version: "14.1.1", manager: "cargo", user: true, uninstall: [{ type: "packageManager", manager: "cargo", name: "ripgrep", tool: null }] }),
    item("package", "Google Chrome", { version: "141.0.7390.108", publisher: "Google LLC", manager: "choco", uninstall: [{ type: "packageManager", manager: "choco", name: "googlechrome", tool: null }] }),
    item("module", "Pester", { version: "3.4.0", publisher: "Pester", manager: "PowerShell", protection: "system" }),
    item("module", "Az.Accounts", { version: "5.3.0", publisher: "Microsoft Corporation", manager: "PowerShell", user: true, uninstall: [{ type: "deletePath", path: `${HOME}\\Documents\\PowerShell\\Modules\\Az.Accounts\\5.3.0` }] }),
    item("sdk", ".NET SDK 9.0.306", { version: "9.0.306", publisher: "Microsoft Corporation", protection: "shared", location: "C:\\Program Files\\dotnet\\sdk\\9.0.306" }),
    item("sdk", "Windows SDK 10.0.26100.0", { version: "10.0.26100.0", publisher: "Microsoft Corporation", protection: "shared" }),
    item("sdk", "Rust toolchain stable-x86_64-pc-windows-msvc", { version: "stable", publisher: "Rust Project", manager: "rustup", user: true, uninstall: [{ type: "packageManager", manager: "rustup", name: "stable-x86_64-pc-windows-msvc", tool: null }] }),
    item("runtime", "Microsoft.NETCore.App 9.0.10", { version: "9.0.10", publisher: "Microsoft Corporation", protection: "shared" }),
    item("cache", "NuGet packages", { size: 3.2 * GB, user: true, location: `${HOME}\\.nuget\\packages`, uninstall: [{ type: "cleanDir", path: `${HOME}\\.nuget\\packages` }] }),
    item("cache", "npm cache", { size: 1.8 * GB, user: true, location: `${HOME}\\AppData\\Local\\npm-cache`, uninstall: [{ type: "cleanDir", path: `${HOME}\\AppData\\Local\\npm-cache` }] }),
    item("cache", "User temp folder", { size: 2.1 * GB, user: true, location: `${HOME}\\AppData\\Local\\Temp`, uninstall: [{ type: "cleanDir", path: `${HOME}\\AppData\\Local\\Temp` }] }),
  ];

  const COLLECTORS = {
    registry: ["Installed programs", ["win32", "msi"]], appx: ["Store & MSIX apps", ["appx"]], services: ["Services", ["service"]],
    processes: ["Running processes", ["process"]], startup: ["Startup entries", ["startup"]], tasks: ["Scheduled tasks", ["task"]],
    drivers: ["Drivers", ["driver"]], features: ["Windows features", ["feature"]], updates: ["Windows updates & packages", ["update"]],
    packages: ["Package managers", ["package"]], modules: ["PowerShell modules", ["module"]], sdks: ["SDKs & runtimes", ["sdk", "runtime"]],
    caches: ["Caches", ["cache"]],
  };

  const byId = (id) => items.find((i) => i.id === id);
  const leftover = (id, display, score, reasons, size = null, type = "dir") => ({
    id, target: { type }, display, score, reasons, sizeBytes: size, preselected: score >= 80,
  });

  const LEFTOVERS = [
    leftover("l1", "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\Mozilla Firefox 131.0.3 (x64 en-US)", 100, ["uninstall entry is still registered"], null, "regKey"),
    leftover("l2", "C:\\Program Files\\Mozilla Firefox", 95, ["install folder", "name matches the product"], 18 * MB),
    leftover("l3", `${HOME}\\AppData\\Roaming\\Mozilla\\Firefox`, 90, ["name matches the product"], 412 * MB),
    leftover("l4", `${HOME}\\AppData\\Local\\Mozilla\\Firefox`, 90, ["name matches the product"], 1.1 * GB),
    leftover("l5", "C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\Firefox.lnk", 90, ["shortcut points into the install folder"], 2048, "file"),
    leftover("l6", "HKLM\\SOFTWARE\\Mozilla\\Mozilla Firefox", 90, ["name matches the product"], null, "regKey"),
    leftover("l7", "HKLM\\SOFTWARE\\Classes\\CLSID\\{0E4B2D7A-41C5-4F1B-9C6E-2A0D7F51E3B8}", 80, ["COM class served from the install folder"], null, "regKey"),
    leftover("l8", "Scheduled task \\Mozilla\\Firefox Default Browser Agent 308046B0AF4A39CB", 85, ["scheduled task runs from the install folder"], null, "task"),
    leftover("l9", "HKU\\S-1-5-21-1001_Classes\\Local Settings\\Software\\Microsoft\\Windows\\Shell\\MuiCache → C:\\Program Files\\Mozilla Firefox\\firefox.exe.FriendlyAppName", 60, ["Explorer name cache"], null, "regValue"),
    leftover("l10", `${HOME}\\AppData\\Local\\Temp\\Firefox`, 50, ["name is similar to the product"], 34 * MB),
  ];

  const THREAT = (it) => [
    leftover("t1", `Stop running instances of ${it.executable}`, 100, ["running instances"], null, "process"),
    leftover("t2", "HKU\\S-1-5-21-1001\\Software\\Microsoft\\Windows\\CurrentVersion\\Run → svchost", 95, ["startup that launches it"], null, "regValue"),
    leftover("t3", "Scheduled task \\SysUpd Updater", 95, ["task that launches it"], null, "task"),
    leftover("t4", it.executable, 95, ["the flagged executable"], 1.4 * MB, "file"),
    leftover("t5", it.executable.replace(/\\[^\\]+$/, ""), 60, ["folder containing the executable"], 3.2 * MB),
  ];

  function plan(it) {
    const blocked = it.uninstall.length === 0 ? "No removal method is known for this item." : null;
    const warnings = [];
    if (it.protection === "shared") warnings.push("Other programs may depend on this shared component. Removing it can break them.");
    const processes = it.name.startsWith("Mozilla Firefox") ? [{ pid: 8420, name: "firefox.exe", path: it.executable }] : [];
    if (processes.length) warnings.push(`${processes.length} running process(es) will be closed first.`);
    const labels = { command: (m) => `Uninstaller: ${m.command}`, msi: (m) => `Windows Installer: msiexec /x ${m.productCode}` };
    return {
      item: it, blocked, warnings, processes,
      methods: it.uninstall.map((m, index) => ({ index, label: (labels[m.type] ?? ((x) => `${x.type}`))(m), runsUnelevated: it.scope === "user", undoable: false })),
      canForce: ["win32", "msi", "appx"].includes(it.kind),
    };
  }

  const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

  async function scan(channel) {
    const cb = callbacks.get(channel.id);
    let index = 0;
    const send = (message) => cb({ message, index: index++ });
    send({ event: "started", elevated: true, collectors: Object.entries(COLLECTORS).map(([id, [label]]) => ({ id, label, requiresAdmin: false })) });
    let ms = 4;
    for (const [id, [, kinds]] of Object.entries(COLLECTORS)) {
      await sleep(5);
      send({ event: "batch", collector: id, items: items.filter((i) => kinds.includes(i.kind)), elapsedMs: (ms += 37) });
    }
    send({ event: "finished", total: items.length, elapsedMs: 1184 });
    return null;
  }

  const handlers = {
    "plugin:app|version": () => "0.1.0",
    session: () => ({ elevated: false, admin: true }),
    start_admin: () => ({ elevated: false, admin: true }),
    load_cache: () => ({ saved: Date.now() / 1000, items }),
    scan: (a) => scan(a.onEvent),
    plan: (a) => plan(byId(a.id)),
    restore_point: async () => (await sleep(400), null),
    execute: async () => (await sleep(900), { success: true, exitCode: 0, rebootRequired: false, stillPresent: false, message: "Uninstaller finished", txn: null }),
    leftovers: async () => (await sleep(600), { txn: "6721f0a3-1b2c3d4e", leftovers: LEFTOVERS }),
    threat: async (a) => (await sleep(500), { txn: "6721f0b8-5e6f7a8b", leftovers: THREAT(byId(a.id)) }),
    clean: async (a) => (await sleep(700), { removed: a.ids.length, failed: [], rebootRequired: false }),
    history: () => [
      { id: "6721f0a3-1b2c3d4e", created: Date.now() / 1000 - 3600, itemName: "Mozilla Firefox (x64 en-US)", itemKind: "win32", found: 10, removed: 8, undone: false, canUndo: true },
      { id: "671f9a10-0a1b2c3d", created: Date.now() / 1000 - 86400 * 2, itemName: "svchost (startup)", itemKind: "startup", found: 5, removed: 4, undone: false, canUndo: true },
      { id: "671c11e2-9f8e7d6c", created: Date.now() / 1000 - 86400 * 6, itemName: "Zoom Workplace", itemKind: "win32", found: 7, removed: 7, undone: true, canUndo: false },
    ],
    undo: () => ({ restored: 8, failed: [] }),
    terminate: () => null,
    defender_scan: async () => (await sleep(800), "Microsoft Defender detected a threat. Threat Trojan:Win32/Wacatac.B!ml identified."),
    export_inventory: () => `${HOME}\\Documents\\snipe-inventory-1761900000.csv`,
    open_location: () => null,
  };

  window.__TAURI_INTERNALS__ = {
    transformCallback(cb) {
      const id = nextCallback++;
      callbacks.set(id, cb);
      return id;
    },
    unregisterCallback(id) {
      callbacks.delete(id);
    },
    async invoke(command, args = {}) {
      const handler = handlers[command];
      if (!handler) throw new Error(`demo: unhandled command ${command}`);
      return handler(args);
    },
    metadata: { currentWindow: { label: "main" }, currentWebview: { windowLabel: "main", label: "main" } },
  };
})();
