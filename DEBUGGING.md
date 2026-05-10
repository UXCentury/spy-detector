# Debugging Spy Detector (Windows)

Short workflows for crashes, native debugging, and Tauri dev. Log file: `%APPDATA%\spy-detector\app.log` (panic lines are prefixed with `[panic]`).

## Quick: capture a panic

1. In PowerShell: `$env:RUST_BACKTRACE = 'full'`
2. Run the app from the same session so the variable applies (e.g. path to `spy-detector.exe`, or `npm run tauri dev`).
3. Reproduce the crash.
4. Copy the **console stderr** output and the **last ~50 lines** of `%APPDATA%\spy-detector\app.log` into your report.

For richer stacks in development builds, you can also set `RUST_BACKTRACE=1` or `full` before starting (see [std::panic](https://doc.rust-lang.org/std/panic/index.html)); release binaries still log the panic line to `app.log` via the panic hook.

## Attach with Visual Studio / VS Code

1. Install the **C/C++** extension (MSVC debugger, `cppvsdbg`) or use **CodeLLDB** (`vadimcn.vscode-lldb`) for the LLDB-based configs in `.vscode/launch.json`.
2. Start Spy Detector normally (installed build or your own build).
3. **Run and Debug** → choose **Attach: spy-detector.exe (MSVC)** (or **Attach: installed spy-detector (MSVC, symbols)** if you debug the NSIS/current-user install under `%LOCALAPPDATA%\Programs\Spy Detector\`).
4. When prompted, pick the **`spy-detector.exe`** process (there should be only one).
5. In VS / VS Code, enable breaking on **C++ / Win32 exceptions** (Access Violation, etc.) if you are chasing native faults rather than Rust panics.

`pickProcess` is used because `cppvsdbg` does not support attach-by-process-name alone; filtering the list to `spy-detector.exe` is the practical equivalent.

## Attach with WinDbg Preview

1. **File → Attach to Process** → select **`spy-detector.exe`**.
2. After a crash, try **`.catch { .ecxr }`** (or run **`.ecxr`** / **`k`** ) to get the faulting context and stack.
3. For automatic **user-mode dumps** (WER), you can configure local crash dumps for the executable via registry under **LocalDumps** or use **Settings → System → For developers** options on recent Windows builds; see Microsoft’s [Collecting User-Mode Dump Files](https://learn.microsoft.com/en-us/windows/win32/wer/collecting-user-mode-dumps) for supported keys and dump types (full vs mini).

## Tauri dev vs release attach

- **`npm run tauri dev`**: starts Next.js and the **debug** `spy-detector.exe`. Use **Attach: spy-detector.exe (MSVC)** or CodeLLDB attach after the window appears, or use **Launch: spy-detector debug exe (MSVC)** only when the dev server is already running (`npm run dev` in another terminal on port 3000) so the UI can load.
- **Launch: spy-detector debug (CodeLLDB, cargo build)** builds and starts the Rust binary under LLDB; you still need the frontend dev server if you want the full UI.
- **Launch: npm run tauri dev (JavaScript debug)** runs the **npm** driver under the Node debugger (useful for scripting/tooling issues, not the Rust core).
- **Release** crashes: attach the same way; prefer **Attach: installed spy-detector (MSVC, symbols)** if symbols for your installed path are configured, or point your debugger at matching `.pdb` sources.

## VS Code `launch.json` summary

| Configuration | Purpose |
|---------------|---------|
| Attach: spy-detector.exe (MSVC) | Attach with symbols path set to **repo** `target/release/spy-detector.exe` |
| Attach: installed spy-detector (MSVC, symbols) | Attach with symbols path under **LocalAppData** install folder |
| Attach: spy-detector.exe (CodeLLDB) | Attach via CodeLLDB (`${command:pickMyProcess}`) |
| Launch: spy-detector debug exe (MSVC) | Start **debug** binary under MSVC (frontend separate) |
| Launch: spy-detector debug (CodeLLDB, cargo build) | Build + launch debug binary under LLDB |
| Launch: npm run tauri dev (JavaScript debug) | Runs `tauri dev` entrypoint under Node debugger |

Bug reports saved from the app can include **diagnostics + last `app.log` lines** when the user checks that option; setting **`RUST_BACKTRACE=full`** before reproducing still helps when sharing console output alongside `app.log`.
