# Forza Horizon 6 Fast Startup

Drop-in mod that skips Forza Horizon 6's startup wait, the ~25s black screen shown after the disclaimer/logo. It leaves disk loading untouched, so the game reaches the menu as soon as loading finishes. The skip is automatic; nothing to configure or turn off.

[Download on Nexus Mods](https://www.nexusmods.com/forzahorizon6/mods/522)

## Install

1. Copy `version.dll` into the game folder, next to `forzahorizon6.exe` (`…\steamapps\common\ForzaHorizon6\`).
2. Optionally copy `fastboot.ini` there to change settings.
3. Launch the game.

No launcher or injector. `version.dll` is a system library the game loads; this copy proxies it and forwards its calls to the real one in `System32`.

Already have a `version.dll` from another mod? Rename it to `version_orig.dll`; this loads it alongside the skip.

## Uninstall

Delete `version.dll` (and `fastboot.ini` / `fastboot.log`).

## How it works

The hold is a busy-wait: one thread spins on `QueryPerformanceCounter` (~1.2M calls per 80ms), comparing elapsed time to a fixed deadline while the disk sits idle.

Fast Startup loads in-process, hooks the timing APIs, and watches for that signature: a QPC spin once the disk goes quiet after loading (a low read-rate over a rolling ~1s window, so load size doesn't matter). It adds a constant offset to the clock to push past the deadline, then disarms.

The offset shifts the clock forward and leaves the rate unchanged, so frame timing (`now - prev`) is unaffected and gameplay runs at normal speed. Loading is disk-bound, so the clock stays at 1x during it. Detection is behavioural, so it keeps working across game updates while the hold stays a QPC spin after loading.

## Config (`fastboot.ini`)

| Key | Default | Meaning |
|-----|---------|---------|
| `qpc_spin_min` | `500000` | Min QPC calls/poll to count as the gate's spin. |
| `quiet_bytes` | `6000000` | Disk counts as quiet below this many bytes read over the window. |
| `quiet_window_polls` | `12` | Rolling read-rate window length (~1s at 80ms). |
| `jump_ms` | `30000` | How far to fast-forward per detected gate. |
| `poll_ms` | `80` | Monitor poll interval. |
| `diag` | `0` | Set `1` for per-poll logging (debugging). |
| `log` | `1` | Write `fastboot.log` with key events. |
| `enter_spammer` | `0` | Set `1` to auto-press Enter through the post-skip press-start prompts and drop straight into the game. |
| `enter_interval_ms` | `120` | Enter interval while spamming. |
| `enter_window_ms` | `12000` | Stop spamming this long after the skip. |

`F8` toggles the skip at runtime.

## Build

Rust, MSVC toolchain:

```
cargo build --release
```

Output: `target/release/version.dll`. `pwsh ./package.ps1` produces the release zip.
