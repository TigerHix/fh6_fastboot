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

The hold is a busy-wait: a game thread spins on `QueryPerformanceCounter`, comparing elapsed time to a fixed deadline. It coincides with the startup logo video (`T10_MS_Combined.bk2`), and it overlaps real disk loading, so "wait for the disk to go quiet" is not a reliable signal.

Fast Startup loads in-process and hooks the timing APIs. It scopes the skip to the startup video's lifetime: it watches for that file opening (and tags the matching `BinkOpen` handle), and acts only until the video closes. Inside that window it spots the hold's busy-wait by its QPC call rate, measured *relative to the same boot's own rate* rather than a fixed threshold, so it auto-scales to any CPU. It then adds a constant offset to the clock to push the wait past its deadline, re-firing until the spin collapses.

The offset shifts the clock forward and leaves the rate unchanged, so frame timing (`now - prev`) is unaffected and gameplay runs at normal speed. Real loading is disk-bound and event-driven, so it is untouched. Scoping to the video window keeps it from firing during menus or gameplay, and works the same on fast SSDs and slow HDDs.

## Config (`fastboot.ini`)

| Key | Default | Meaning |
|-----|---------|---------|
| `intro_video` | `T10_MS_Combined` | Startup video filename (substring). The skip runs only while this video is on screen. If a game update renames it, set the new name here. |
| `jump_ms` | `30000` | How far to push the clock per jump. |
| `poll_ms` | `80` | Monitor poll interval. |
| `enter_spammer` | `0` | Set `1` to auto-press Enter through the post-skip press-start prompts and drop straight into the game. |
| `enter_interval_ms` | `120` | Enter interval while spamming. |
| `enter_window_ms` | `12000` | Stop spamming this long after the skip. |

The spin threshold is auto-calibrated per machine, so there is nothing disk- or CPU-specific to tune. `F8` is a manual skip: press it to collapse the intro on the spot (a hands-on fallback if the automatic skip ever misses). The mod always writes a small `fastboot.log` (spin peaks, gate, disarm); delete it anytime.

## Build

Rust, MSVC toolchain:

```
cargo build --release
```

Output: `target/release/version.dll`. `pwsh ./package.ps1` produces the release zip.
