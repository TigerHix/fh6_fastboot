#![allow(non_snake_case)]
//! FH6 FastBoot: a version.dll proxy that skips Forza Horizon 6's startup
//! black-screen hold without touching disk loading.
//!
//! The hold is a busy-wait: a thread spins on QueryPerformanceCounter comparing
//! elapsed time to a fixed deadline while the disk sits idle. We load in-process,
//! hook the timing APIs, and watch for that signature: a QPC spin once the disk
//! goes quiet after loading. Then we add a constant offset to the clock to push
//! past the deadline, and disarm. The offset leaves the rate unchanged, so frame
//! timing is unaffected and loading runs at 1x.

use core::ffi::c_void;
use core::sync::atomic::{AtomicBool, AtomicI64, AtomicIsize, AtomicPtr, AtomicU64, AtomicUsize, Ordering};
use std::path::PathBuf;
use std::sync::OnceLock;

use retour::GenericDetour;

// ───────────────────────── Win32 bindings (hand-declared) ─────────────────────────
type HMODULE = isize;
type HANDLE = isize;
type BOOL = i32;
type FARPROC = usize;

#[repr(C)]
#[derive(Default, Clone, Copy)]
struct IO_COUNTERS {
    read_op: u64,
    write_op: u64,
    other_op: u64,
    read_tx: u64,
    write_tx: u64,
    other_tx: u64,
}

extern "system" {
    fn LoadLibraryW(name: *const u16) -> HMODULE;
    fn GetModuleHandleW(name: *const u16) -> HMODULE;
    fn GetProcAddress(h: HMODULE, name: *const u8) -> FARPROC;
    fn GetModuleFileNameW(h: HMODULE, buf: *mut u16, sz: u32) -> u32;
    fn GetSystemDirectoryW(buf: *mut u16, sz: u32) -> u32;
    fn DisableThreadLibraryCalls(h: HMODULE) -> BOOL;
    fn CreateThread(
        attr: *const c_void,
        stack: usize,
        start: extern "system" fn(*mut c_void) -> u32,
        param: *mut c_void,
        flags: u32,
        tid: *mut u32,
    ) -> HANDLE;
    fn GetCurrentProcess() -> HANDLE;
    fn GetProcessIoCounters(h: HANDLE, c: *mut IO_COUNTERS) -> BOOL;
    fn QueryPerformanceFrequency(f: *mut i64) -> BOOL;
    fn GetAsyncKeyState(vk: i32) -> i16;
    fn Sleep(ms: u32);
    // enter_spammer: post Enter to the game window to clear the post-skip prompts
    fn PostMessageW(hwnd: isize, msg: u32, wparam: usize, lparam: isize) -> BOOL;
    fn EnumWindows(cb: extern "system" fn(isize, isize) -> BOOL, lparam: isize) -> BOOL;
    fn GetWindowThreadProcessId(hwnd: isize, pid: *mut u32) -> u32;
    fn GetCurrentProcessId() -> u32;
    fn IsWindowVisible(hwnd: isize) -> BOOL;
}

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

// ───────────────────────── version.dll proxy forwarders ─────────────────────────
// Each export is a naked stub that jumps to the real system version.dll function,
// whose address we resolve once in DllMain. (Intel asm is Rust's default.)
macro_rules! proxies {
    ($($n:ident),+ $(,)?) => {
        mod reals {
            use core::sync::atomic::AtomicUsize;
            $( #[allow(non_upper_case_globals)] pub static $n: AtomicUsize = AtomicUsize::new(0); )+
        }
        $(
            #[no_mangle]
            #[unsafe(naked)]
            pub extern "C" fn $n() {
                core::arch::naked_asm!("jmp qword ptr [rip + {0}]", sym reals::$n);
            }
        )+
        static PROXY_LIST: &[(&'static str, &'static AtomicUsize)] =
            &[ $( (stringify!($n), &reals::$n) ),+ ];
        fn proxy_init_list() -> &'static [(&'static str, &'static AtomicUsize)] {
            PROXY_LIST
        }
    };
}

proxies!(
    GetFileVersionInfoA,
    GetFileVersionInfoByHandle,
    GetFileVersionInfoExA,
    GetFileVersionInfoExW,
    GetFileVersionInfoSizeA,
    GetFileVersionInfoSizeExA,
    GetFileVersionInfoSizeExW,
    GetFileVersionInfoSizeW,
    GetFileVersionInfoW,
    VerFindFileA,
    VerFindFileW,
    VerInstallFileA,
    VerInstallFileW,
    VerLanguageNameA,
    VerLanguageNameW,
    VerQueryValueA,
    VerQueryValueW,
);

fn init_proxy() {
    // The real version.dll, loaded by absolute system path so the loader doesn't
    // re-resolve to us (infinite recursion).
    let mut buf = [0u16; 320];
    let n = unsafe { GetSystemDirectoryW(buf.as_mut_ptr(), buf.len() as u32) } as usize;
    let mut sys: Vec<u16> = buf[..n].to_vec();
    sys.extend("\\version.dll".encode_utf16());
    sys.push(0);
    let h_sys = unsafe { LoadLibraryW(sys.as_ptr()) };

    // Chainload: another version.dll mod renamed to version_orig.dll next to the
    // game exe. Loading it runs its DllMain; we forward version calls to it
    // first, falling back to the system version.dll for anything it lacks.
    let chain = exe_dir().join("version_orig.dll");
    let h_chain = if chain.exists() {
        unsafe { LoadLibraryW(wide(&chain.to_string_lossy()).as_ptr()) }
    } else {
        0
    };

    for (name, slot) in proxy_init_list() {
        let mut c: Vec<u8> = name.bytes().collect();
        c.push(0);
        let mut p = 0usize;
        if h_chain != 0 {
            p = unsafe { GetProcAddress(h_chain, c.as_ptr()) };
        }
        if p == 0 && h_sys != 0 {
            p = unsafe { GetProcAddress(h_sys, c.as_ptr()) };
        }
        slot.store(p, Ordering::SeqCst);
    }
}

// ───────────────────────── virtual clock (RCU snapshot) ─────────────────────────
// virtual = anchor_virt + (real - anchor_real) * milli/1000. We keep the rate at
// 1x (milli = 1000) and only add a constant offset (jump_clock) to skip the gate;
// the general form is kept so each update is a single lock-free atomic swap.
#[derive(Clone, Copy)]
struct Snap {
    milli: i64, // factor * 1000
    qa: i64,
    qv: i64, // QueryPerformanceCounter
    t64a: i64,
    t64v: i64, // GetTickCount64
    ta: i64,
    tv: i64, // GetTickCount
    ma: i64,
    mv: i64, // timeGetTime
}

static CLOCK: AtomicPtr<Snap> = AtomicPtr::new(core::ptr::null_mut());
static FREQ: AtomicI64 = AtomicI64::new(0);

#[inline]
fn scale(real: i64, a: i64, v: i64, milli: i64) -> i64 {
    v + (((real - a) as i128 * milli as i128) / 1000) as i64
}

fn store_snap(s: Snap) {
    let b = Box::into_raw(Box::new(s));
    let old = CLOCK.swap(b, Ordering::Release);
    // Leak the old snapshot: it may still be read concurrently and we only ever
    // change the factor a couple of times per process, so this is negligible.
    let _ = old;
}

/// Shift the virtual clock forward by `ms` for all timers without changing the
/// rate. A timed wait (`now - start >= deadline`) then sees its deadline met and
/// exits; frame deltas are unaffected (the offset cancels in `now - prev`).
fn jump_clock(ms: i64) {
    let p = CLOCK.load(Ordering::Acquire);
    if p.is_null() {
        return;
    }
    let o = unsafe { *p };
    let freq = FREQ.load(Ordering::Relaxed);
    let qpc_off = (ms as i128 * freq as i128 / 1000) as i64;
    store_snap(Snap {
        milli: o.milli, // rate unchanged (stays 1x)
        qa: o.qa,
        qv: o.qv + qpc_off,
        t64a: o.t64a,
        t64v: o.t64v + ms,
        ta: o.ta,
        tv: o.tv + ms,
        ma: o.ma,
        mv: o.mv + ms,
    });
    ACTIVE.store(true, Ordering::Release); // from now on the hooks apply the offset
}

// ───────────────────────── timer hooks ─────────────────────────
type FnQpc = unsafe extern "system" fn(*mut i64) -> i32;
type FnU64 = unsafe extern "system" fn() -> u64;
type FnU32 = unsafe extern "system" fn() -> u32;
type FnCreateW =
    unsafe extern "system" fn(*const u16, u32, u32, *const c_void, u32, u32, isize) -> isize;
type FnCreateA =
    unsafe extern "system" fn(*const u8, u32, u32, *const c_void, u32, u32, isize) -> isize;
type FnBinkOpen = unsafe extern "system" fn(*const u8, u32) -> isize;
type FnBinkClose = unsafe extern "system" fn(isize); // BinkClose: void(HBINK)

// GenericDetour holds raw pointers; we only ever touch the originals through it
// and the factor state is separately synchronized, so sharing is sound here.
struct Hook<T: retour::Function>(OnceLock<GenericDetour<T>>);
unsafe impl<T: retour::Function> Sync for Hook<T> {}
impl<T: retour::Function> Hook<T> {
    const fn new() -> Self {
        Hook(OnceLock::new())
    }
}

static QPC: Hook<FnQpc> = Hook::new();
static GTC64: Hook<FnU64> = Hook::new();
static GTC: Hook<FnU32> = Hook::new();
static MM: Hook<FnU32> = Hook::new();
static CRW: Hook<FnCreateW> = Hook::new();
static CRA: Hook<FnCreateA> = Hook::new();
static BKOPEN: Hook<FnBinkOpen> = Hook::new(); // BinkOpen: tag the intro handle
static BKCLOSE: Hook<FnBinkClose> = Hook::new(); // BinkClose: end of the intro window

fn real_qpc() -> i64 {
    if let Some(d) = QPC.0.get() {
        let mut x = 0i64;
        unsafe { d.call(&mut x as *mut i64) };
        x
    } else {
        0
    }
}
fn real_gtc64() -> u64 {
    GTC64.0.get().map(|d| unsafe { d.call() }).unwrap_or(0)
}
fn real_gtc() -> u32 {
    GTC.0.get().map(|d| unsafe { d.call() }).unwrap_or(0)
}
fn real_mm() -> u32 {
    MM.0.get().map(|d| unsafe { d.call() }).unwrap_or(0)
}

// QPC call count, sampled by the monitor to detect the gate's spin-loop. The
// clock offset is applied only once ACTIVE (after a jump), so the pre-gate hot
// path is a counter increment plus the original call.
static QPC_N: AtomicU64 = AtomicU64::new(0);
static ACTIVE: AtomicBool = AtomicBool::new(false);
// Diagnostic file-open probe: START_MS anchors timestamps; WATCH_FILES gates the
// (per-file-open) inspection to the boot window so it costs nothing in gameplay.
static START_MS: AtomicI64 = AtomicI64::new(0);
static WATCH_FILES: AtomicBool = AtomicBool::new(true);
// Set true when the startup video opens: the hold has begun, so the gate may
// fire on the spin alone without requiring the disk to be quiet.
static INTRO_OPEN: AtomicBool = AtomicBool::new(false);
// The intro's HBINK handle. BinkOpen takes the .bk2 from memory (no filename),
// so we tag the first BinkOpen after the intro file's CreateFile as the intro,
// and watch its BinkClose to bound the skip window.
static INTRO_HBINK: AtomicIsize = AtomicIsize::new(0);
static INTRO_FILE_PENDING: AtomicBool = AtomicBool::new(false);
static INTRO_CLOSED: AtomicBool = AtomicBool::new(false);

unsafe extern "system" fn hk_qpc(out: *mut i64) -> i32 {
    QPC_N.fetch_add(1, Ordering::Relaxed);
    let r = QPC.0.get().unwrap().call(out);
    if r != 0 && ACTIVE.load(Ordering::Relaxed) {
        let p = CLOCK.load(Ordering::Acquire);
        if !p.is_null() {
            let s = &*p;
            *out = scale(*out, s.qa, s.qv, s.milli);
        }
    }
    r
}
unsafe extern "system" fn hk_gtc64() -> u64 {
    let real = GTC64.0.get().unwrap().call();
    if !ACTIVE.load(Ordering::Relaxed) {
        return real;
    }
    let p = CLOCK.load(Ordering::Acquire);
    if p.is_null() {
        return real;
    }
    let s = &*p;
    scale(real as i64, s.t64a, s.t64v, s.milli) as u64
}
unsafe extern "system" fn hk_gtc() -> u32 {
    let real = GTC.0.get().unwrap().call();
    if !ACTIVE.load(Ordering::Relaxed) {
        return real;
    }
    let p = CLOCK.load(Ordering::Acquire);
    if p.is_null() {
        return real;
    }
    let s = &*p;
    scale(real as i64, s.ta, s.tv, s.milli) as u32
}
unsafe extern "system" fn hk_mm() -> u32 {
    let real = MM.0.get().unwrap().call();
    if !ACTIVE.load(Ordering::Relaxed) {
        return real;
    }
    let p = CLOCK.load(Ordering::Acquire);
    if p.is_null() {
        return real;
    }
    let s = &*p;
    scale(real as i64, s.ma, s.mv, s.milli) as u32
}

// Diagnostic: log when a .bk2 video file is opened, so we can see whether the
// intro video read coincides with the start of the startup hold. Bounded to the
// boot window by WATCH_FILES.
fn note_bk2(name: &str) {
    if name.len() < 4 {
        return;
    }
    let lower = name.to_ascii_lowercase();
    if !lower.contains(".bk2") {
        return;
    }
    let el = now_ms() - START_MS.load(Ordering::Relaxed);
    let base = name.rsplit(['\\', '/']).next().unwrap_or(name);
    // Identify the intro: its file open tags the next BinkOpen as the intro handle.
    if let Some(cfg) = CFG.get() {
        let needle = cfg.intro_video.to_ascii_lowercase();
        if !needle.is_empty() && lower.contains(&needle) {
            INTRO_FILE_PENDING.store(true, Ordering::Relaxed);
            if !INTRO_OPEN.swap(true, Ordering::Relaxed) {
                log(&format!("[{}ms] intro file opened ({}) -> tagging next BinkOpen", el, base));
            }
            return;
        }
    }
    log(&format!("[{}ms] OPEN {}", el, base));
}
unsafe extern "system" fn hk_crw(
    name: *const u16,
    a: u32,
    s: u32,
    sa: *const c_void,
    d: u32,
    fl: u32,
    t: isize,
) -> isize {
    if WATCH_FILES.load(Ordering::Relaxed) && !name.is_null() {
        let mut buf = String::new();
        let mut i = 0isize;
        while i < 1024 {
            let c = *name.offset(i);
            if c == 0 {
                break;
            }
            buf.push(char::from_u32(c as u32).unwrap_or('?'));
            i += 1;
        }
        note_bk2(&buf);
    }
    CRW.0.get().unwrap().call(name, a, s, sa, d, fl, t)
}
unsafe extern "system" fn hk_cra(
    name: *const u8,
    a: u32,
    s: u32,
    sa: *const c_void,
    d: u32,
    fl: u32,
    t: isize,
) -> isize {
    if WATCH_FILES.load(Ordering::Relaxed) && !name.is_null() {
        let mut buf = Vec::new();
        let mut i = 0isize;
        while i < 1024 {
            let c = *name.offset(i);
            if c == 0 {
                break;
            }
            buf.push(c);
            i += 1;
        }
        note_bk2(&String::from_utf8_lossy(&buf));
    }
    CRA.0.get().unwrap().call(name, a, s, sa, d, fl, t)
}

// Boot window: bound the file/Bink logging to startup so it costs nothing later.
fn boot_window() -> bool {
    now_ms() - START_MS.load(Ordering::Relaxed) < 120_000
}
// BinkOpen: the first call after the intro .bk2 file opened is the intro itself,
// so we tag its handle. (The handle's BinkClose then bounds the skip window.)
unsafe extern "system" fn hk_bkopen(name: *const u8, flags: u32) -> isize {
    let _ = name; // the game opens from memory (BINKFROMMEMORY), so name is not a path
    let h = BKOPEN.0.get().unwrap().call(name, flags);
    if boot_window() {
        let el = now_ms() - START_MS.load(Ordering::Relaxed);
        // The first BinkOpen after the intro file opened is the intro itself.
        if INTRO_FILE_PENDING.swap(false, Ordering::Relaxed)
            && INTRO_HBINK.load(Ordering::Relaxed) == 0
        {
            INTRO_HBINK.store(h, Ordering::Relaxed);
            log(&format!("[{}ms] BinkOpen -> intro handle {:#x} (flags={:#x})", el, h, flags));
        } else {
            log(&format!("[{}ms] BinkOpen -> {:#x} (flags={:#x})", el, h, flags));
        }
    }
    h
}
// BinkClose marks the end of the intro's lifetime -- the skip window's upper bound.
unsafe extern "system" fn hk_bkclose(b: isize) {
    let is_intro = b == INTRO_HBINK.load(Ordering::Relaxed);
    if is_intro {
        INTRO_CLOSED.store(true, Ordering::Relaxed);
    }
    if boot_window() {
        let el = now_ms() - START_MS.load(Ordering::Relaxed);
        log(&format!("[{}ms] BinkClose {:#x}{}", el, b, if is_intro { " <INTRO>" } else { "" }));
    }
    BKCLOSE.0.get().unwrap().call(b)
}

fn resolve(module: &str, name: &[u8]) -> Option<usize> {
    unsafe {
        let mut h = GetModuleHandleW(wide(module).as_ptr());
        if h == 0 {
            h = LoadLibraryW(wide(module).as_ptr());
        }
        if h == 0 {
            return None;
        }
        let p = GetProcAddress(h, name.as_ptr());
        if p == 0 {
            None
        } else {
            Some(p)
        }
    }
}

fn install_hooks() {
    let mut f = 0i64;
    unsafe { QueryPerformanceFrequency(&mut f) };
    FREQ.store(f, Ordering::SeqCst);

    // QueryPerformanceCounter lives in kernelbase.
    if let Some(a) = resolve("kernelbase.dll", b"QueryPerformanceCounter\0")
        .or_else(|| resolve("kernel32.dll", b"QueryPerformanceCounter\0"))
    {
        unsafe {
            let t: FnQpc = core::mem::transmute(a);
            if let Ok(d) = GenericDetour::<FnQpc>::new(t, hk_qpc) {
                let _ = QPC.0.set(d);
            }
        }
    }
    if let Some(a) = resolve("kernelbase.dll", b"GetTickCount64\0")
        .or_else(|| resolve("kernel32.dll", b"GetTickCount64\0"))
    {
        unsafe {
            let t: FnU64 = core::mem::transmute(a);
            if let Ok(d) = GenericDetour::<FnU64>::new(t, hk_gtc64) {
                let _ = GTC64.0.set(d);
            }
        }
    }
    if let Some(a) = resolve("kernelbase.dll", b"GetTickCount\0")
        .or_else(|| resolve("kernel32.dll", b"GetTickCount\0"))
    {
        unsafe {
            let t: FnU32 = core::mem::transmute(a);
            if let Ok(d) = GenericDetour::<FnU32>::new(t, hk_gtc) {
                let _ = GTC.0.set(d);
            }
        }
    }
    if let Some(a) = resolve("winmm.dll", b"timeGetTime\0") {
        unsafe {
            let t: FnU32 = core::mem::transmute(a);
            if let Ok(d) = GenericDetour::<FnU32>::new(t, hk_mm) {
                let _ = MM.0.set(d);
            }
        }
    }
    // Diagnostic file-open probe (CreateFileW/A) to time the intro .bk2 read.
    if let Some(a) = resolve("kernelbase.dll", b"CreateFileW\0")
        .or_else(|| resolve("kernel32.dll", b"CreateFileW\0"))
    {
        unsafe {
            let t: FnCreateW = core::mem::transmute(a);
            if let Ok(d) = GenericDetour::<FnCreateW>::new(t, hk_crw) {
                let _ = CRW.0.set(d);
            }
        }
    }
    if let Some(a) = resolve("kernelbase.dll", b"CreateFileA\0")
        .or_else(|| resolve("kernel32.dll", b"CreateFileA\0"))
    {
        unsafe {
            let t: FnCreateA = core::mem::transmute(a);
            if let Ok(d) = GenericDetour::<FnCreateA>::new(t, hk_cra) {
                let _ = CRA.0.set(d);
            }
        }
    }
    // Bink window hooks (bink2w64.dll; loaded on demand if not yet present): the
    // intro's BinkOpen/BinkClose bound the skip window.
    if let Some(a) = resolve("bink2w64.dll", b"BinkOpen\0") {
        unsafe {
            let t: FnBinkOpen = core::mem::transmute(a);
            if let Ok(d) = GenericDetour::<FnBinkOpen>::new(t, hk_bkopen) {
                let _ = BKOPEN.0.set(d);
            }
        }
    }
    if let Some(a) = resolve("bink2w64.dll", b"BinkClose\0") {
        unsafe {
            let t: FnBinkClose = core::mem::transmute(a);
            if let Ok(d) = GenericDetour::<FnBinkClose>::new(t, hk_bkclose) {
                let _ = BKCLOSE.0.set(d);
            }
        }
    }

    // Initialize the clock at 1x (virtual == real) before enabling hooks.
    let q = real_qpc();
    let t64 = real_gtc64() as i64;
    let t = real_gtc() as i64;
    let m = real_mm() as i64;
    store_snap(Snap {
        milli: 1000,
        qa: q,
        qv: q,
        t64a: t64,
        t64v: t64,
        ta: t,
        tv: t,
        ma: m,
        mv: m,
    });
    START_MS.store(now_ms(), Ordering::SeqCst);

    unsafe {
        if let Some(d) = QPC.0.get() {
            let _ = d.enable();
        }
        if let Some(d) = GTC64.0.get() {
            let _ = d.enable();
        }
        if let Some(d) = GTC.0.get() {
            let _ = d.enable();
        }
        if let Some(d) = MM.0.get() {
            let _ = d.enable();
        }
        if let Some(d) = CRW.0.get() {
            let _ = d.enable();
        }
        if let Some(d) = CRA.0.get() {
            let _ = d.enable();
        }
        if let Some(d) = BKOPEN.0.get() {
            let _ = d.enable();
        }
        if let Some(d) = BKCLOSE.0.get() {
            let _ = d.enable();
        }
    }
}

// ───────────────────────── config + logging ─────────────────────────
struct Config {
    jump_ms: i64,
    poll_ms: u32,
    // The startup video filename (substring) used to identify the intro's Bink
    // handle; the skip is scoped to that handle's BinkOpen -> BinkClose window.
    intro_video: String,
    // After the skip, post Enter to the window on a fast interval to blow through
    // the post-skip press-start prompts and start the game. Off by default.
    enter_spammer: bool,
    enter_interval_ms: i64,
    enter_window_ms: i64, // stop spamming this long after the skip disarms
}
static CFG: OnceLock<Config> = OnceLock::new();

fn exe_dir() -> PathBuf {
    let mut buf = [0u16; 520];
    let n = unsafe { GetModuleFileNameW(0, buf.as_mut_ptr(), buf.len() as u32) } as usize;
    let s = String::from_utf16_lossy(&buf[..n]);
    PathBuf::from(s)
        .parent()
        .map(|p| p.to_path_buf())
        .unwrap_or_default()
}

fn load_config() -> Config {
    let mut c = Config {
        jump_ms: 30_000,
        poll_ms: 80,
        intro_video: "T10_MS_Combined".to_string(),
        enter_spammer: false,
        enter_interval_ms: 120,
        enter_window_ms: 12_000,
    };
    if let Ok(txt) = std::fs::read_to_string(exe_dir().join("fastboot.ini")) {
        for line in txt.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') || line.starts_with(';') || line.starts_with('[') {
                continue;
            }
            if let Some((k, v)) = line.split_once('=') {
                let (k, v) = (k.trim(), v.trim());
                match k {
                    "jump_ms" => {
                        if let Ok(x) = v.parse() {
                            c.jump_ms = x;
                        }
                    }
                    "poll_ms" => {
                        if let Ok(x) = v.parse() {
                            c.poll_ms = x;
                        }
                    }
                    "intro_video" => c.intro_video = v.to_string(),
                    "enter_spammer" => {
                        c.enter_spammer = v != "0" && !v.eq_ignore_ascii_case("false")
                    }
                    "enter_interval_ms" => {
                        if let Ok(x) = v.parse() {
                            c.enter_interval_ms = x;
                        }
                    }
                    "enter_window_ms" => {
                        if let Ok(x) = v.parse() {
                            c.enter_window_ms = x;
                        }
                    }
                    _ => {}
                }
            }
        }
    }
    c
}

fn log(msg: &str) {
    use std::io::Write;
    if let Ok(mut f) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(exe_dir().join("fastboot.log"))
    {
        let _ = writeln!(f, "{}", msg);
    }
}

// ───────────────────────── enter spammer (optional) ─────────────────────────
// FH6 ignores injected system input (SendInput/keybd_event) but honours window
// messages, so we post WM_KEYDOWN/UP for Enter straight to the game window.
const WM_KEYDOWN: u32 = 0x0100;
const WM_KEYUP: u32 = 0x0101;
const VK_RETURN: u8 = 0x0D;

static FOUND_HWND: AtomicIsize = AtomicIsize::new(0);

extern "system" fn enum_cb(hwnd: isize, _l: isize) -> BOOL {
    let mut pid = 0u32;
    unsafe { GetWindowThreadProcessId(hwnd, &mut pid) };
    if pid == unsafe { GetCurrentProcessId() } && unsafe { IsWindowVisible(hwnd) } != 0 {
        FOUND_HWND.store(hwnd, Ordering::SeqCst);
        return 0; // stop enumeration
    }
    1
}

fn game_window() -> isize {
    FOUND_HWND.store(0, Ordering::SeqCst);
    unsafe { EnumWindows(enum_cb, 0) };
    FOUND_HWND.load(Ordering::SeqCst)
}

fn post_key(vk: u16) -> bool {
    let h = game_window();
    if h == 0 {
        return false;
    }
    unsafe {
        PostMessageW(h, WM_KEYDOWN, vk as usize, 0x0000_0001);
        PostMessageW(h, WM_KEYUP, vk as usize, 0xC000_0001u32 as isize);
    }
    true
}

// ───────────────────────── boot-phase monitor ─────────────────────────
fn now_ms() -> i64 {
    let f = FREQ.load(Ordering::Relaxed);
    if f == 0 {
        return 0;
    }
    (real_qpc() as i128 * 1000 / f as i128) as i64
}

fn read_bytes() -> u64 {
    let mut c = IO_COUNTERS::default();
    unsafe { GetProcessIoCounters(GetCurrentProcess(), &mut c) };
    c.read_tx
}

// SKIP mode: the clock runs at 1x the whole time (loading untouched). We watch
// the QueryPerformanceCounter call rate; the hold is a QPC spin (~1.2M
// calls/poll) with the disk idle after the bulk load is read. On that signature
// we add a clock offset past the gate's deadline, once per gate.
fn monitor() {
    let cfg = CFG.get().unwrap();
    // Relative spin trigger: the hold's busy-wait spins QueryPerformanceCounter
    // far faster than the pre-intro loading code, and both scale with CPU speed,
    // so we arm when dq exceeds (pre-intro peak * SPIN_MULT), floored. No fixed
    // hardware-tuned threshold -- it auto-scales to slow and fast CPUs alike.
    const SPIN_MULT: u64 = 2;
    const SPIN_FLOOR: u64 = 50_000;
    const WINDOW: usize = 12; // ~1s read-rate, for the diagnostic log only
    const CAP: u32 = 8; // total-jump ceiling (bounds banked offset; normally 1-3)
    const COLLAPSE_STOP: u32 = 3; // disarm/done after the spin stays collapsed this many polls
    log(&format!(
        "[fastboot] SKIP v1.3.1: intro='{}' jump={}ms poll={}ms spin>=max(baseline*{},{})",
        cfg.intro_video, cfg.jump_ms, cfg.poll_ms, SPIN_MULT, SPIN_FLOOR
    ));
    let t0 = now_ms();
    let mut pq = QPC_N.load(Ordering::Relaxed);
    let mut ring = [0u64; 32]; // cumulative-read samples -> rolling read total (diagnostic)
    let mut ri = 0usize;
    let mut filled = 0usize;
    let mut jumps = 0u32;
    let mut total = 0i64;
    let mut done = false;
    // enter_spammer: after the skip, post Enter on a fast interval for a bounded
    // window to clear the press-start prompts and start the game.
    let mut disarm_t = 0i64;
    let mut last_enter_t = 0i64;
    let mut enters = 0u32;
    let mut spam_done_logged = false;
    let mut last_jump = 0i64; // re-fire cooldown
    let mut peak_dq = 0u64; // diagnostic
    let mut baseline = 0u64; // max dq/poll seen before the intro opened
    let mut armed = false; // playback started -> begin periodic jumping
    let mut arm_pending = false; // a spin spike awaiting next-poll confirmation
    let mut intro_open_t = 0i64; // when the intro window first opened
    let mut collapse = 0u32; // consecutive polls with the spin collapsed (post-arm)
    let mut cycle_jumps = 0u32; // jumps landed in the current arm cycle (reset on each arm)
    loop {
        unsafe { Sleep(cfg.poll_ms) };
        let t = now_ms();
        let el = t - t0;

        let cum = read_bytes();
        let q = QPC_N.load(Ordering::Relaxed);
        let dq = q.wrapping_sub(pq);
        pq = q;

        // rolling disk-read total over the trailing WINDOW polls (~1s) -- kept for
        // the diagnostic log only (distinguishes "missed hold" from "no hold").
        let ago = ring[(ri + 32 - WINDOW) % 32];
        let window_read = if filled >= WINDOW { cum.wrapping_sub(ago) } else { u64::MAX };
        ring[ri] = cum;
        ri = (ri + 1) % 32;
        if filled < 32 {
            filled += 1;
        }
        // Before the intro opens, the highest QPC rate we see is loading code;
        // the hold spins well above it. Arm relative to that baseline.
        if !INTRO_OPEN.load(Ordering::Relaxed) && dq > baseline {
            baseline = dq;
        }
        let spin_min = baseline.saturating_mul(SPIN_MULT).max(SPIN_FLOOR);
        let spin = dq >= spin_min;

        // Stop the file-open probe if no gate ever fires (bounds gameplay cost).
        if WATCH_FILES.load(Ordering::Relaxed) && el > 180_000 {
            WATCH_FILES.store(false, Ordering::Relaxed);
        }

        // Compact always-on diagnostic: each new spin peak, with the current
        // relative threshold and disk read-rate, so a field log shows whether the
        // hold crossed the bar and what the disk was doing.
        if dq > 200_000 && dq > peak_dq {
            peak_dq = dq;
            log(&format!(
                "[{}ms] spin peak {}/poll (thr={}, window={}B)",
                el, dq, spin_min,
                if window_read == u64::MAX { 0 } else { window_read }
            ));
        }
        // Per-poll trace inside the intro window (until done): shows the bursty
        // pacing spin and arming so an intermittent miss is fully diagnosable.
        if INTRO_OPEN.load(Ordering::Relaxed) && !done {
            log(&format!(
                "[{}ms] win dq={} thr={} armed={} jumps={} window={}B",
                el, dq, spin_min, armed as u8, jumps,
                if window_read == u64::MAX { 0 } else { window_read }
            ));
        }

        // F8: manual skip. Each press jumps the clock now, collapsing whatever
        // timed wait is on screen -- a hands-on fallback if auto-skip ever misses
        // and the intro is playing. Works regardless of armed/done state.
        if (unsafe { GetAsyncKeyState(0x77) } as u16) & 0x8000 != 0 {
            jump_clock(cfg.jump_ms);
            total += cfg.jump_ms;
            log(&format!("[{}ms] F8 -> manual skip (clock +{}ms, total +{}ms)", el, cfg.jump_ms, total));
            unsafe { Sleep(200) }; // debounce
        }

        // The gate. Act strictly inside the intro video's window (BinkOpen ->
        // BinkClose) -- that scope, not a disk heuristic, excludes menu/gameplay.
        // Then jump every 400ms UNCONDITIONALLY -- the pacing spin is bursty and
        // dips below threshold between frames, so a per-jump spin gate would miss
        // re-fires (verified in field traces). Stop when the spin stays collapsed
        // for COLLAPSE_STOP polls, or at BinkClose, or on the jump-cap / timeout.
        if !done && INTRO_OPEN.load(Ordering::Relaxed) {
            if intro_open_t == 0 {
                intro_open_t = t;
            }
            // Done is latched only when the intro video actually ends (BinkClose),
            // or on the safety backstops. NOT on a spin collapse -- a pre-playback
            // transient collapses too, and the real hold can start right after it.
            // BinkClose only ends us if we actually jumped (a 0-jump close is an
            // early/mistagged handle, not our skip). Effective-collapse (below) is
            // the primary stop; cap/timeout are backstops.
            if (INTRO_CLOSED.load(Ordering::Relaxed) && jumps >= 1) || jumps >= CAP || el > 90_000 {
                done = true;
                disarm_t = t;
                WATCH_FILES.store(false, Ordering::Relaxed);
                log(&format!(
                    "[{}ms] intro window done (closed={}, {} jumps, total +{}ms)",
                    el, INTRO_CLOSED.load(Ordering::Relaxed) as u8, jumps, total
                ));
                if cfg.enter_spammer {
                    log(&format!(
                        "[{}ms] enter_spammer: Enter every {}ms for {}ms",
                        el, cfg.enter_interval_ms, cfg.enter_window_ms
                    ));
                }
            } else {
                // Arm when a spin spike is confirmed by the next poll still active.
                // Purely relative to this boot's own rate -- no time/clock constant.
                if !armed {
                    let active = dq >= spin_min / 2;
                    if arm_pending && active {
                        armed = true;
                        collapse = 0;
                        cycle_jumps = 0;
                        last_jump = t; // first jump fires one cadence later, not now,
                                       // so a sub-400ms transient never lands a jump
                        log(&format!("[{}ms] armed ({}ms after intro open)", el, t - intro_open_t));
                    } else {
                        arm_pending = spin;
                    }
                }
                if armed {
                    if dq < spin_min / 2 {
                        collapse += 1;
                    } else {
                        collapse = 0;
                    }
                    if collapse >= COLLAPSE_STOP {
                        if cycle_jumps >= 1 {
                            // We landed a jump on a running hold and it then
                            // collapsed: a genuine skip. Stop for good, independent
                            // of BinkClose (so the menu render can't re-arm us).
                            done = true;
                            disarm_t = t;
                            WATCH_FILES.store(false, Ordering::Relaxed);
                            log(&format!(
                                "[{}ms] intro window done (collapsed after {} jumps, total +{}ms)",
                                el, cycle_jumps, total
                            ));
                            if cfg.enter_spammer {
                                log(&format!(
                                    "[{}ms] enter_spammer: Enter every {}ms for {}ms",
                                    el, cfg.enter_interval_ms, cfg.enter_window_ms
                                ));
                            }
                        } else {
                            // Armed on a transient that vanished before any jump
                            // landed -> not the hold. Disarm and stay re-armable.
                            armed = false;
                            arm_pending = false;
                            collapse = 0;
                            log(&format!("[{}ms] disarmed (transient, no jump landed -> re-armable)", el));
                        }
                    } else if (t - last_jump) > 400 {
                        jump_clock(cfg.jump_ms);
                        jumps += 1;
                        cycle_jumps += 1;
                        total += cfg.jump_ms;
                        last_jump = t;
                        log(&format!(
                            "[{}ms] GATE jump (intro window, dq={}, thr={}, window={}B) -> +{}ms (total +{}ms, #{})",
                            el, dq, spin_min, window_read, cfg.jump_ms, total, jumps
                        ));
                    }
                }
            }
        }

        // enter_spammer: post Enter rapidly through the post-skip prompts, then stop.
        if cfg.enter_spammer && done {
            let since_disarm = t - disarm_t;
            if since_disarm < cfg.enter_window_ms {
                if t - last_enter_t >= cfg.enter_interval_ms {
                    post_key(VK_RETURN as u16);
                    last_enter_t = t;
                    enters += 1;
                }
            } else if !spam_done_logged {
                spam_done_logged = true;
                log(&format!("[{}ms] enter_spammer: done ({} Enter sent)", el, enters));
            }
        }
    }
}

// ───────────────────────── entry points ─────────────────────────
extern "system" fn worker(_: *mut c_void) -> u32 {
    let _ = CFG.set(load_config());
    log("[fastboot] worker start");
    install_hooks();
    log("[fastboot] hooks enabled");
    monitor();
    0
}

#[no_mangle]
pub extern "system" fn DllMain(h: HMODULE, reason: u32, _: *mut c_void) -> BOOL {
    const DLL_PROCESS_ATTACH: u32 = 1;
    if reason == DLL_PROCESS_ATTACH {
        init_proxy(); // must be ready before the game calls any version.dll API
        unsafe {
            DisableThreadLibraryCalls(h);
            CreateThread(
                core::ptr::null(),
                0,
                worker,
                core::ptr::null_mut(),
                0,
                core::ptr::null_mut(),
            );
        }
    }
    1
}
