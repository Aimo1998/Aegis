# Aegis

[点击切换到中文](README.md)

> A fully offline iOS jailbreak detection app — three escalating levels, 17 checks, covering everything from classic rootful jailbreaks to RootHide-grade concealment.

**Runs entirely offline. No network calls, no data leaves the device.**

```
🔵 Level C · Basic signatures     5 checks
🟡 Level B · Rootless & injection 6 checks
🔴 Level A · Deep anti-tamper     6 checks
```

---

## Features

- **Escalating levels**: C catches classic jailbreaks fast; B targets rootless (`/var/jb`) and injected frameworks; A is built for RootHide-style process isolation and hook masquerading
- **API cross-validation**: the same semantic queried through both `libc` and a raw `syscall`; any disagreement exposes a hook
- **Timing attack detection**: sampled with `mach_absolute_time` — return values can be forged, elapsed time cannot
- **IMP provenance check**: resolves key selectors' IMPs back through `dladdr` to detect methods redirected into dylibs under jailbreak paths
- **Zero third-party dependencies**: pure SwiftUI + Darwin + DeviceCheck
- **System info diagnostics page**: dumps every low-level value the checks rely on (sysctl / csops / lstat-vs-syscall / mount table / process table) so verdicts can be verified against reality
- **All low-level calls go through a C shim**: `fork` / `ptrace` / `_dyld_*` / `getfsstat` are either marked unavailable in Swift or have signatures that are painful to match — all wrapped in `AegisShim.c`

---

## Detection Matrix

### 🔵 Level C · Basic signatures (5)

| ID | Check | Implementation |
|---|---|---|
| C1 | Filesystem blacklist | `lstat` + `FileManager` over 48 characteristic paths (Cydia / Sileo / ssh / apt / Substrate / `/var/jb` …) |
| C2 | URL scheme probe | `canOpenURL` on 9 schemes (cydia / sileo / filza / zbra / trollstore …) |
| C3 | Sandbox escape & fork | Writes probes to `/private`, `/var/jb`, `/tmp`; attempts `syscall(SYS_fork)` |
| C4 | Environment variables | 8 variables incl. `DYLD_INSERT_LIBRARIES` / `DYLD_FRAMEWORK_PATH`, checked for non-system paths |
| C5 | Simulator & hardware | `TARGET_OS_SIMULATOR` + `hw.machine` + Secure Enclave / biometric hardware presence |

### 🟡 Level B · Rootless & injection (6)

| ID | Check | Implementation |
|---|---|---|
| B1 | Rootless path probe | Raw `SYS_lstat` against 10 rootless mount points + `getfsstat` mount-table scan |
| B2 | Injected framework scan | Walks `_dyld_image_count`, matching 16 signatures (ElleKit / MobileSubstrate / Substitute / libhooker / systemhook / TweakLoader …) |
| B3 | UI tampering | Resolves IMPs of 8 key selectors on `UIApplication` / `UIView` / `UISwitch` / `UIWindow` via `dladdr` |
| B4 | Debugger & anti-injection | `sysctl P_TRACED` + `PT_DENY_ATTACH` self-check + Frida ports 27042/27043/27044 + `gum_*` symbols |
| B5 | RWX memory | Walks `vm_region_64`, flagging W+X pages not owned by any loaded image |
| B6 | Process chain | `sysctl KERN_PROC_ALL`, matching 19 signatures (jailbreakd / linjector / frida-server / dropbear …) |

### 🔴 Level A · Deep anti-tamper (6)

| ID | Check | Implementation |
|---|---|---|
| A1 | API cross-validation | `lstat` (libc) vs `SYS_lstat` (raw syscall): compares return code / inode / file type, plus a third pass through `FileManager` |
| A2 | Code signing & TrustCache | `csops(CS_OPS_STATUS)` reads csflags, checking whether `CS_VALID` was injected, `CS_DEBUGGED` stripped, `CS_HARD`/`CS_KILL` removed, `CS_PLATFORM`/`CS_INSTALLER` missing |
| A3 | Kernel state | `kern.bootargs` for `amfi_get_out_of_my_way` / `cs_enforcement_disable`; `getfsstat` for anomalous mounts |
| A4 | Timing attack | `mach_absolute_time` over normal / jailbreak / nonexistent paths, comparing like-for-like |
| A5 | Anti-tamper & pointer integrity | Verifies key API addresses still fall inside legitimate images (inline hooks / forged PAC), cross-checked with `dladdr` |
| A6 | App Attest | `DCAppAttestService.generateKey`; auto-skips when the entitlement is absent |

---

## Installation

### Option 1: deb (jailbroken device, recommended)

```bash
dpkg -i Aegis.deb
```

`postinst` handles everything:

```bash
ldid -S /var/jb/Applications/Aegis.app/Aegis   # ad-hoc sign
chown -R root:wheel /var/jb/Applications/Aegis.app
uicache -p /var/jb/Applications/Aegis.app      # refresh icon cache
```

Uninstall:

```bash
dpkg -r com.aegis.detector
```

### Option 2: ipa (TrollStore / self-signing)

```bash
unzip -o Aegis.ipa -d /tmp/aegis
cp -R /tmp/aegis/Payload/Aegis.app /var/jb/Applications/
chown -R root:wheel /var/jb/Applications/Aegis.app
ldid -S /var/jb/Applications/Aegis.app/Aegis
uicache -p /var/jb/Applications/Aegis.app
```

Or simply hand the ipa to TrollStore.

> Tapping "Install" on an unsigned ipa via the system installer will fail — that is expected. iOS only accepts signed apps.

---

## Risk Scoring

Each of the 17 checks carries a weight (243 points total); the hit weight is scaled to a 0–100 risk score:

| Score | Tier | Meaning |
|---|---|---|
| 0 | Safe | Nothing triggered |
| 1–25 | Low | Only basic signatures (e.g. a leftover path) |
| 26–50 | Medium | Injection or debugging traces present |
| 51–75 | High | Several deep checks triggered at once |
| 76–100 | Critical | Low-level state is broadly inconsistent — typical RootHide pattern |

| ID | Weight | ID | Weight | ID | Weight |
|---|---|---|---|---|---|
| C1 | 8 | B1 | 12 | A1 | 25 |
| C2 | 6 | B2 | 15 | A2 | 20 |
| C3 | 15 | B3 | 18 | A3 | 15 |
| C4 | 10 | B4 | 12 | A4 | 22 |
| C5 | 5 | B5 | 15 | A5 | 25 |
| — | — | B6 | 10 | A6 | 10 |

> The verdict still follows "any trigger ⇒ 😢"; the score only expresses severity. To switch to a score-threshold verdict, modify `ScanReport.isJailbroken`.

---

## Bypass Hints

Expanding any ❌ row shows, besides the rationale and evidence, a **Bypass** line describing what it would take to fool that class of check:

```
❌ API cross-validation failed
   Idea     Queries the same path via lstat and SYS_lstat, comparing return / inode / type…
   Bypass   Would need to hook both libc and the raw syscall identically — very easy to get wrong
   Evidence /var/jb: lstat=0 raw=0, inode/type mismatch
```

This makes results more informative: you can tell at a glance which items are *hard* checks (A5 requires forging an entire pointer chain) and which are merely *soft* signatures (C2 disappears once the tool's app is uninstalled).

---

## App Modes

The `☰` button at the top-left switches between five modes:

| Mode | Content |
|---|---|
| 🛡 **Detect** | Pick a level → scan → results (with risk-score card) |
| 📚 **Images** | Lists every loaded dylib, grouped into 6 categories, jailbreak injections highlighted first |
| 🕒 **History** | Auto-archives each scan (max 60) and diffs against the previous run of the same level, marking new failures / recovered items |
| 🧪 **Red Team** | Self-tampers with its own IMP to validate B3 sensitivity; counts injected image visibility |
| 🧾 **System Info** | Raw low-level diagnostics: sysctl, csflags bit breakdown, lstat vs raw syscall, mount table, process table |

---

## Technical Notes

### Why every low-level call goes through a C shim

In Swift these symbols are either `unavailable` or have signatures that are painful to match:

| Symbol | Problem in Swift |
|---|---|
| `fork()` | `unavailable: Please use threads or posix_spawn*()` |
| `ptrace()` / `PT_DENY_ATTACH` | Neither symbol nor constants are exported; iOS SDK ships no `<sys/ptrace.h>` |
| `_dyld_image_count()` / `_dyld_get_image_name()` | Not exposed by `import Darwin` |
| `getfsstat()` | Array pointers and tuple rebinding are easy to get wrong |
| `csops()` | Private syscall, no libc wrapper |

All wrapped in `AegisShim.c`; the Swift side only calls simple interfaces:

```c
int  aegis_dyld_image_count(void);
const char *aegis_dyld_image_name(int index);
int  aegis_ptrace_deny_attach(void);
int  aegis_fork_raw(void);
int  aegis_mount_points(char *out, size_t outSize);
int  aegis_list_process_names(char *out, size_t outSize);
int  aegis_csops(uint32_t pid, uint32_t ops, void *useraddr, uint32_t usersize);
bool aegis_read_bootargs(char *buf, size_t bufSize, size_t *outLen);
```

### Why timing attacks work

RootHide-class solutions can tamper with return values and file attributes, but **cannot forge elapsed time at the same time**:

- Hooked path → intercept → evaluate → return a forged result ⇒ measurably slower (usually >4x)
- Straight-up forged ENOENT → skips the real VFS lookup ⇒ anomalously fast (<0.15x)

Only like-for-like comparisons are used (lstat vs lstat). Comparing `lstat` against `getpid()` is invalid — they differ by four orders of magnitude by design.

---

## Known Limitations

1. **A6 App Attest** requires the `com.apple.developer.devicecheck.appattest-environment` entitlement from a paid developer account; under free signing `isSupported` is false and the check auto-skips
2. **C2 URL schemes** must be declared in `Info.plist` under `LSApplicationQueriesSchemes`, otherwise `canOpenURL` always returns false
3. **Timing checks** depend on device load; under heavy load false positives are possible — tune the 4x / 0.15x thresholds as needed
4. **C5 hardware fingerprint** only recognizes explicit simulator architectures (`x86_64` / `arm64` / `i386`); unrecognized machine IDs are treated as real devices to avoid false positives
5. Results are advisory — **a single anomaly does not prove compromise**; judge by the overall hit count

---

## Project Structure

```
Aegis/
├── project.yml                      # XcodeGen project definition
├── build.sh                         # Local one-shot build
├── codemagic.yaml                   # Codemagic CI (produces deb + ipa)
├── release.sh                       # One-command GitHub release
├── .github/workflows/build-ipa.yml  # GitHub Actions
└── Aegis/
    ├── AegisApp.swift
    ├── Info.plist                   # Includes LSApplicationQueriesSchemes
    ├── AegisShim.h / .c             # syscall / ptrace / dyld / process table shims
    ├── Aegis-Bridging-Header.h
    ├── Assets.xcassets/AppIcon.appiconset/
    ├── Detector/
    │   ├── Models.swift             # Check model + aggregation + risk scoring
    │   ├── LevelC.swift             # 🔵 5 checks
    │   ├── LevelB.swift             # 🟡 6 checks
    │   ├── LevelA.swift             # 🔴 6 checks
    │   ├── ScanEngine.swift         # Scan scheduler
    │   ├── DylibScanner.swift       # Loaded-image enumeration & classification
    │   ├── HistoryStore.swift       # Scan history + weight/bypass metadata
    │   └── RedTeam.swift            # Self-tamper & injection visibility tests
    └── Views/
        ├── ContentView.swift        # Top bar + hamburger menu + home + scanning
        ├── ResultView.swift         # Results (score card, expandable evidence/bypass)
        ├── DylibListView.swift      # Loaded images
        ├── HistoryView.swift        # History & diff
        ├── RedTeamView.swift        # Red team self-test
        ├── SystemInfoView.swift     # System info diagnostics
        └── SharedFooter.swift       # Global signature footer
```

---

## Releasing

Release names follow a fixed format: **`Aegis v<version>`** (e.g. `Aegis v1.2.0`), with tag `v<version>`.

One command:

```bash
export GH_TOKEN=<a PAT with repo scope>
./release.sh 1.2.0 build/Aegis.deb build/Aegis.ipa
```

The script will:

1. Create a release named `Aegis v1.2.0` with tag `v1.2.0`
2. Upload `Aegis.deb` and `Aegis.ipa`
3. Print the release page URL

To supply custom notes, pass a Markdown file as the fourth argument:

```bash
./release.sh 1.2.0 build/Aegis.deb build/Aegis.ipa RELEASE_NOTES.md
```

---

## Requirements

- iOS **16.0+** (`kerning` / `tracking` and similar SwiftUI APIs need 16+)
- Build: Xcode 15+ / XcodeGen
- Tested on: Dopamine3 (arm64)

---

## Disclaimer

This project is intended for **security research and inspecting devices you own**. Results do not constitute a security verdict; do not use it to audit devices without authorization.

---

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.