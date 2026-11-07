//
//  DetectorTextEN.swift
//  Aegis
//
//  28 项检测的英文说明（原理 / 绕过）
//

import Foundation

extension DetectorCatalog {

    static let detailEN: [String: String] = [
        "C1": "Probes 48 characteristic jailbreak paths (Cydia / Sileo, ssh, apt, Substrate, /var/jb …) using both lstat and FileManager.",
        "C2": "Uses canOpenURL to check whether jailbreak-only URL schemes are registered (cydia / sileo / filza …). Requires LSApplicationQueriesSchemes in Info.plist.",
        "C3": "Attempts to write a probe file outside the sandbox and to fork a child process. Both should fail inside a normal iOS sandbox.",
        "C4": "Inspects DYLD_INSERT_LIBRARIES, DYLD_FRAMEWORK_PATH and 6 more injection-related variables, flagging any value pointing outside system directories.",
        "C5": "Detects the simulator via TARGET_OS_SIMULATOR and hw.machine, then verifies real biometric hardware through LocalAuthentication's biometryType.",

        "B1": "Probes /var/jb, /.jbroot and other rootless mount points with the raw SYS_lstat, then scans the getfsstat mount table for jbroot entries.",
        "B2": "Walks _dyld_image_count to enumerate every loaded dylib, matching ElleKit / MobileSubstrate / Substitute / libhooker / systemhook and 11 more signatures.",
        "B3": "Resolves the IMPs of key methods on UIApplication / UIView / UISwitch, then uses dladdr to find which image they belong to. An IMP owned by a jailbreak dylib means the method was hooked.",
        "B4": "Checks the sysctl P_TRACED flag, the ptrace(PT_DENY_ATTACH) return value, and probes Frida's default ports 27042-27044 plus gum_* symbols.",
        "B5": "Walks mach_vm_region counting pages that are both writable and executable while not belonging to any loaded image — a typical code-injection trace.",
        "B6": "Pulls the full process list via sysctl KERN_PROC_ALL and matches jailbreak daemons (jailbreakd, linjector, frida-server, dropbear … 19 signatures).",
        "B7": "Uses lstat (no follow) to check whether /var/jb or /.jbroot is itself a symlink, and reads the target. Links pointing into /private/preboot are Dopamine's normal layout and are skipped.",
        "B8": "Calls lstat on each jailbreak path and records errno, distinguishing \"not found (ENOENT)\" from \"exists but denied (EACCES / EPERM)\". The latter means the path is real.",
        "B9": "canOpenURL only returns real results for schemes declared in LSApplicationQueriesSchemes. This check lists undeclared jailbreak schemes, marking blind spots in C2.",
        "B10": "Reads LC_ENCRYPTION_INFO_64 from its own Mach-O and checks cryptid. App Store binaries ship encrypted (1); self-signed or jailbreak-deployed ones are 0.",
        "B11": "Counts loaded dylibs. A normal iOS app loads 150~320; far more suggests bulk injection, far fewer suggests a trimmed environment.",
        "B12": "Scans loopback for common backdoor and debug ports: 22 (ssh), 1337, 4444, 8080, 9090, 31337, 27042~27044 (Frida).",

        "A1": "Queries the same path through libc lstat and raw SYS_lstat, comparing return value, inode and file type, then cross-checks with FileManager. Disagreement exposes a hook.",
        "A2": "Reads csflags via csops(CS_OPS_STATUS) and checks whether CS_VALID was forced on, CS_DEBUGGED stripped, CS_HARD / CS_KILL removed, or CS_PLATFORM / CS_INSTALLER missing.",
        "A3": "Reads kern.bootargs for -s / amfi_get_out_of_my_way and scans the getfsstat mount table for anomalous entries.",
        "A4": "Samples lstat with mach_absolute_time and compares the per-call cost of a normal path, a jailbreak path and a nonexistent path. Only like-for-like comparisons are used.",
        "A5": "Verifies that the addresses of lstat / getfsstat / sysctl / ptrace / csops still fall inside legitimate images (catching inline hooks and forged PAC), cross-checked with dladdr.",
        "A6": "Calls Apple DeviceCheck / App Attest. Needs the appattest entitlement from a paid developer account; auto-skips when unavailable.",
        "A7": "Reads the getfsstat table checking whether / became writable, whether /System/Library lost MNT_RDONLY, and whether the mount count is abnormal.",
        "A8": "For the same loaded image, resolves the path through both _dyld_get_image_name and dladdr and compares them. Frida and memory injection often make the two diverge.",
        "A9": "Calls csops(CS_OPS_STATUS) three times, comparing the returned csflags. Any variation between calls indicates a hooked csops; CS_VALID must also be set.",
        "A10": "Bypasses _dyld_* and parses the main executable's load commands directly, extracting LC_LOAD_DYLIB entries and cross-checking them against the dyld view.",
        "A11": "Reads its own entitlements through SecTask and validates application-identifier, get-task-allow and platform-application. Resigning always leaves traces here."
    ]

    static let bypassEN: [String: String] = [
        "C1": "RootHide redirects paths per-process so the app never sees the real file tree",
        "C2": "Uninstall the jailbreak tool's app and the scheme disappears with it",
        "C3": "The sandbox is enforced by the kernel; bypassing it means editing the sandbox profile",
        "C4": "Clear DYLD_* at launch, or start the app from launchd with a clean environment",
        "C5": "A simulator cannot fake Secure Enclave; real devices pass this by default",

        "B1": "RootHide uses a randomized mount point and hooks stat so it stays invisible",
        "B2": "In-memory-only injection (never touches disk) plus library renaming, at the cost of functionality",
        "B3": "Would require forging IMP provenance so dladdr resolves to a legitimate system library",
        "B4": "Hide the Frida port and thread names; ptrace interception needs kernel cooperation",
        "B5": "Drop RWX back to RX after injecting, or use copy-on-write",
        "B6": "Rename the daemons and isolate them into a separate namespace",
        "B7": "Symlinks can be replaced by firmlinks or never written to disk",
        "B8": "Rewrite EACCES / EPERM into ENOENT — requires hooking the sandbox check itself",
        "B9": "A local configuration issue; fix by completing Info.plist rather than changing the environment",
        "B10": "cryptid is set by Apple at distribution time and cannot be forged locally",
        "B11": "Trim the tweak set to bring the count back into range",
        "B12": "Stop the ssh / Frida / panel services — a purely behavioral signature",

        "A1": "Must hook both libc and the raw syscall identically, which is very easy to get wrong",
        "A2": "csflags is kernel-maintained; TrustCache needs a kernel patch",
        "A3": "bootargs is read-only; the mount table can be isolated with a mount namespace",
        "A4": "The interposer would have to match real VFS timing to the microsecond",
        "A5": "Requires forging an entire pointer chain and image provenance",
        "A6": "Needs a paid developer certificate plus server-side App Attest validation",
        "A7": "Mount flags are kernel-owned; only entries can be hidden, flags cannot be forged",
        "A8": "Must hook both dyld and dladdr and return the same path from each",
        "A9": "csops is a private syscall; keeping several calls perfectly consistent after hooking is hard",
        "A10": "Would need to tamper with load commands and the dyld view at the same time",
        "A11": "Entitlements are bound by the kernel signature; resigning always changes application-identifier"
    ]
}
