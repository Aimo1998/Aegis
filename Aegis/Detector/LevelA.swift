//
//  LevelA.swift
//  Aegis
//
//  🔴 A 级检测：深度对抗与底层校验（针对 RootHide 及高级隐藏）
//

import Foundation
import Darwin
import DeviceCheck

// Swift 无法使用 C 的 #define 数值宏，这里等价定义一份
private let AEGIS_RTLD_DEFAULT = UnsafeMutableRawPointer(bitPattern: -2)!
private let CS_OPS_STATUS: UInt32 = 0x00000000
private let CS_VALID: UInt32     = 0x00000001
private let CS_HARD: UInt32      = 0x00000100
private let CS_KILL: UInt32      = 0x00000200
private let CS_RESTRICT: UInt32  = 0x00000800
private let CS_DEBUGGED: UInt32  = 0x10000000
private let CS_PLATFORM: UInt32  = 0x00000400
private let CS_INSTALLER: UInt32 = 0x00080000

enum LevelA {

    static let all: [Detector] = [
        apiCrossValidation,
        codeSignatureCheck,
        kernelStateCheck,
        timingAttackCheck,
        antiTamperCheck,
        appAttestCheck
    ]

    // MARK: A1 · API 交叉验证

    private static let probePaths = [
        "/var/jb",
        "/.jbroot",
        "/Applications/Cydia.app",
        "/usr/lib/libellekit.dylib",
        "/bin/bash",
        "/var/jb/usr/lib",
        "/private/var/jb",
        "/usr/lib/libSystem.B.dylib",
        "/System/Library/CoreServices"
    ]

    static let apiCrossValidation = Detector(
        id: "A1",
        level: .a,
        name: "API 交叉验证",
        detail: "同一路径分别用 libc 的 lstat 与原始 SYS_lstat 查询，比对返回值、inode 与文件类型；再用 FileManager 做第三重交叉。RootHide 一类方案常只 Hook 其中一条路径，两边结果必然矛盾。",
        run: {
            var mismatches: [String] = []

            for path in probePaths {
                var stLibc = Darwin.stat()
                var stRaw = Darwin.stat()

                let rLibc = lstat(path, &stLibc)
                let rRaw = withUnsafeMutablePointer(to: &stRaw) { p -> Int32 in
                    aegis_raw_lstat(path, UnsafeMutableRawPointer(p))
                }

                if rLibc != rRaw {
                    mismatches.append("\(path): lstat=\(rLibc) raw=\(rRaw)")
                    continue
                }

                if rLibc == 0 && rRaw == 0 {
                    if stLibc.st_ino != stRaw.st_ino ||
                       (stLibc.st_mode & S_IFMT) != (stRaw.st_mode & S_IFMT) {
                        mismatches.append("\(path): inode/type 不一致")
                    }
                }
            }

            for path in ["/var/jb", "/.jbroot"] {
                var st = Darwin.stat()
                let byStat = lstat(path, &st) == 0
                let byFM = FileManager.default.fileExists(atPath: path)
                if byStat != byFM {
                    mismatches.append("\(path): FileManager(\(byFM)) 与 lstat(\(byStat)) 矛盾")
                }
            }

            guard !mismatches.isEmpty else { return nil }
            return mismatches.prefix(3).joined(separator: "；")
        }
    )

    // MARK: A2 · 代码签名与 TrustCache

    static let codeSignatureCheck = Detector(
        id: "A2",
        level: .a,
        name: "代码签名与 TrustCache",
        detail: "通过 csops(CS_OPS_STATUS) 读取 csflags，检查 CS_VALID 是否被强行注入、CS_DEBUGGED 是否被抹除、CS_HARD/CS_KILL 是否被剥离；同时判断是否缺少 CS_PLATFORM/CS_INSTALLER（ad-hoc 被塞进 TrustCache 的典型特征）。",
        run: {
            var flags: UInt32 = 0
            let ret = withUnsafeMutablePointer(to: &flags) { p -> Int32 in
                aegis_csops(UInt32(getpid()), CS_OPS_STATUS, UnsafeMutableRawPointer(p), 4)
            }

            guard ret == 0 else {
                return "csops 调用失败 errno=\(errno)（系统调用层被干预）"
            }

            var issues: [String] = []

            if (flags & CS_VALID) == 0 { issues.append("CS_VALID 未置位") }
            if (flags & CS_DEBUGGED) != 0 { issues.append("CS_DEBUGGED 已置位") }
            if (flags & CS_HARD) == 0 { issues.append("CS_HARD 缺失") }
            if (flags & CS_KILL) == 0 { issues.append("CS_KILL 缺失") }
            if (flags & CS_RESTRICT) == 0 { issues.append("CS_RESTRICT 缺失") }
            if (flags & CS_PLATFORM) == 0 && (flags & CS_INSTALLER) == 0 {
                issues.append("无 CS_PLATFORM/CS_INSTALLER（疑似 ad-hoc 入 TrustCache）")
            }

            guard !issues.isEmpty else { return nil }
            return "csflags=0x" + String(flags, radix: 16) + "：" + issues.joined(separator: "、")
        }
    )

    // MARK: A3 · 内核全局状态

    static let kernelStateCheck = Detector(
        id: "A3",
        level: .a,
        name: "内核状态探测",
        detail: "读取 kern.bootargs 检查是否带 -s / amfi_get_out_of_my_way 等越狱启动参数，并扫描 getfsstat 挂载表中是否有动态 jbroot 挂载点。",
        run: {
            var issues: [String] = []

            var buf = [CChar](repeating: 0, count: 4096)
            var outLen: size_t = 0
            let ok = buf.withUnsafeMutableBufferPointer { p -> Bool in
                aegis_read_bootargs(p.baseAddress, size_t(4096), &outLen)
            }

            if ok {
                let bootargs = String(cString: buf).lowercased()
                let markers = [
                    "amfi_get_out_of_my_way", "cs_enforcement_disable",
                    "kextlog", "debug=0x144", "kpf"
                ]
                for m in markers where bootargs.contains(m) {
                    issues.append("bootargs 含 \(m)")
                    break
                }
            }

            if let mounts = aegisFetchMounts() {
                for m in mounts {
                    let lower = m.lowercased()
                    if lower.contains("jbroot") || lower.contains("/var/jb")
                        || lower.contains("procursus") || lower.contains("libhooker") {
                        issues.append("挂载点异常：\(m)")
                        break
                    }
                }
            }

            guard !issues.isEmpty else { return nil }
            return issues.joined(separator: "；")
        }
    )

    // MARK: A4 · 计时攻击检测

    private static func measureNs(iterations: Int, _ block: () -> Void) -> Double {
        let t0 = mach_absolute_time()
        for _ in 0..<iterations { block() }
        let t1 = mach_absolute_time()

        var tb = mach_timebase_info_data_t()
        mach_timebase_info(&tb)
        let numer = Double(tb.numer)
        let denom = Double(tb.denom)
        let ns = Double(t1 - t0) * numer / denom
        return ns / Double(iterations)
    }

    static let timingAttackCheck = Detector(
        id: "A4",
        level: .a,
        name: "计时攻击检测",
        detail: "用 mach_absolute_time 对 stat 类调用连续采样，对比「正常系统路径」与「越狱特征路径」的单次耗时，并对比纯 syscall（getpid）基线。被 Hook 拦截的路径耗时会明显偏离正常区间。",
        run: {
            let iterations = 300
            var st = Darwin.stat()

            let normalNs = measureNs(iterations: iterations) {
                _ = lstat("/System/Library", &st)
            }
            let jailNs = measureNs(iterations: iterations) {
                _ = lstat("/var/jb", &st)
            }
            let sysNs = measureNs(iterations: iterations) {
                _ = getpid()
            }

            var issues: [String] = []

            if normalNs > 0 && sysNs > 0 {
                let ratio = normalNs / sysNs
                if ratio > 30 {
                    issues.append(String(format: "正常路径 lstat 耗时异常 (%.1fx syscall)", ratio))
                }
            }

            if normalNs > 0 && jailNs > 0 {
                let ratio = jailNs / normalNs
                if ratio > 4.0 {
                    issues.append(String(format: "/var/jb 探测耗时 %.1fx 于正常路径（疑似 Hook 拦截）", ratio))
                }
                if ratio < 0.15 {
                    issues.append(String(format: "/var/jb 探测耗时仅 %.2fx（疑似伪造返回）", ratio))
                }
            }

            guard !issues.isEmpty else { return nil }
            return issues.joined(separator: "；")
        }
    )

    // MARK: A5 · 反-反调试与指针完整性

    static let antiTamperCheck = Detector(
        id: "A5",
        level: .a,
        name: "防篡改与指针完整性",
        detail: "检查 lstat/getfsstat/sysctl/ptrace/csops 等关键 API 的函数地址是否仍落在合法映像范围内（检测内联 Hook 与 PAC 指针伪造），并用 dladdr 交叉验证其来源库路径。",
        run: {
            var issues: [String] = []

            let names = ["lstat", "getfsstat", "sysctl", "ptrace", "csops"]
            for name in names {
                guard let sym = dlsym(AEGIS_RTLD_DEFAULT, name) else { continue }
                let addr = UInt(bitPattern: sym)
                if !aegis_address_in_image(addr) {
                    issues.append("\(name) 地址不在任何映像内（疑似 Hook）")
                }
            }

            if let sym = dlsym(AEGIS_RTLD_DEFAULT, "lstat") {
                var info = Dl_info()
                if dladdr(sym, &info) != 0, let fname = info.dli_fname {
                    let path = String(cString: fname)
                    let lower = path.lowercased()
                    if lower.contains("/var/jb") || lower.contains("/.jbroot")
                        || lower.contains("substrate") || lower.contains("ellekit") {
                        issues.append("lstat 来源映像异常：\(path)")
                    }
                }
            }

            guard !issues.isEmpty else { return nil }
            return issues.prefix(3).joined(separator: "；")
        }
    )

    // MARK: A6 · 设备完整性（App Attest）

    static let appAttestCheck = Detector(
        id: "A6",
        level: .a,
        name: "App Attest 完整性",
        detail: "调用 Apple DeviceCheck / App Attest。需要付费开发者账号的 appattest entitlement；不可用时该项自动跳过（不计通过也不计失败）。",
        run: {
            #if targetEnvironment(simulator)
            return nil
            #else
            let service = DCAppAttestService.shared
            guard service.isSupported else { return nil }

            let sem = DispatchSemaphore(value: 0)
            var failure: String?

            service.generateKey { keyId, error in
                if let error = error {
                    failure = "generateKey 失败：\(error.localizedDescription)"
                } else if keyId == nil {
                    failure = "generateKey 未返回 keyId（环境异常）"
                }
                sem.signal()
            }
            _ = sem.wait(timeout: .now() + 8)

            return failure
            #endif
        }
    )
}
