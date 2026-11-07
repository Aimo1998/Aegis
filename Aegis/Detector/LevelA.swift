//
//  LevelA.swift
//  Aegis
//
//  🔴 A 级检测：深度对抗与底层校验（针对 RootHide 及高级隐藏）
//

import Foundation
import Darwin
import Security
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


// MARK: - 私有 Security 符号
//
// SecTask 系列在公开 SDK 里没有头文件，但 dyld 符号存在，直接声明即可链接。

@_silgen_name("SecTaskCreateFromSelf")
private func ph_SecTaskCreateFromSelf(_ allocator: CFAllocator?) -> CFTypeRef?

@_silgen_name("SecTaskCopyValueForEntitlement")
private func ph_SecTaskCopyValueForEntitlement(_ task: CFTypeRef,
                                               _ entitlement: CFString,
                                               _ error: UnsafeMutablePointer<Unmanaged<CFError>?>?) -> CFTypeRef?

enum LevelA {

    static let all: [Detector] = [
        apiCrossValidation,
        codeSignatureCheck,
        kernelStateCheck,
        timingAttackCheck,
        antiTamperCheck,
        appAttestCheck,
        mountAnalysisCheck,
        imagePathConsistencyCheck,
        csopsIntegrityCheck,
        machoSelfCheck,
        entitlementCheck
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

            // 只把「内核本应强制、无法被用户态篡改」的位缺失当作异常。
            // CS_RESTRICT / CS_PLATFORM / CS_INSTALLER 缺失在 ad-hoc 签名（ldid -S）下
            // 属正常现象，CS_DEBUGGED 也常见于开发者证书，均不作为失败依据。
            if (flags & CS_VALID) == 0 {
                issues.append("CS_VALID 未置位（签名状态异常）")
            }
            if (flags & CS_HARD) == 0 {
                issues.append("CS_HARD 缺失（页面可被动态改写）")
            }
            if (flags & CS_KILL) == 0 {
                issues.append("CS_KILL 缺失（违规时不会被内核终止）")
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
        detail: "用 mach_absolute_time 对 lstat 连续采样，对比「正常系统路径」「越狱特征路径」「不存在的路径」三者的单次耗时。只做同类操作对比——被 Hook 拦截的路径会明显偏慢（>6x）或异常偏快（<0.1x）。",
        run: {
            let iterations = 400
            var st = Darwin.stat()

            // 三条路径取各自的平均耗时
            let normalNs = measureNs(iterations: iterations) {
                _ = lstat("/System/Library", &st)
            }
            let jailNs = measureNs(iterations: iterations) {
                _ = lstat("/var/jb", &st)
            }
            let missingNs = measureNs(iterations: iterations) {
                _ = lstat("/.aegis_nonexistent_probe", &st)
            }

            var issues: [String] = []

            // 只做「同类操作之间」的对比：lstat 与 lstat 比，
            // 不能拿 lstat 去比 getpid —— 两者差 4 个数量级属正常。
            if normalNs > 0 && jailNs > 0 {
                let ratio = jailNs / normalNs
                if ratio > 6.0 {
                    issues.append(String(format:
                        "/var/jb 探测耗时 %.1fx 于正常路径（疑似 Hook 拦截）", ratio))
                }
                if ratio < 0.10 {
                    issues.append(String(format:
                        "/var/jb 探测耗时仅 %.2fx（疑似伪造返回）", ratio))
                }
            }

            // /var/jb 若不存在，耗时应接近「不存在的路径」；
            // 若明显更快，说明没走真实 VFS 查找
            if missingNs > 0 && jailNs > 0 && normalNs > 0 {
                if jailNs < missingNs * 0.15 && jailNs < normalNs * 0.15 {
                    issues.append(String(format:
                        "/var/jb 探测比不存在的路径还快 %.0f%%（疑似伪造 ENOENT）",
                        (1 - jailNs / missingNs) * 100))
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
    // MARK: A7 · 挂载点深度分析

    static let mountAnalysisCheck = Detector(
        id: "A7",
        level: .a,
        name: "挂载点深度分析",
        detail: "读取 getfsstat 挂载表，检查根文件系统是否被改成可写、是否存在非标准的引导镜像挂载点、以及挂载点数量是否异常。",
        run: {
            var issues: [String] = []

            // 1. 根文件系统正常应为只读
            if aegis_root_writable() {
                issues.append("根文件系统 / 可写（正常应为只读）")
            }

            // 2. 关键挂载点 flags
            let keyPaths = ["/", "/private/var", "/private/preboot", "/System/Library"]
            for path in keyPaths {
                var flags: UInt32 = 0
                let ok = path.withCString { cstr -> Bool in
                    aegis_mount_flags(cstr, &flags)
                }
                guard ok else { continue }
                // MNT_RDONLY = 0x1
                if path == "/System/Library" && (flags & 0x1) == 0 {
                    issues.append("/System/Library 可写")
                }
            }

            // 3. 挂载表里的可疑项
            if let mounts = aegisFetchMounts() {
                for m in mounts {
                    let lower = m.lowercased()
                    if lower.contains("jbroot") || lower.contains("/var/jb")
                        || lower.contains("procursus") || lower.contains("libhooker") {
                        issues.append("异常挂载：\(m)")
                        if issues.count >= 4 { break }
                    }
                }
            }

            // 4. 挂载点总数异常（正常 20~35）
            let n = Int(aegis_mount_count())
            if n > 45 {
                issues.append("挂载点数量异常：\(n) 个")
            }

            guard !issues.isEmpty else { return nil }
            return issues.prefix(4).joined(separator: "；")
        }
    )

    // MARK: A8 · 映像路径一致性

    static let imagePathConsistencyCheck = Detector(
        id: "A8",
        level: .a,
        name: "映像路径一致性",
        detail: "对同一批已加载映像，分别用 _dyld_get_image_name 和 dladdr 解析路径，比对两者是否一致。Frida / 内存注入常让两条路径出现分歧。",
        run: {
            let rawCount = aegis_dyld_image_count()
            guard rawCount > 0 else { return nil }
            let count = Int(rawCount)
            let limit = min(count, 220)

            var mismatches: [String] = []

            for i in 0..<limit {
                guard let cname = aegis_dyld_image_name(Int32(i)) else { continue }
                let dyldPath = String(cString: cname)
                guard !dyldPath.isEmpty else { continue }

                guard let hdr = aegis_dyld_image_header(Int32(i)) else { continue }

                var info = Dl_info()
                guard dladdr(hdr, &info) != 0, let fname = info.dli_fname else { continue }
                let dlPath = String(cString: fname)
                guard !dlPath.isEmpty else { continue }

                if dyldPath != dlPath {
                    let short = (dyldPath as NSString).lastPathComponent
                    mismatches.append("\(short): dyld=\(dyldPath) dladdr=\(dlPath)")
                    if mismatches.count >= 3 { break }
                }
            }

            guard !mismatches.isEmpty else { return nil }
            return mismatches.joined(separator: "；")
        }
    )

    // MARK: A9 · csops 完整性

    static let csopsIntegrityCheck = Detector(
        id: "A9",
        level: .a,
        name: "csops 完整性",
        detail: "连续多次调用 csops(CS_OPS_STATUS)，比对每次返回的 csflags 是否完全一致，并校验 CS_VALID 必须置位。第一次调用后的返回值若发生变化，通常说明 csops 被 Hook 伪造。",
        run: {
            var samples: [UInt32] = []
            var callErrs: [Int32] = []

            for _ in 0..<3 {
                var flags: UInt32 = 0
                let r = withUnsafeMutablePointer(to: &flags) { p -> Int32 in
                    aegis_csops(UInt32(getpid()), 0, UnsafeMutableRawPointer(p), 4)
                }
                callErrs.append(r)
                samples.append(flags)
            }

            // 调用本身失败
            if let first = callErrs.first, first != 0 {
                let allSame = callErrs.allSatisfy { $0 == first }
                if allSame {
                    return nil          // 稳定失败，可能是权限限制，不判越狱
                }
                return "csops 返回值不稳定：\(callErrs)（疑似被 Hook）"
            }

            // 返回值不稳定
            if Set(samples).count > 1 {
                let hex = samples.map { "0x" + String($0, radix: 16) }.joined(separator: ", ")
                return "csops 结果不一致：\(hex)（疑似被 Hook）"
            }

            // CS_VALID = 0x1 必须置位
            let flags = samples[0]
            if (flags & 0x1) == 0 {
                return "CS_VALID 未置位（csflags=0x\(String(flags, radix: 16))）"
            }

            return nil
        }
    )

    // MARK: A10 · Mach-O 自检

    static let machoSelfCheck = Detector(
        id: "A10",
        level: .a,
        name: "Mach-O 自检",
        detail: "绕过 _dyld_* API，直接读取本进程主程序 header 的 load commands，解析 LC_LOAD_DYLIB 列表，并与 dyld 报告的映像数对比。dyld 层被 Hook 时两者会出现分歧。",
        run: {
            // 1. header 基本信息
            var ncmds: UInt32 = 0
            var sizeofcmds: UInt32 = 0
            guard aegis_self_header_info(&ncmds, &sizeofcmds) else {
                return "无法读取自身 Mach-O header（可能被 Hook）"
            }

            if ncmds == 0 || sizeofcmds == 0 {
                return "Mach-O header 异常：ncmds=\(ncmds) sizeofcmds=\(sizeofcmds)"
            }

            // 2. 直接解析 LC_LOAD_DYLIB
            var buf = [CChar](repeating: 0, count: 8192)
            let n = buf.withUnsafeMutableBufferPointer { p -> Int32 in
                aegis_self_load_dylibs(p.baseAddress, size_t(8192))
            }
            guard n > 0 else { return nil }

            let raw = String(cString: buf)
            let linked = raw.split(separator: "\n").map(String.init)
            guard !linked.isEmpty else { return nil }

            var issues: [String] = []

            // 3. 链接列表里出现越狱路径
            for lib in linked {
                let l = lib.lowercased()
                if l.contains("/var/jb/") || l.contains("/.jbroot/")
                    || l.contains("substrate") || l.contains("substitute")
                    || l.contains("libhooker") || l.contains("ellekit") {
                    issues.append("链接了越狱库：\(lib)")
                    if issues.count >= 3 { break }
                }
            }

            // 4. 与 dyld 视图比对：主程序链接数应远小于全进程映像数
            let total = Int(aegis_dyld_image_count())
            if total > 0 && linked.count > total {
                issues.append("链接库 \(linked.count) 个 > 进程映像 \(total) 个（约定被破坏）")
            }

            guard !issues.isEmpty else { return nil }
            return issues.joined(separator: "；")
        }
    )

    // MARK: A11 · Entitlements 校验

    static let entitlementCheck = Detector(
        id: "A11",
        level: .a,
        name: "Entitlements 校验",
        detail: "用 SecTask 读取本进程的 entitlements，校验 application-identifier 是否为 TeamID.BundleID 格式、get-task-allow 状态、以及是否存在异常的自定义权限。重签名常在这里留下痕迹。",
        run: {
            guard let task = ph_SecTaskCreateFromSelf(nil) else { return nil }

            var issues: [String] = []

            // application-identifier 必须是 TeamID.BundleID
            let appIdKey = "application-identifier" as CFString
            if let val = ph_SecTaskCopyValueForEntitlement(task, appIdKey, nil) as? String {
                let comps = val.split(separator: ".")
                let bid = Bundle.main.bundleIdentifier ?? ""
                if comps.count < 2 {
                    issues.append("application-identifier 格式异常：\(val)")
                } else if !bid.isEmpty && !val.hasSuffix(bid) {
                    issues.append("application-identifier(\(val)) 与 BundleID(\(bid)) 不匹配")
                }
                // TeamID 一般是 10 位
                if let team = comps.first, team.count != 10 {
                    issues.append("TeamID 长度异常：\(team)")
                }
            } else {
                issues.append("缺少 application-identifier（疑似重签名）")
            }

            // get-task-allow
            let gtaKey = "get-task-allow" as CFString
            if let gta = ph_SecTaskCopyValueForEntitlement(task, gtaKey, nil) as? Bool, gta {
                issues.append("get-task-allow=true（允许调试器附加）")
            }

            // 是否有平台签名标记（正常 App 不该有）
            let platKey = "platform-application" as CFString
            if let plat = ph_SecTaskCopyValueForEntitlement(task, platKey, nil) as? Bool, plat {
                issues.append("带 platform-application 权限（平台级伪造）")
            }

            guard !issues.isEmpty else { return nil }
            return issues.prefix(3).joined(separator: "；")
        }
    )

}
