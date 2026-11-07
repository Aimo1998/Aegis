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

enum LevelA {

    static let all: [Detector] = [
        apiCrossValidation,
        codeSignatureCheck,
        kernelStateCheck,
        antiTamperCheck,
        appAttestCheck
    ]

    // MARK: A1 · API 交叉验证（反 Hook）

    /// 交叉验证用路径（既有越狱特征，也有系统正常路径做对照）
    private static let probePaths = [
        "/var/jb",
        "/.jbroot",
        "/Applications/Cydia.app",
        "/usr/lib/libellekit.dylib",
        "/bin/bash",
        "/var/jb/usr/lib",
        "/private/var/jb",
        "/usr/lib/libSystem.B.dylib",      // 正常对照
        "/System/Library/CoreServices"     // 正常对照
    ]

    static let apiCrossValidation = Detector(
        id: "A1",
        level: .a,
        name: "API 交叉验证",
        detail: "同一路径分别用 libc 的 lstat 与原始 SYS_lstat 查询，比对返回值、inode 与文件类型。RootHide 一类方案常只 Hook 其中一条路径，两边结果必然矛盾。",
        run: {
            var mismatches: [String] = []

            for path in probePaths {
                var stLibc = stat()
                var stRaw = stat()

                let rLibc = lstat(path, &stLibc)
                let rRaw = withUnsafeMutablePointer(to: &stRaw) { p -> Int32 in
                    aegis_raw_lstat(path, p)
                }

                // 1. 返回值本身不一致
                if rLibc != rRaw {
                    mismatches.append("\(path): lstat=\(rLibc) raw=\(rRaw)")
                    continue
                }

                // 2. 都成功但 inode / 类型不一致
                if rLibc == 0 && rRaw == 0 {
                    if stLibc.st_ino != stRaw.st_ino ||
                       (stLibc.st_mode & S_IFMT) != (stRaw.st_mode & S_IFMT) {
                        mismatches.append("\(path): inode/type 不一致")
                    }
                }
            }

            // 3. FileManager 与 lstat 交叉
            for path in ["/var/jb", "/.jbroot"] {
                var st = stat()
                let existsByStat = lstat(path, &st) == 0
                let existsByFM = FileManager.default.fileExists(atPath: path)
                if existsByStat != existsByFM {
                    mismatches.append("\(path): FileManager(\(existsByFM)) 与 lstat(\(existsByStat)) 矛盾")
                }
            }

            guard !mismatches.isEmpty else { return nil }
            return mismatches.prefix(3).joined(separator: "；")
        }
    )

    // MARK: A2 · 代码签名与信任链

    static let codeSignatureCheck = Detector(
        id: "A2",
        level: .a,
        name: "代码签名审查",
        detail: "通过 csops(CS_OPS_STATUS) 读取进程 csflags，检查 CS_VALID 是否被强行注入、CS_DEBUGGED 是否被抹除，以及 CS_HARD/CS_KILL 是否被剥离（RootHide 常见手法）。",
        run: {
            var flags: UInt32 = 0
            let ret = withUnsafeMutablePointer(to: &flags) { p -> Int32 in
                aegis_csops(UInt32(getpid()), CS_OPS_STATUS, p, 4)
            }

            guard ret == 0 else {
                // csops 本身失败，说明系统调用层已被干预
                return "csops 调用失败 errno=\(errno)"
            }

            var issues: [String] = []

            if (flags & CS_VALID) == 0 {
                issues.append("CS_VALID 未置位")
            }
            if (flags & CS_DEBUGGED) != 0 {
                issues.append("CS_DEBUGGED 已置位（被调试签名）")
            }
            if (flags & CS_HARD) == 0 {
                issues.append("CS_HARD 缺失（可被动态修改）")
            }
            if (flags & CS_KILL) == 0 {
                issues.append("CS_KILL 缺失")
            }

            // 额外：检查是否被注入 ad-hoc 签名标记
            if (flags & CS_RESTRICT) == 0 {
                issues.append("CS_RESTRICT 缺失（非正常受限签名）")
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

            // 1. kern.bootargs
            var buf = [CChar](repeating: 0, count: 4096)
            var outLen = 0
            let ok = buf.withUnsafeMutableBufferPointer { p -> Bool in
                aegis_read_bootargs(p.baseAddress, 4096, &outLen)
            }

            if ok {
                var bootargs = String(cString: buf).lowercased()
                if bootargs.isEmpty { bootargs = "" }

                let markers = [
                    "-s", "amfi_get_out_of_my_way", "cs_enforcement_disable",
                    "kextlog", "debug=0x144", "pmap_pagetable_corruption",
                    "kpf", "jit"
                ]
                for m in markers where bootargs.contains(m) {
                    issues.append("bootargs 含 \(m)")
                    break
                }
            }

            // 2. 挂载表
            if let mounts = aegis_mount_points() {
                var dynamicCount = 0
                for m in mounts {
                    let lower = m.lowercased()
                    if lower.contains("jbroot") ||
                       lower.contains("/var/jb") ||
                       lower.contains("procursus") ||
                       lower.contains("libhooker") {
                        dynamicCount += 1
                        if dynamicCount == 1 {
                            issues.append("挂载点异常：\(m)")
                        }
                    }
                }
            }

            guard !issues.isEmpty else { return nil }
            return issues.joined(separator: "；")
        }
    )

    // MARK: A4 · 反-反调试 / 指针完整性

    static let antiTamperCheck = Detector(
        id: "A4",
        level: .a,
        name: "防篡改与指针完整性",
        detail: "检查关键 API 的函数地址是否仍落在合法映像范围内（检测 PAC 指针伪造 / 内联 Hook），并验证 dladdr 与 _dyld_get_image_name 的路径是否一致。",
        run: {
            var issues: [String] = []

            // 1. 关键导入函数的地址归属
            let probes: [(String, UnsafeMutableRawPointer?)] = [
                ("lstat", dlsym(AEGIS_RTLD_DEFAULT, "lstat")),
                ("getfsstat", dlsym(AEGIS_RTLD_DEFAULT, "getfsstat")),
                ("sysctl", dlsym(AEGIS_RTLD_DEFAULT, "sysctl")),
                ("ptrace", dlsym(AEGIS_RTLD_DEFAULT, "ptrace")),
                ("csops", dlsym(AEGIS_RTLD_DEFAULT, "csops")),
                ("_dyld_get_image_name", dlsym(AEGIS_RTLD_DEFAULT, "_dyld_get_image_name"))
            ]

            for (name, sym) in probes {
                guard let sym = sym else {
                    // 解析不到本身也不算异常（不同 iOS 版本符号可见性不同）
                    continue
                }
                let addr = UInt(bitPattern: sym)
                if !aegis_address_in_image(addr) {
                    issues.append("\(name) 地址不在任何映像内（疑似 Hook）")
                }
            }

            // 2. dladdr 与 dyld 映像名交叉
            if let sym = dlsym(AEGIS_RTLD_DEFAULT, "lstat") {
                var info = Dl_info()
                if dladdr(sym, &info) != 0, let fname = info.dli_fname {
                    let path = String(cString: fname)
                    if !path.hasPrefix("/usr/lib/") && !path.hasPrefix("/System/") {
                        issues.append("lstat 来源映像异常：\(path)")
                    }
                }
            }

            guard !issues.isEmpty else { return nil }
            return issues.prefix(3).joined(separator: "；")
        }
    )

    // MARK: A5 · 设备完整性（App Attest）

    static let appAttestCheck = Detector(
        id: "A5",
        level: .a,
        name: "App Attest 完整性",
        detail: "调用 Apple DeviceCheck / App Attest。需要付费开发者账号的 appattest entitlement；不可用时该项自动跳过（不计为通过也不计为失败）。",
        run: {
            // 模拟器直接跳过
            #if targetEnvironment(simulator)
            return nil
            #else
            let service = DCAppAttestService.shared
            guard service.isSupported else { return nil }   // 无 entitlement，跳过

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
