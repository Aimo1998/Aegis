//
//  LevelB.swift
//  Aegis
//
//  🟡 B 级检测：现代环境与注入检测（针对无根越狱 Rootless）
//

import Foundation
import Darwin

private let AEGIS_RTLD_DEFAULT = UnsafeMutableRawPointer(bitPattern: -2)!

enum LevelB {

    static let all: [Detector] = [
        dyldInjectionScan,
        environmentCheck,
        debuggerCheck,
        fridaCheck,
        rwxMemoryCheck,
        rootlessPathCheck
    ]

    // MARK: B1 · 动态库注入扫描

    /// 越狱/注入框架特征（小写匹配）
    private static let injectionSignatures: [String] = [
        "ellekit",
        "mobilesubstrate",
        "cydia substrate",
        "substrate",
        "substitute",
        "libhooker",
        "tweakloader",
        "orion",
        "libblackjack",
        "jailbreak",
        "/var/jb/",
        "/.jbroot/",
        "/usr/lib/libhooker",
        "frida",
        "cycript",
        "libcolorpicker"
    ]

    static let dyldInjectionScan = Detector(
        id: "B1",
        level: .b,
        name: "动态库注入扫描",
        detail: "遍历 _dyld_image_count 枚举所有已加载的 dylib，匹配 ElleKit / MobileSubstrate / Substitute / libhooker 等特征。",
        run: {
            let count = _dyld_image_count()
            var hits: [String] = []

            for i in 0..<count {
                guard let cname = _dyld_get_image_name(i) else { continue }
                let name = String(cString: cname).lowercased()

                // 我们的 App 自身与系统库白名单
                if name.contains("/aegis.app/") { continue }

                for sig in injectionSignatures where name.contains(sig) {
                    // 系统自带的 /usr/lib 路径偶尔含 substrate 字样，用路径排除
                    if name.hasPrefix("/usr/lib/system/") || name.hasPrefix("/system/") { continue }
                    hits.append(String(cString: cname))
                    break
                }
                if hits.count >= 6 { break }
            }

            guard !hits.isEmpty else { return nil }
            return "发现 \(hits.count) 个可疑映像：" + hits.prefix(3).map {
                ($0 as NSString).lastPathComponent
            }.joined(separator: "、")
        }
    )

    // MARK: B2 · 环境变量审查

    private static let suspiciousEnvKeys = [
        "DYLD_INSERT_LIBRARIES",
        "DYLD_FORCE_FLAT_NAMESPACE",
        "DYLD_IMAGE_SUFFIX",
        "DYLD_LIBRARY_PATH",
        "DYLD_FRAMEWORK_PATH",
        "_MSSafeMode",
        "_SafeMode",
        "JB_ROOT",
        "JBROOT_PATH"
    ]

    static let environmentCheck = Detector(
        id: "B2",
        level: .b,
        name: "环境变量审查",
        detail: "检查 DYLD_INSERT_LIBRARIES 等注入相关环境变量是否被设置。正常 App 这些应为空。",
        run: {
            var found: [String] = []
            for key in suspiciousEnvKeys {
                if let v = getenv(key), String(cString: v).isEmpty == false {
                    found.append("\(key)=\(String(cString: v))")
                }
            }
            guard !found.isEmpty else { return nil }
            return found.prefix(3).joined(separator: "；")
        }
    )

    // MARK: B3 · 调试与追踪

    static let debuggerCheck = Detector(
        id: "B3",
        level: .b,
        name: "调试器 / 追踪检测",
        detail: "用 sysctl KERN_PROC 读取进程 kinfo_proc，检查 P_TRACED 标志；同时验证 ptrace(PT_DENY_ATTACH) 是否被绕过。",
        run: {
            var info = kinfo_proc()
            var size = MemoryLayout<kinfo_proc>.stride
            var mib: [Int32] = [CTL_KERN, KERN_PROC, KERN_PROC_PID, getpid()]

            let kr = mib.withUnsafeMutableBufferPointer { mibPtr in
                sysctl(mibPtr.baseAddress, 4, &info, &size, nil, 0)
            }

            var reasons: [String] = []

            if kr == 0 {
                let traced = (info.kp_proc.p_flag & P_TRACED) != 0
                if traced {
                    reasons.append("P_TRACED 已置位（进程被调试）")
                }
            } else {
                reasons.append("sysctl 返回异常 errno=\(errno)")
            }

            // ptrace PT_DENY_ATTACH 自检：正常返回 0 或 EPERM；被 hook 时常见返回 0 且无副作用
            let ptRet = ptrace(PT_DENY_ATTACH, 0, nil, nil)
            if ptRet == 0 && getppid() != 1 {
                // 父进程不是 launchd 且 ptrace 返回 0，存在被绕过嫌疑
                reasons.append("PT_DENY_ATTACH 返回值异常")
            }

            guard !reasons.isEmpty else { return nil }
            return reasons.joined(separator: "；")
        }
    )

    // MARK: B4 · Frida 探测

    private static let fridaPorts: [Int32] = [27042, 27043, 27044]

    static let fridaCheck = Detector(
        id: "B4",
        level: .b,
        name: "Frida 注入检测",
        detail: "探测 Frida 默认监听端口（27042/27043/27044），并扫描内存中是否残留 Frida 特征字符串。",
        run: {
            var hits: [String] = []

            for port in fridaPorts {
                if aegis_port_open(port, 250) {
                    hits.append("端口 \(port) 开放")
                }
            }

            // 内存特征：通过 dlsym 查找 frida 符号（Frida 会在进程里留下 gum-js-loop 线程）
            let fridaSyms = ["gum_init", "frida_agent_main", "gum_script_backend"]
            for s in fridaSyms {
                if dlsym(AEGIS_RTLD_DEFAULT, s) != nil {
                    hits.append("符号 \(s) 可解析")
                }
            }

            guard !hits.isEmpty else { return nil }
            return hits.joined(separator: "、")
        }
    )

    // MARK: B5 · RWX 内存段

    static let rwxMemoryCheck = Detector(
        id: "B5",
        level: .b,
        name: "RWX 内存段检测",
        detail: "遍历 mach_vm_region，统计同时具备写(W)与执行(X)权限、且不属于任何已加载映像的内存页。这通常是代码注入痕迹。",
        run: {
            let n = Int(aegis_count_rwx_regions())
            guard n > 0 else { return nil }
            return "发现 \(n) 个非映像归属的 RWX 内存页"
        }
    )

    // MARK: B6 · 无根越狱路径探测

    private static let rootlessCandidates = [
        "/var/jb",
        "/var/jb/usr",
        "/var/jb/usr/lib",
        "/var/jb/Library",
        "/var/jb/Applications",
        "/private/var/jb",
        "/.jbroot",
        "/var/LIB",
        "/var/containers/Bundle/tweaksupport",
        "/var/mobile/Library/Preferences/com.apple.Cydia"
    ]

    static let rootlessPathCheck = Detector(
        id: "B6",
        level: .b,
        name: "无根越狱路径探测",
        detail: "用原始 SYS_lstat 探测 /var/jb、/.jbroot 等无根越狱挂载点，并检查 getfsstat 挂载表中是否有异常 jbroot 挂载。",
        run: {
            var hits: [String] = []

            for path in rootlessCandidates {
                var st = Darwin.stat()
                let r = withUnsafeMutablePointer(to: &st) { p -> Int32 in
                    aegis_raw_lstat(path, UnsafeMutableRawPointer(p))
                }
                if r == 0 {
                    // /var/jb 在真机上仅越狱环境存在
                    hits.append(path)
                }
            }

            // 挂载表检查
            if let mounts = aegis_mount_points() {
                for m in mounts {
                    let lower = m.lowercased()
                    if lower.contains("jbroot") || lower.contains("/var/jb") || lower.contains("procursus") {
                        hits.append("挂载点 \(m)")
                    }
                }
            }

            guard !hits.isEmpty else { return nil }
            return hits.prefix(4).joined(separator: "、")
        }
    )
}

// MARK: - 辅助

/// 通过 getfsstat 取挂载点
func aegis_mount_points() -> [String]? {
    let count = getfsstat(nil, 0, MNT_NOWAIT)
    guard count > 0 else { return nil }

    var buf = [statfs](repeating: statfs(), count: Int(count))
    let size = Int32(MemoryLayout<statfs>.stride * Int(count))
    let n = buf.withUnsafeMutableBufferPointer { ptr -> Int32 in
        getfsstat(ptr.baseAddress, size, MNT_NOWAIT)
    }
    guard n > 0 else { return nil }

    return (0..<Int(n)).map { i in
        var fs = buf[i]
        return withUnsafePointer(to: &fs.f_mntonname) { p -> String in
            p.withMemoryRebound(to: CChar.self, capacity: Int(MAXPATHLEN)) {
                String(cString: $0)
            }
        }
    }
}
