//
//  LevelB.swift
//  Aegis
//
//  🟡 B 级检测：现代无根与注入（针对无根越狱 Rootless）
//

import Foundation
import UIKit
import Darwin
import ObjectiveC

private let AEGIS_RTLD_DEFAULT = UnsafeMutableRawPointer(bitPattern: -2)!

enum LevelB {

    static let all: [Detector] = [
        rootlessPathCheck,
        dyldInjectionScan,
        uiTamperCheck,
        debuggerCheck,
        rwxMemoryCheck,
        processChainCheck
    ]

    // MARK: B1 · 无根越狱路径探测

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
        id: "B1",
        level: .b,
        name: "无根路径探测",
        detail: "用原始 SYS_lstat 探测 /var/jb、/.jbroot 等无根越狱挂载点，并检查 getfsstat 挂载表中是否有异常 jbroot 挂载。",
        run: {
            var hits: [String] = []

            for path in rootlessCandidates {
                var st = Darwin.stat()
                let r = withUnsafeMutablePointer(to: &st) { p -> Int32 in
                    aegis_raw_lstat(path, UnsafeMutableRawPointer(p))
                }
                if r == 0 {
                    hits.append(path)
                }
            }

            if let mounts = aegisFetchMounts() {
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

    // MARK: B2 · 注入框架扫描

    private static let injectionSignatures: [String] = [
        "ellekit",
        "mobilesubstrate",
        "cydia substrate",
        "substrate",
        "substitute",
        "libhooker",
        "systemhook",
        "tweakloader",
        "orion",
        "libblackjack",
        "jailbreak",
        "/var/jb/",
        "/.jbroot/",
        "frida",
        "cycript",
        "colorpicker"
    ]

    static let dyldInjectionScan = Detector(
        id: "B2",
        level: .b,
        name: "注入框架扫描",
        detail: "遍历 _dyld_image_count 枚举所有已加载的 dylib，匹配 ElleKit / MobileSubstrate / Substitute / libhooker / systemhook / TweakLoader / Frida 等 16 个特征。",
        run: {
            let count = Int(aegis_dyld_image_count())
            var hits: [String] = []

            for i in 0..<count {
                guard let cname = aegis_dyld_image_name(Int32(i)) else { continue }
                let name = String(cString: cname).lowercased()

                if name.contains("/aegis.app/") { continue }
                if name.hasPrefix("/usr/lib/system/") || name.hasPrefix("/system/") { continue }

                for sig in injectionSignatures where name.contains(sig) {
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

    // MARK: B3 · UI 篡改检测（IMP 归属）

    /// 关键类的关键 selector，被 Hook 时 IMP 会落到非系统库
    private static let uiProbes: [(String, String)] = [
        ("UIApplication", "sendAction:to:from:forEvent:"),
        ("UIApplication", "applicationState"),
        ("UIView", "layoutSubviews"),
        ("UIView", "didMoveToWindow"),
        ("UISwitch", "setOn:animated:"),
        ("UIWindow", "makeKeyAndVisible"),
        ("UIViewController", "viewDidLoad"),
        ("UIResponder", "touchesBegan:withEvent:")
    ]

    static let uiTamperCheck = Detector(
        id: "B3",
        level: .b,
        name: "UI 篡改检测",
        detail: "取 UIApplication / UIView / UISwitch 等核心类关键方法的 IMP，用 dladdr 反查其所在映像。IMP 落在 UIKit 之外的可写库（如 /var/jb 下的 dylib）说明方法被 Hook 重定向。",
        run: {
            var hits: [String] = []

            for (className, selectorName) in uiProbes {
                guard let cls = NSClassFromString(className) else { continue }
                let sel = NSSelectorFromString(selectorName)
                guard let method = class_getInstanceMethod(cls, sel) else { continue }

                let imp = method_getImplementation(method)
                var info = Dl_info()
                let ptr = unsafeBitCast(imp, to: UnsafeRawPointer.self)
                guard dladdr(ptr, &info) != 0, let fname = info.dli_fname else { continue }

                let path = String(cString: fname)
                let lower = path.lowercased()

                // IMP 落在越狱路径 = 被注入库劫持
                let suspect = lower.contains("/var/jb")
                    || lower.contains("/.jbroot")
                    || lower.contains("/private/var")
                    || lower.contains("substrate")
                    || lower.contains("ellekit")
                    || lower.contains("tweak")

                if suspect {
                    hits.append("\(className) -\(selectorName) → \(path)")
                }
            }

            guard !hits.isEmpty else { return nil }
            return hits.prefix(2).joined(separator: "；")
        }
    )

    // MARK: B4 · 调试与反注入

    private static let fridaPorts: [Int32] = [27042, 27043, 27044]

    static let debuggerCheck = Detector(
        id: "B4",
        level: .b,
        name: "调试与反注入",
        detail: "检查 sysctl P_TRACED 标志、ptrace(PT_DENY_ATTACH) 返回值，并探测 Frida 默认端口 27042/27043/27044 及 gum 符号。",
        run: {
            var reasons: [String] = []

            // 1) P_TRACED
            var info = kinfo_proc()
            var size = MemoryLayout<kinfo_proc>.stride
            var mib: [Int32] = [CTL_KERN, KERN_PROC, KERN_PROC_PID, getpid()]
            let kr = mib.withUnsafeMutableBufferPointer { mibPtr -> Int32 in
                sysctl(mibPtr.baseAddress, 4, &info, &size, nil, 0)
            }
            if kr == 0 {
                if (info.kp_proc.p_flag & P_TRACED) != 0 {
                    reasons.append("P_TRACED 已置位（进程被调试）")
                }
            } else {
                reasons.append("sysctl 异常 errno=\(errno)")
            }

            // 2) ptrace 自检
            let ptRet = aegis_ptrace_deny_attach()
            if ptRet == 0 && getppid() != 1 {
                reasons.append("PT_DENY_ATTACH 返回值异常")
            }

            // 3) Frida 端口
            for port in fridaPorts where aegis_port_open(port, 200) {
                reasons.append("端口 \(port) 开放")
            }

            // 4) Frida 符号
            for s in ["gum_init", "frida_agent_main", "gum_script_backend"] {
                if dlsym(AEGIS_RTLD_DEFAULT, s) != nil {
                    reasons.append("符号 \(s) 可解析")
                }
            }

            guard !reasons.isEmpty else { return nil }
            return reasons.joined(separator: "、")
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

    // MARK: B6 · 进程链检测

    private static let suspiciousProcesses = [
        "jailbreakd",
        "linjector",
        "frida-server",
        "frida-helper",
        "trollstorehelper",
        "trollstorelite",
        "afcd",              // 被替换的 afc2 服务
        "dropbear",
        "sshd",
        "substrate",
        "ellekit",
        "launchd_sim",
        "cydia",
        "sileo",
        "zebra",
        "unc0ver",
        "taurine",
        "palera1n",
        "dopamine"
    ]

    static let processChainCheck = Detector(
        id: "B6",
        level: .b,
        name: "进程链检测",
        detail: "用 sysctl KERN_PROC_ALL 拉取系统全部进程名，匹配越狱守护进程（jailbreakd、linjector、frida-server、dropbear 等 19 个特征）。",
        run: {
            guard let procs = aegisFetchProcesses() else { return nil }

            var hits: [String] = []
            let lowerSet = procs.map { $0.lowercased() }
            for sig in suspiciousProcesses {
                if let idx = lowerSet.firstIndex(where: { $0.contains(sig) }) {
                    hits.append(procs[idx])
                }
            }

            guard !hits.isEmpty else { return nil }
            return "发现 \(hits.count) 个可疑进程：" + hits.prefix(4).joined(separator: "、")
        }
    )
}

// MARK: - 辅助

/// 通过 C shim 取挂载点
func aegisFetchMounts() -> [String]? {
    var buf = [CChar](repeating: 0, count: 32768)
    let n = buf.withUnsafeMutableBufferPointer { p -> Int32 in
        aegis_mount_points(p.baseAddress, size_t(32768))
    }
    guard n > 0 else { return nil }
    let raw = String(cString: buf)
    return raw.split(separator: "\n").map(String.init)
}

/// 通过 C shim 取进程名列表
func aegisFetchProcesses() -> [String]? {
    var buf = [CChar](repeating: 0, count: 65536)
    let n = buf.withUnsafeMutableBufferPointer { p -> Int32 in
        aegis_list_process_names(p.baseAddress, size_t(65536))
    }
    guard n > 0 else { return nil }
    let raw = String(cString: buf)
    let list = raw.split(separator: "\n").map(String.init)
    return list.isEmpty ? nil : list
}
