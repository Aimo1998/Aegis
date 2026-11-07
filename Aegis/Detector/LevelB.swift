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
        processChainCheck,
        symlinkResidueCheck,
        permissionProbeCheck,
        schemeDeclareCheck,
        selfPathCheck,
        dylibCountCheck,
        portScanCheck
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
            let rawCount = aegis_dyld_image_count()
            guard rawCount > 0 else { return nil }
            let count = Int(rawCount)
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

                // dladdr 拿不到路径时（dyld 共享缓存常见），退回地址归属判断，
                // 避免把「只是没名字」误判成「被 Hook」
                guard dladdr(ptr, &info) != 0, let fname = info.dli_fname else {
                    if !aegis_address_in_image(UInt(bitPattern: ptr)) {
                        hits.append("\(className) -\(selectorName) → IMP 不在任何已加载映像内")
                    }
                    continue
                }

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

    // MARK: B7 · 符号链接本体

    static let symlinkResidueCheck = Detector(
        id: "B7",
        level: .b,
        name: "符号链接残留",
        detail: "用 lstat（不跟随链接）检查 /var/jb、/.jbroot 等路径本身是否为符号链接，并读取链接目标。常规 stat 会跟随链接，检测不到这种残留。",
        run: {
            var hits: [String] = []

            let targets = [
                "/var/jb", "/.jbroot", "/private/var/jb",
                "/usr/lib/substrate", "/usr/lib/libsubstrate.dylib",
                "/Library/MobileSubstrate", "/Library/TweakInject",
                "/var/lib/dpkg", "/etc/apt"
            ]

            for path in targets {
                var st = Darwin.stat()
                guard lstat(path, &st) == 0 else { continue }
                let mode = st.st_mode & S_IFMT
                guard mode == S_IFLNK else { continue }

                var buf = [CChar](repeating: 0, count: 1024)
                let n = readlink(path, &buf, buf.count - 1)
                let dest: String
                if n > 0 {
                    dest = String(cString: buf)
                } else {
                    dest = "?"
                }
                hits.append("\(path) → \(dest)")
            }

            guard !hits.isEmpty else { return nil }
            return hits.prefix(3).joined(separator: "；")
        }
    )

    // MARK: B8 · 权限异常探测

    static let permissionProbeCheck = Detector(
        id: "B8",
        level: .b,
        name: "权限异常探测",
        detail: "对越狱特征路径逐个调用 lstat 并记录 errno。区分「路径不存在（ENOENT）」与「存在但访问被拒（EACCES / EPERM）」——后者说明路径真实存在，只是被沙盒或 Hook 拦住了访问。",
        run: {
            var denied: [String] = []
            var oddly: [String] = []

            let probes = [
                "/var/jb", "/.jbroot", "/private/preboot",
                "/Library/MobileSubstrate", "/Library/TweakInject",
                "/usr/lib/libsubstrate.dylib", "/usr/lib/libhooker.dylib",
                "/usr/lib/libellekit.dylib", "/bin/bash", "/usr/bin/ssh"
            ]

            for path in probes {
                var st = Darwin.stat()
                errno = 0
                let r = lstat(path, &st)
                if r == 0 { continue }                 // 已由 B1 负责
                let e = errno
                if e == EACCES || e == EPERM {
                    denied.append("\(path)(errno=\(e))")
                } else if e != ENOENT && e != 0 {
                    oddly.append("\(path)(errno=\(e))")
                }
            }

            var parts: [String] = []
            if !denied.isEmpty {
                parts.append("访问被拒：" + denied.prefix(3).joined(separator: "、"))
            }
            if !oddly.isEmpty {
                parts.append("异常 errno：" + oddly.prefix(3).joined(separator: "、"))
            }
            guard !parts.isEmpty else { return nil }
            return parts.joined(separator: "；")
        }
    )

    // MARK: B9 · Scheme 声明自检

    static let schemeDeclareCheck = Detector(
        id: "B9",
        level: .b,
        name: "Scheme 声明自检",
        detail: "canOpenURL 只会对 Info.plist 中 LSApplicationQueriesSchemes 声明过的 Scheme 返回真实结果，未声明的一律返回 false。本项检查哪些越狱 Scheme 没有声明，标注出 C2 的检测盲区。",
        run: {
            let needed = [
                "cydia", "sileo", "zbra", "zebra", "filza",
                "activator", "undecimus", "sbsettings",
                "trollstore", "procursus"
            ]

            let declared = (Bundle.main.object(forInfoDictionaryKey: "LSApplicationQueriesSchemes") as? [String]) ?? []
            let declaredLower = Set(declared.map { $0.lowercased() })

            let missing = needed.filter { !declaredLower.contains($0) }
            guard !missing.isEmpty else { return nil }
            return "未声明：\(missing.joined(separator: ", "))（这些 Scheme 无法探测，C2 存在盲区）"
        }
    )

    // MARK: B10 · 自身运行路径

    static let selfPathCheck = Detector(
        id: "B10",
        level: .b,
        name: "自身运行路径",
        detail: "检查 App 自身的可执行文件是否从越狱目录（/var/jb、/private/preboot、/.jbroot）加载。装在沙盒容器外即说明以越狱方式部署。",
        run: {
            let exe = Bundle.main.executablePath ?? ""
            guard !exe.isEmpty else { return nil }

            let badMarkers = ["/var/jb/", "/.jbroot/", "/private/preboot/",
                              "/Library/MobileSubstrate/"]
            for m in badMarkers where exe.contains(m) {
                return "App 从越狱路径运行：\(exe)"
            }

            // 正常应在 /var/containers/Bundle/Application/ 下
            if !exe.contains("/var/containers/Bundle/Application/")
                && !exe.contains("/private/var/containers/Bundle/Application/") {
                return "App 位于非常规容器路径：\(exe)"
            }
            return nil
        }
    )

    // MARK: B11 · 动态库数量基线

    static let dylibCountCheck = Detector(
        id: "B11",
        level: .b,
        name: "动态库数量基线",
        detail: "统计当前进程加载的 dylib 总数。正常 iOS App 在 150~320 之间，明显偏多说明被批量注入，明显偏少说明环境被裁剪。",
        run: {
            let raw = aegis_dyld_image_count()
            guard raw > 0 else { return nil }
            let n = Int(raw)

            if n > 420 {
                return "加载 \(n) 个 dylib（正常上限约 320）"
            }
            if n < 90 {
                return "仅加载 \(n) 个 dylib（异常偏少）"
            }
            return nil
        }
    )

    // MARK: B12 · 本地端口扫描

    static let portScanCheck = Detector(
        id: "B12",
        level: .b,
        name: "本地服务端口",
        detail: "扫描本机回环上的常见后门与调试端口：22(ssh)、1337、4444、8080、9090、31337、27042~27044(Frida)。任一开放即说明有调试服务在跑。",
        run: {
            let ports: [(Int32, String)] = [
                (22, "ssh"),
                (1337, "backdoor"),
                (4444, "backdoor"),
                (8080, "http-proxy"),
                (9090, "panel"),
                (31337, "backdoor"),
                (27042, "frida"),
                (27043, "frida"),
                (27044, "frida")
            ]

            var open: [String] = []
            for (port, label) in ports {
                if aegis_port_open(port, 180) {
                    open.append("\(port)/\(label)")
                }
            }

            guard !open.isEmpty else { return nil }
            return "开放端口：" + open.joined(separator: "、")
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
