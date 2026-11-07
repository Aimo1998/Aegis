//
//  LevelC.swift
//  Aegis
//
//  🔵 C 级检测：基础特征（针对传统有根越狱）
//

import Foundation
import UIKit
import Darwin
import LocalAuthentication

enum LevelC {

    static let all: [Detector] = [
        fileSystemCheck,
        urlSchemeCheck,
        sandboxEscapeCheck,
        environmentCheck,
        simulatorHardwareCheck
    ]

    // MARK: C1 · 文件系统黑名单

    private static let blacklistPaths: [String] = [
        "/Applications/Cydia.app",
        "/Applications/Sileo.app",
        "/Applications/Zebra.app",
        "/Applications/Installer.app",
        "/Applications/blackra1n.app",
        "/Applications/FakeCarrier.app",
        "/Applications/Icy.app",
        "/Applications/IntelliScreen.app",
        "/Applications/MxTube.app",
        "/Applications/RockApp.app",
        "/Applications/SBSettings.app",
        "/Applications/WinterBoard.app",
        "/Library/MobileSubstrate/MobileSubstrate.dylib",
        "/Library/MobileSubstrate/DynamicLibraries",
        "/Library/Frameworks/CydiaSubstrate.framework",
        "/bin/bash",
        "/bin/sh",
        "/usr/sbin/sshd",
        "/usr/bin/ssh",
        "/usr/libexec/ssh-keysign",
        "/usr/libexec/sftp-server",
        "/etc/apt",
        "/etc/ssh/sshd_config",
        "/private/etc/apt",
        "/private/var/lib/apt",
        "/private/var/lib/cydia",
        "/private/var/stash",
        "/private/var/tmp/cydia.log",
        "/var/cache/apt",
        "/var/lib/apt",
        "/var/lib/cydia",
        "/var/log/syslog",
        "/var/tmp/cydia.log",
        "/jb",
        "/jb/amfid_payload.dylib",
        "/jb/jailbreakd",
        "/jb/libjailbreak.dylib",
        "/usr/lib/libjailbreak.dylib",
        "/var/jb",
        "/var/jb/usr/bin/sh",
        "/var/jb/usr/lib/libellekit.dylib",
        "/var/jb/Library/MobileSubstrate",
        "/.bootstrapped_electra",
        "/.cydia_no_stash",
        "/.installed_unc0ver",
        "/.installed_taurine",
        "/.installed_odyssey",
        "/.procursus_strapped"
    ]

    static let fileSystemCheck = Detector(
        id: "C1",
        level: .c,
        name: "文件系统黑名单",
        detail: "检查 \(blacklistPaths.count) 个越狱特征路径是否存在（Cydia/Sileo、ssh、apt、Substrate、/var/jb 等）。",
        run: {
            var hits: [String] = []
            for path in blacklistPaths {
                var st = Darwin.stat()
                if lstat(path, &st) == 0 {
                    hits.append(path)
                }
                if FileManager.default.fileExists(atPath: path) && !hits.contains(path) {
                    hits.append(path)
                }
                if hits.count >= 8 { break }
            }
            guard !hits.isEmpty else { return nil }
            return "命中 \(hits.count) 个路径：" + hits.prefix(6).joined(separator: "、")
        }
    )

    // MARK: C2 · URL Scheme 探测

    private static let jailbreakSchemes: [String] = [
        "cydia://",
        "sileo://",
        "zbra://",
        "filza://",
        "activator://",
        "undecimus://",
        "sbsettings://",
        "trollstore://",
        "procursus://"
    ]

    static let urlSchemeCheck = Detector(
        id: "C2",
        level: .c,
        name: "URL Scheme 探测",
        detail: "用 canOpenURL 检查是否注册了越狱工具专属协议（cydia/sileo/filza 等）。需在 Info.plist 的 LSApplicationQueriesSchemes 中声明。",
        run: {
            let sem = DispatchSemaphore(value: 0)
            var opened: [String] = []

            DispatchQueue.main.async {
                for scheme in jailbreakSchemes {
                    if let url = URL(string: scheme), UIApplication.shared.canOpenURL(url) {
                        opened.append(scheme)
                    }
                }
                sem.signal()
            }
            _ = sem.wait(timeout: .now() + 3)

            guard !opened.isEmpty else { return nil }
            return "已注册协议：" + opened.joined(separator: "、")
        }
    )

    // MARK: C3 · 沙盒逃逸 + 子进程

    static let sandboxEscapeCheck = Detector(
        id: "C3",
        level: .c,
        name: "沙盒逃逸与进程创建",
        detail: "尝试向沙盒外写入探针文件，并调用 SYS_fork 创建子进程。iOS 沙盒内这两项都应当失败。",
        run: {
            var reasons: [String] = []

            let token = UUID().uuidString
            // 注意：不能探测 /tmp —— iOS 上 /tmp 是指向 App 自己沙盒 tmp 的符号链接，
            // 写入必然成功，会造成假阳性。
            let targets = [
                "/private/jailbreak_test_\(token).txt",
                "/private/var/tmp/jailbreak_test_\(token).txt",
                "/var/jb/.aegis_probe_\(token)",
                "/usr/lib/.aegis_probe_\(token)"
            ]
            for path in targets {
                do {
                    try token.write(toFile: path, atomically: true, encoding: .utf8)
                    reasons.append("沙盒外写入成功：\(path)")
                    try? FileManager.default.removeItem(atPath: path)
                    break
                } catch {
                    // 写入失败属正常
                }
            }

            let pid = aegis_fork_raw()
            if pid == 0 {
                _exit(0)
            }
            if pid > 0 {
                var status: Int32 = 0
                kill(pid, SIGKILL)
                waitpid(pid, &status, 0)
                reasons.append("SYS_fork 成功创建子进程 PID=\(pid)")
            }

            guard !reasons.isEmpty else { return nil }
            return reasons.joined(separator: "；")
        }
    )

    // MARK: C4 · 环境变量审查

    private static let envKeys = [
        "DYLD_INSERT_LIBRARIES",
        "DYLD_FRAMEWORK_PATH",
        "DYLD_LIBRARY_PATH",
        "DYLD_FORCE_FLAT_NAMESPACE",
        "DYLD_IMAGE_SUFFIX",
        "_MSSafeMode",
        "_SafeMode",
        "JB_ROOT"
    ]

    private static let nonSystemMarkers = [
        "/var/jb", "/.jbroot", "/private/", "/var/mobile", "/tmp/",
        "cydia", "substrate", "ellekit", "libhooker", "substitute", "tweak"
    ]

    static let environmentCheck = Detector(
        id: "C4",
        level: .c,
        name: "环境变量审查",
        detail: "检查 DYLD_INSERT_LIBRARIES / DYLD_FRAMEWORK_PATH 等注入相关变量，判断其值是否指向系统目录以外的路径。正常 App 这些变量为空或不含非系统路径。",
        run: {
            var hits: [String] = []

            for key in envKeys {
                guard let raw = getenv(key) else { continue }
                let value = String(cString: raw)
                if value.isEmpty { continue }

                let lower = value.lowercased()
                let hasMarker = nonSystemMarkers.contains { lower.contains($0) }
                let onlySystem = value.split(separator: ":").allSatisfy { part -> Bool in
                    let p = String(part)
                    return p.hasPrefix("/System/") || p.hasPrefix("/usr/lib/")
                }

                if hasMarker || !onlySystem {
                    hits.append("\(key)=\(value)")
                }
            }

            guard !hits.isEmpty else { return nil }
            return hits.prefix(2).joined(separator: "；")
        }
    )

    // MARK: C5 · 模拟器与硬件指纹

    /// 读取字符串类型的 sysctl
    private static func sysctlString(_ name: String) -> String? {
        var size = 0
        guard sysctlbyname(name, nil, &size, nil, 0) == 0, size > 0 else { return nil }
        var buf = [CChar](repeating: 0, count: size)
        guard sysctlbyname(name, &buf, &size, nil, 0) == 0 else { return nil }
        return String(cString: buf)
    }

    static let simulatorHardwareCheck = Detector(
        id: "C5",
        level: .c,
        name: "模拟器与硬件指纹",
        detail: "检查是否运行在模拟器（TARGET_OS_SIMULATOR / hw.machine / hw.model），并通过 LocalAuthentication 的 biometryType 判断是否存在真实生物识别硬件（Touch ID / Face ID）。模拟器无法通过此项。",
        run: {
            var reasons: [String] = []

            #if targetEnvironment(simulator)
            reasons.append("编译目标为模拟器（TARGET_OS_SIMULATOR）")
            #endif

            // 1. hw.machine：模拟器为 x86_64 / arm64，真机为 iPhoneXX,X 之类
            if let machine = sysctlString("hw.machine") {
                if machine == "x86_64" || machine == "arm64" || machine.hasPrefix("i386") {
                    reasons.append("hw.machine = \(machine)（非真机）")
                }
            }

            // 2. hw.model：真机应以 iPhone / iPad / iPod 开头
            if let model = sysctlString("hw.model") {
                let isRealDevice = model.hasPrefix("iPhone")
                    || model.hasPrefix("iPad")
                    || model.hasPrefix("iPod")
                    || model.hasPrefix("Mac")
                if !isRealDevice {
                    reasons.append("hw.model = \(model)（非 iOS 真机型号）")
                }
            }

            // 3. 生物识别硬件：biometryType 反映硬件是否存在，
            //    与「用户是否录入了指纹/面容」无关
            let ctx = LAContext()
            _ = ctx.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: nil)
            if ctx.biometryType == .none {
                reasons.append("无生物识别硬件（biometryType = none）")
            }

            guard !reasons.isEmpty else { return nil }
            return reasons.joined(separator: "；")
        }
    )
}
