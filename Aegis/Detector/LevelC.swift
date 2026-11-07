//
//  LevelC.swift
//  Aegis
//
//  🛑 C 级检测：基础特征匹配（针对传统有根越狱）
//

import Foundation
import UIKit

enum LevelC {

    static let all: [Detector] = [
        fileSystemCheck,
        urlSchemeCheck,
        sandboxEscapeCheck,
        forkCheck
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
                var st = stat()
                if lstat(path, &st) == 0 {
                    hits.append(path)
                }
                if FileManager.default.fileExists(atPath: path) && !hits.contains(path) {
                    hits.append(path)
                }
                if hits.count >= 8 { break }   // 命中足够多就提前结束
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
        "sbSettings://",
        "trollstore://",
        "procursus://"
    ]

    static let urlSchemeCheck = Detector(
        id: "C2",
        level: .c,
        name: "URL Scheme 探测",
        detail: "用 canOpenURL 检查是否注册了越狱工具专属协议（cydia/sileo/filza 等）。需在 Info.plist 的 LSApplicationQueriesSchemes 中声明。",
        run: {
            // canOpenURL 必须在主线程调用
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

    // MARK: C3 · 沙盒逃逸

    static let sandboxEscapeCheck = Detector(
        id: "C3",
        level: .c,
        name: "沙盒逃逸写入",
        detail: "尝试向沙盒外的 /private 目录写入文件。沙盒正常时必然失败，成功即说明沙盒被突破。",
        run: {
            let token = UUID().uuidString
            let targets = [
                "/private/jailbreak_test_\(token).txt",
                "/private/var/tmp/jailbreak_test_\(token).txt",
                "/var/jb/.aegis_probe_\(token)",
                "/tmp/aegis_probe_\(token)"
            ]

            var written: [String] = []
            for path in targets {
                do {
                    try token.write(toFile: path, atomically: true, encoding: .utf8)
                    written.append(path)
                    try? FileManager.default.removeItem(atPath: path)  // 清理
                } catch {
                    // 写入失败是正常表现
                }
            }

            guard !written.isEmpty else { return nil }
            return "成功写入沙盒外：\(written[0])"
        }
    )

    // MARK: C4 · 进程创建

    static let forkCheck = Detector(
        id: "C4",
        level: .c,
        name: "子进程创建",
        detail: "调用 fork()。iOS 沙盒内应用禁止创建子进程，返回成功即为异常。",
        run: {
            let pid = fork()
            if pid == 0 {
                // 子进程立刻退出，不留垃圾进程
                _exit(0)
            }
            if pid > 0 {
                var status: Int32 = 0
                kill(pid, SIGKILL)
                waitpid(pid, &status, 0)
                return "fork() 成功返回子进程 PID=\(pid)"
            }
            // pid < 0：errno == EPERM 属正常
            return nil
        }
    )
}
