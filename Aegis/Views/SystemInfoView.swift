//
//  SystemInfoView.swift
//  Aegis
//
//  系统信息诊断：把检测逻辑依赖的所有底层返回值原样列出来
//  用于核对检测项是否因 API 语义理解偏差而误判
//

import SwiftUI
import Darwin
import LocalAuthentication
import DeviceCheck

// MARK: - 数据模型

struct InfoItem: Identifiable {
    let id = UUID()
    let key: String
    let value: String
    let note: String?
}

struct InfoSection: Identifiable {
    let id = UUID()
    let title: String
    let icon: String
    let items: [InfoItem]
}

// MARK: - 采集器

enum SystemInfoCollector {

    private static func sysctlString(_ name: String) -> String? {
        var size = 0
        guard sysctlbyname(name, nil, &size, nil, 0) == 0, size > 0 else { return nil }
        var buf = [CChar](repeating: 0, count: size)
        guard sysctlbyname(name, &buf, &size, nil, 0) == 0 else { return nil }
        let s = String(cString: buf)
        return s.isEmpty ? nil : s
    }

    private static func sysctlInt(_ name: String) -> Int64? {
        var value: Int64 = 0
        var size = MemoryLayout<Int64>.size
        guard sysctlbyname(name, &value, &size, nil, 0) == 0 else { return nil }
        return value
    }

    static func collect() -> [InfoSection] {
        [deviceSection(), signatureSection(), runtimeSection(),
         probeSection(), processSection()]
    }

    // MARK: 1. 设备信息

    private static func deviceSection() -> InfoSection {
        var items: [InfoItem] = []

        func add(_ key: String, _ name: String, _ note: String? = nil) {
            let v = sysctlString(key) ?? "—"
            items.append(InfoItem(key: name, value: v, note: note))
        }

        add("hw.machine", "hw.machine", "机型标识，模拟器为 arm64/x86_64")
        add("hw.model", "hw.model", "iOS 返回平台代号（如 D22AP）")
        add("hw.product", "hw.product", nil)
        add("hw.target", "hw.target", nil)
        add("hw.ncpu", "hw.ncpu", nil)
        add("hw.memsize", "hw.memsize", nil)
        add("kern.osversion", "kern.osversion", "系统构建号")
        add("kern.osproductversion", "kern.osproductversion", "系统版本号")
        add("kern.hostname", "kern.hostname", nil)

        if let mem = sysctlInt("hw.memsize") {
            items.append(InfoItem(key: "内存",
                                  value: ByteCountFormatter.string(fromByteCount: mem, countStyle: .memory),
                                  note: nil))
        }

        return InfoSection(title: L10n.shared.t("设备信息", "Device"), icon: "iphone", items: items)
    }

    // MARK: 2. 代码签名

    private static func signatureSection() -> InfoSection {
        var items: [InfoItem] = []

        var flags: UInt32 = 0
        let ret = withUnsafeMutablePointer(to: &flags) { p -> Int32 in
            aegis_csops(UInt32(getpid()), 0, UnsafeMutableRawPointer(p), 4)
        }

        if ret == 0 {
            items.append(InfoItem(key: "csops 返回", value: "0", note: "成功"))
            items.append(InfoItem(key: "csflags",
                                  value: "0x" + String(flags, radix: 16).uppercased(),
                                  note: nil))

            let bits: [(String, UInt32, String)] = [
                ("CS_VALID",      0x00000001, "签名有效"),
                ("CS_HARD",       0x00000100, "页面不可动态改写"),
                ("CS_KILL",       0x00000200, "违规会被内核终止"),
                ("CS_PLATFORM",   0x00000400, "系统平台签名"),
                ("CS_RESTRICT",   0x00000800, "受限签名"),
                ("CS_DEBUGGED",   0x10000000, "允许调试（开发证书）"),
                ("CS_INSTALLER",  0x00080000, "安装器签名"),
                ("CS_REQUIRE_LV", 0x00002000, "要求库验证")
            ]

            for (name, bit, desc) in bits {
                let on = (flags & bit) != 0
                items.append(InfoItem(key: name,
                                      value: on ? "✅ 已置位" : "⬜️ 未置位",
                                      note: desc))
            }
        } else {
            items.append(InfoItem(key: "csops 返回", value: "\(ret)",
                                  note: "失败 errno=\(errno)"))
        }

        items.append(InfoItem(key: "ptrace(PT_DENY_ATTACH)",
                              value: "\(aegis_ptrace_deny_attach())",
                              note: "0 = 成功；被 Hook 时行为可能异常"))
        items.append(InfoItem(key: "getppid()", value: "\(getppid())",
                              note: "正常 App 应为 1（launchd）"))

        return InfoSection(title: L10n.shared.t("代码签名", "Code Signing"), icon: "checkmark.seal", items: items)
    }

    // MARK: 3. 运行时

    private static func runtimeSection() -> InfoSection {
        var items: [InfoItem] = []

        let total = Int(aegis_dyld_image_count())
        items.append(InfoItem(key: "已加载映像", value: "\(total)", note: "dyld_image_count"))

        let images = DylibScanner.scan()
        let injected = images.filter { $0.category == .jailbreakInjected }
        items.append(InfoItem(key: "越狱路径映像", value: "\(injected.count)",
                              note: injected.isEmpty ? nil : injected.prefix(3).map(\.name).joined(separator: ", ")))

        // 生物识别
        let ctx = LAContext()
        _ = ctx.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: nil)
        let bio: String
        switch ctx.biometryType {
        case .none:    bio = "none"
        case .touchID: bio = "touchID"
        case .faceID:  bio = "faceID"
        @unknown default: bio = "unknown"
        }
        items.append(InfoItem(key: "biometryType", value: bio,
                              note: "反映硬件存在性，与是否录入无关"))

        items.append(InfoItem(key: "App Attest 支持",
                              value: DCAppAttestService.shared.isSupported ? "✅ 支持" : "⬜️ 不支持",
                              note: "需要付费账号 entitlement"))

        items.append(InfoItem(key: "RWX 内存页", value: "\(aegis_count_rwx_regions())",
                              note: "非映像归属的 W+X 页"))

        // x86 环境变量
        let envKeys = ["DYLD_INSERT_LIBRARIES", "DYLD_LIBRARY_PATH",
                       "DYLD_FRAMEWORK_PATH", "DYLD_FORCE_FLAT_NAMESPACE"]
        let set = envKeys.compactMap { k -> String? in
            guard let v = getenv(k) else { return nil }
            let s = String(cString: v)
            return s.isEmpty ? nil : "\(k)=\(s)"
        }
        items.append(InfoItem(key: "DYLD_* 变量",
                              value: set.isEmpty ? "未设置" : "\(set.count) 个",
                              note: set.first))

        return InfoSection(title: L10n.shared.t("运行时", "Runtime"), icon: "cpu", items: items)
    }

    // MARK: 4. 文件系统探测（lstat vs 裸 syscall）

    private static func probeSection() -> InfoSection {
        var items: [InfoItem] = []

        let paths = ["/var/jb", "/.jbroot", "/bin/bash", "/Applications/Cydia.app",
                     "/System/Library", "/usr/lib/libSystem.B.dylib"]

        for path in paths {
            var stLibc = Darwin.stat()
            var stRaw = Darwin.stat()

            let rLibc = lstat(path, &stLibc)
            let rRaw = withUnsafeMutablePointer(to: &stRaw) { p -> Int32 in
                aegis_raw_lstat(path, UnsafeMutableRawPointer(p))
            }

            let same = (rLibc == rRaw)
            let value = "lstat=\(rLibc) raw=\(rRaw)"
            let note: String
            if rLibc == 0 && rRaw == 0 {
                let isDir = (stLibc.st_mode & S_IFMT) == S_IFDIR
                note = "存在（\(isDir ? "目录" : "文件")），两条路径一致=\(same ? "是" : "否 ⚠️")"
            } else if rLibc == 0 {
                note = "仅 libc 可见 ⚠️"
            } else if rRaw == 0 {
                note = "仅裸 syscall 可见 ⚠️"
            } else {
                note = "均不存在（errno \(errno)）"
            }

            items.append(InfoItem(key: path, value: value, note: note))
        }

        // 挂载表
        let mounts = aegisFetchMounts() ?? []
        let jbMounts = mounts.filter {
            let l = $0.lowercased()
            return l.contains("jbroot") || l.contains("/var/jb") || l.contains("procursus")
        }
        items.append(InfoItem(key: "挂载点总数", value: "\(mounts.count)", note: nil))
        items.append(InfoItem(key: "可疑挂载点", value: "\(jbMounts.count)",
                              note: jbMounts.first))

        // bootargs
        var buf = [CChar](repeating: 0, count: 2048)
        var outLen: size_t = 0
        let ok = buf.withUnsafeMutableBufferPointer { p -> Bool in
            aegis_read_bootargs(p.baseAddress, size_t(2048), &outLen)
        }
        let bootargs = ok ? String(cString: buf) : "读取失败"
        items.append(InfoItem(key: "kern.bootargs",
                              value: bootargs.isEmpty ? "（空）" : String(bootargs.prefix(120)),
                              note: ok ? nil : "sysctl 被拒绝"))

        return InfoSection(title: L10n.shared.t("文件系统探测", "Filesystem"), icon: "folder", items: items)
    }

    // MARK: 5. 进程与环境

    private static func processSection() -> InfoSection {
        var items: [InfoItem] = []

        let procs = aegisFetchProcesses() ?? []
        items.append(InfoItem(key: "进程表条目", value: "\(procs.count)",
                              note: procs.isEmpty ? "可能受沙盒限制" : nil))

        let suspicious = ["jailbreakd", "linjector", "frida-server", "dropbear",
                          "sshd", "dopamine", "trollstorehelper", "ellekit"]
        let hits = procs.filter { p in
            let l = p.lowercased()
            return suspicious.contains { l.contains($0) }
        }
        items.append(InfoItem(key: "可疑进程", value: "\(hits.count)",
                              note: hits.isEmpty ? nil : hits.prefix(5).joined(separator: ", ")))

        items.append(InfoItem(key: "pid", value: "\(getpid())", note: nil))
        items.append(InfoItem(key: "uid / gid", value: "\(getuid()) / \(getgid())", note: nil))

        if let bundle = Bundle.main.bundleIdentifier {
            items.append(InfoItem(key: "Bundle ID", value: bundle, note: nil))
        }
        if let exe = Bundle.main.executablePath {
            items.append(InfoItem(key: "可执行路径", value: exe, note: nil))
        }

        return InfoSection(title: L10n.shared.t("进程与环境", "Process & Env"), icon: "list.bullet", items: items)
    }
}

// MARK: - 视图

struct SystemInfoView: View {

    @ObservedObject private var l10n = L10n.shared

    @State private var sections: [InfoSection] = []
    @State private var loading = true
    @State private var expanded: Set<String> = []

    private let bg = Color(red: 0.05, green: 0.06, blue: 0.10)

    var body: some View {
        ScrollView {
            VStack(spacing: 14) {
                if loading {
                    ProgressView().padding(60)
                } else {
                    Text(l10n.t("以下为检测逻辑实际读取到的底层返回值，用于核对判定是否准确。",
                        "Raw values the detectors actually read, for verifying verdicts."))
                        .font(.system(size: 11.5, design: .rounded))
                        .foregroundStyle(.white.opacity(0.38))
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .padding(.horizontal, 4)

                    ForEach(sections) { section in
                        sectionView(section)
                    }

                    MadeByFooter()
                }
            }
            .padding(.horizontal, 16)
            .padding(.top, 12)
            .padding(.bottom, 40)
        }
        .background(bg.ignoresSafeArea())
        .onAppear(perform: load)
        .toolbar {
            ToolbarItem(placement: .topBarTrailing) {
                Button {
                    load()
                } label: {
                    Image(systemName: "arrow.clockwise")
                }
            }
        }
    }

    private func sectionView(_ section: InfoSection) -> some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack(spacing: 7) {
                Image(systemName: section.icon)
                    .font(.system(size: 12, weight: .medium))
                    .foregroundStyle(Color(red: 0.5, green: 0.75, blue: 1.0).opacity(0.8))
                Text(section.title)
                    .font(.system(size: 13, weight: .semibold, design: .rounded))
                    .foregroundStyle(.white.opacity(0.6))
                Spacer()
            }
            .padding(.horizontal, 4)

            ForEach(section.items) { item in
                row(item)
            }
        }
    }

    private func row(_ item: InfoItem) -> some View {
        VStack(alignment: .leading, spacing: 3) {
            HStack(alignment: .top, spacing: 8) {
                Text(item.key)
                    .font(.system(size: 11.5, design: .monospaced))
                    .foregroundStyle(.white.opacity(0.42))
                    .frame(width: 130, alignment: .leading)

                Text(item.value)
                    .font(.system(size: 11.5, weight: .medium, design: .monospaced))
                    .foregroundStyle(.white.opacity(0.88))
                    .frame(maxWidth: .infinity, alignment: .leading)
            }

            if let note = item.note, !note.isEmpty {
                Text(note)
                    .font(.system(size: 10.5, design: .rounded))
                    .foregroundStyle(
                        note.contains("⚠️")
                        ? Color(red: 1.0, green: 0.65, blue: 0.45)
                        : Color.white.opacity(0.28)
                    )
                    .padding(.leading, 138)
                    .fixedSize(horizontal: false, vertical: true)
            }
        }
        .padding(.horizontal, 12)
        .padding(.vertical, 8)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(
            RoundedRectangle(cornerRadius: 10, style: .continuous)
                .fill(Color.white.opacity(0.035))
        )
    }

    private func load() {
        loading = true
        DispatchQueue.global(qos: .userInitiated).async {
            let data = SystemInfoCollector.collect()
            DispatchQueue.main.async {
                sections = data
                loading = false
            }
        }
    }
}
