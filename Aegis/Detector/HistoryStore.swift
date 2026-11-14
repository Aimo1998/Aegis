//
//  HistoryStore.swift
//  Aegis
//
//  扫描历史记录与变化对比
//

import Foundation

struct HistoryEntry: Codable, Identifiable {
    var id: UUID = UUID()
    let date: Date
    let levelRaw: String
    let passed: Int
    let total: Int
    let failedIDs: [String]
    let duration: Double

    var level: DetectionLevel {
        DetectionLevel(rawValue: levelRaw) ?? .a
    }

    var isJailbroken: Bool { !failedIDs.isEmpty }
}

final class HistoryStore: ObservableObject {

    static let shared = HistoryStore()

    @Published private(set) var entries: [HistoryEntry] = []

    private let storageKey = "aegis.scan.history"
    private let maxEntries = 60

    private init() {
        load()
    }

    // MARK: 读写

    func add(_ report: ScanReport) {
        let entry = HistoryEntry(
            date: report.startedAt,
            levelRaw: report.level.rawValue,
            passed: report.passedCount,
            total: report.results.count,
            failedIDs: report.results.filter(\.triggered).map(\.id),
            duration: report.duration
        )

        entries.insert(entry, at: 0)
        if entries.count > maxEntries {
            entries = Array(entries.prefix(maxEntries))
        }
        save()
    }

    func clear() {
        entries = []
        save()
    }

    private func load() {
        guard let data = UserDefaults.standard.data(forKey: storageKey) else { return }
        if let list = try? JSONDecoder().decode([HistoryEntry].self, from: data) {
            entries = list
        }
    }

    private func save() {
        if let data = try? JSONEncoder().encode(entries) {
            UserDefaults.standard.set(data, forKey: storageKey)
        }
    }

    // MARK: 变化对比

    struct Diff {
        let newlyFailed: [String]
        let recovered: [String]
        let previous: HistoryEntry?
    }

    /// 拿某条记录与它之前一条（同等级）做对比
    func diff(for entry: HistoryEntry) -> Diff {
        guard let idx = entries.firstIndex(where: { $0.id == entry.id }) else {
            return Diff(newlyFailed: [], recovered: [], previous: nil)
        }

        // 找同等级的上一条
        var prev: HistoryEntry?
        for i in (idx + 1)..<entries.count {
            if entries[i].level == entry.level {
                prev = entries[i]
                break
            }
        }

        guard let previous = prev else {
            return Diff(newlyFailed: [], recovered: [], previous: nil)
        }

        let nowSet = Set(entry.failedIDs)
        let prevSet = Set(previous.failedIDs)

        return Diff(
            newlyFailed: Array(nowSet.subtracting(prevSet)).sorted(),
            recovered: Array(prevSet.subtracting(nowSet)).sorted(),
            previous: previous
        )
    }
}

// MARK: - 检测项 ID → 名称映射（历史页显示用）

enum DetectorCatalog {

    static func name(for id: String) -> String {
        allNames[id] ?? id
    }

    static let allNames: [String: String] = [
        "C1": "文件系统黑名单",
        "C2": "URL Scheme 探测",
        "C3": "沙盒逃逸与进程创建",
        "C4": "环境变量审查",
        "C5": "模拟器与硬件指纹",
        "B1": "无根路径探测",
        "B2": "注入框架扫描",
        "B3": "UI 篡改检测",
        "B4": "调试与反注入",
        "B5": "RWX 内存段检测",
        "B6": "进程链检测",
        "A1": "API 交叉验证",
        "A2": "代码签名与 TrustCache",
        "A3": "内核状态探测",
        "A4": "计时攻击检测",
        "A5": "防篡改与指针完整性",
        "A6": "App Attest 完整性"
    ]
}

// MARK: - 检测项元数据：权重与绕过思路

struct DetectorMeta {
    let weight: Int
    let bypass: String
}

extension DetectorCatalog {

    static let meta: [String: DetectorMeta] = [
        "C1": DetectorMeta(weight: 8,
            bypass: "RootHide 通过进程级路径重定向让 App 看不到真实文件树"),
        "C2": DetectorMeta(weight: 6,
            bypass: "卸载越狱工具 App，对应 scheme 随之消失"),
        "C3": DetectorMeta(weight: 15,
            bypass: "沙盒由内核保证，绕过需修改 sandbox profile，成本极高"),
        "C4": DetectorMeta(weight: 10,
            bypass: "启动时清空 DYLD_* 环境变量，或用 launchd 干净拉起"),
        "C5": DetectorMeta(weight: 5,
            bypass: "模拟器无法伪装 Secure Enclave，此项对真机天然通过"),

        "B1": DetectorMeta(weight: 12,
            bypass: "RootHide 使用动态随机挂载点，并 Hook stat 系列使其不可见"),
        "B2": DetectorMeta(weight: 15,
            bypass: "无痕注入（dylib 不落盘）+ 库名混淆，但会牺牲部分功能"),
        "B3": DetectorMeta(weight: 18,
            bypass: "需同时伪造 IMP 归属，让 dladdr 返回合法系统库，成本极高"),
        "B4": DetectorMeta(weight: 12,
            bypass: "隐藏 Frida 端口与线程名；ptrace 层需内核态配合"),
        "B5": DetectorMeta(weight: 15,
            bypass: "注入后清理 RWX 页权限，改用 RX + 写时复制"),
        "B6": DetectorMeta(weight: 10,
            bypass: "守护进程改名并隔离到独立命名空间"),

        "B7": DetectorMeta(weight: 12,
            bypass: "符号链接可由 RootHide 换成 firmlink 或直接不落盘，lstat 只会看到普通目录"),
        "B8": DetectorMeta(weight: 15,
            bypass: "把 EACCES/EPERM 统一改写为 ENOENT，需要 Hook 沙盒判定，成本高"),
        "B9": DetectorMeta(weight: 1,
            bypass: "声明缺失是本机配置问题，不是越狱证据；权重降到 1，仅作提示"),

        "A7": DetectorMeta(weight: 20,
            bypass: "挂载表由内核维护，用户态只能隐藏条目，无法伪造 flags"),
        "A8": DetectorMeta(weight: 22,
            bypass: "需同时 Hook dyld 与 dladdr 且返回同一路径，任一处不一致即暴露"),
        "A9": DetectorMeta(weight: 18,
            bypass: "csops 是私有 syscall，Hook 后极难保持多次调用完全一致"),

        "B10": DetectorMeta(weight: 10,
            bypass: "只能把 App 装回沙盒容器，越狱部署方式无法伪装"),
        "B11": DetectorMeta(weight: 8,
            bypass: "可卸载多余 tweak 把数量压回区间，但会牺牲功能"),
        "B12": DetectorMeta(weight: 10,
            bypass: "关掉 ssh / Frida / 面板服务即可，纯行为特征"),

        "A10": DetectorMeta(weight: 24,
            bypass: "需同时篡改 Mach-O load commands 与 dyld 视图，任一处不一致即暴露"),
        "A11": DetectorMeta(weight: 22,
            bypass: "entitlements 由内核签名绑定，重签名必然改变 application-identifier"),

        "C6": DetectorMeta(weight: 6,
            bypass: "区域、语言、时区三者要同时伪造，改一处就会互相矛盾"),

        "B13": DetectorMeta(weight: 14,
            bypass: "要么连挂载表一起隐藏（需要 mount namespace），要么别用过滤工具"),
        "B14": DetectorMeta(weight: 12,
            bypass: "屏蔽插件本身要先做到无痕加载，难度比隐藏越狱还高"),

        "A12": DetectorMeta(weight: 20,
            bypass: "目录存在但零加载是硬矛盾，除非连挂载表一并处理"),
        "A13": DetectorMeta(weight: 24,
            bypass: "随机挂载点要配合降低熵值（如固定前缀），但那样就失去了随机性"),
        "A14": DetectorMeta(weight: 22,
            bypass: "转换包必须重写 LC_LOAD_DYLIB 指向，否则旧路径一眼可见"),

        "A1": DetectorMeta(weight: 25,
            bypass: "必须同时 Hook libc 与裸 syscall 且结果完全一致，极易露馅"),
        "A2": DetectorMeta(weight: 20,
            bypass: "csflags 由内核维护，用户态无法伪造；TrustCache 需内核补丁"),
        "A3": DetectorMeta(weight: 15,
            bypass: "bootargs 只读；挂载表可用 mount namespace 隔离"),
        "A4": DetectorMeta(weight: 22,
            bypass: "拦截层需把耗时控制在微秒级且与真实 VFS 一致，几乎不可能"),
        "A5": DetectorMeta(weight: 25,
            bypass: "需完整伪造指针链与映像归属，攻击成本极高"),
        "A6": DetectorMeta(weight: 10,
            bypass: "需付费开发者证书 + 服务端 App Attest 校验")
    ]

    static func weight(for id: String) -> Int {
        meta[id]?.weight ?? 5
    }

    static func bypass(for id: String) -> String {
        meta[id]?.bypass ?? ""
    }

    /// 全部检测项权重之和
    static var totalWeight: Int {
        meta.values.reduce(0) { $0 + $1.weight }
    }
}
