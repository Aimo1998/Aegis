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
