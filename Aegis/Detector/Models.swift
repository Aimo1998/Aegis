//
//  Models.swift
//  Aegis
//
//  检测项模型与结果聚合
//

import SwiftUI

/// 检测等级
enum DetectionLevel: String, CaseIterable, Identifiable {
    case c = "C 级"
    case b = "B 级"
    case a = "A 级"

    var id: String { rawValue }

    var title: String {
        switch self {
        case .c: return "C 级 · 基础特征"
        case .b: return "B 级 · 动态环境"
        case .a: return "A 级 · 深度对抗"
        }
    }

    var subtitle: String {
        switch self {
        case .c: return "针对传统有根越狱"
        case .b: return "针对无根越狱 / 注入"
        case .a: return "针对 RootHide / 高级隐藏"
        }
    }

    var subtitleLocalized: String {
        switch self {
        case .c: return L10n.shared.t("针对传统有根越狱", "Classic rootful jailbreaks")
        case .b: return L10n.shared.t("针对无根越狱 / 注入", "Rootless & injection")
        case .a: return L10n.shared.t("针对 RootHide / 高级隐藏", "RootHide & deep hiding")
        }
    }

    var badge: String {
        switch self {
        case .c: return "🔵"
        case .b: return "🟡"
        case .a: return "🔴"
        }
    }

    /// 仅本等级的检测项
    var own: [Detector] {
        switch self {
        case .c: return LevelC.all
        case .b: return LevelB.all
        case .a: return LevelA.all
        }
    }

    /// 实际要跑的检测项
    /// - Parameter cascade: true 时递进包含低等级（B=C+B，A=C+B+A）
    func checks(cascade: Bool) -> [Detector] {
        guard cascade else { return own }
        switch self {
        case .c: return LevelC.all
        case .b: return LevelC.all + LevelB.all
        case .a: return LevelC.all + LevelB.all + LevelA.all
        }
    }

    /// 兼容旧调用：默认不递进
    var checks: [Detector] { own }
}

/// 单个检测项
struct Detector: Identifiable {
    let id: String
    let level: DetectionLevel
    /// 简称（列表里显示）
    let name: String
    /// 详细说明（点开看）
    let detail: String
    /// 返回 nil 表示检测通过；返回非 nil 表示检测到异常，字符串为证据
    let run: () -> String?

    init(id: String, level: DetectionLevel, name: String, detail: String,
         run: @escaping () -> String?) {
        self.id = id
        self.level = level
        self.name = name
        self.detail = detail
        self.run = run
    }
}

/// 单个检测项的执行结果
struct CheckResult: Identifiable {
    let id: String
    let level: DetectionLevel
    let name: String
    let detail: String
    /// true = 检测到异常（❌ 未通过）
    let triggered: Bool
    /// 附加证据（路径、库名、端口等）
    let evidence: String?

    var passed: Bool { !triggered }

    /// 按当前语言显示的名称
    var localizedName: String {
        L10n.shared.detectorName(id: id, fallback: name)
    }

    /// 该项权重
    var weight: Int { DetectorCatalog.weight(for: id) }

    /// 该类检测的绕过思路
    var bypass: String { DetectorCatalog.bypass(for: id) }
}

/// 一次完整扫描的聚合结果
struct ScanReport {
    let level: DetectionLevel
    let results: [CheckResult]
    let startedAt: Date
    let duration: TimeInterval

    var triggeredCount: Int { results.filter(\.triggered).count }
    var passedCount: Int { results.filter(\.passed).count }

    /// 整体判定：任何一项触发即判定为"检测到越狱环境"
    var isJailbroken: Bool { triggeredCount > 0 }

    var headline: String {
        isJailbroken ? "检测到越狱环境" : "未检测到越狱环境"
    }

    var emoji: String {
        isJailbroken ? "😢" : "😋"
    }

    var tint: Color {
        isJailbroken ? Color(red: 0.92, green: 0.32, blue: 0.32)
                     : Color(red: 0.20, green: 0.78, blue: 0.45)
    }

    // MARK: 风险评分

    /// 命中项权重占全部权重的百分比（0–100）
    var riskScore: Int {
        let total = totalWeight
        guard total > 0 else { return 0 }
        let hit = results.filter(\.triggered).reduce(0) { $0 + $1.weight }
        let pct = Double(hit) / Double(total) * 100.0
        return min(100, Int(pct.rounded()))
    }

    /// 命中权重绝对值
    var hitWeight: Int {
        results.filter(\.triggered).reduce(0) { $0 + $1.weight }
    }

    /// 本次扫描涉及项的总权重（不是全部 17 项的权重）
    var totalWeight: Int {
        results.reduce(0) { $0 + $1.weight }
    }

    struct RiskTier {
        let label: String
        let color: Color
    }

    var riskTier: RiskTier {
        switch riskScore {
        case 0:
            return RiskTier(label: "安全", color: Color(red: 0.20, green: 0.78, blue: 0.45))
        case 1...25:
            return RiskTier(label: "低风险", color: Color(red: 0.55, green: 0.78, blue: 0.50))
        case 26...50:
            return RiskTier(label: "中风险", color: Color(red: 0.95, green: 0.75, blue: 0.30))
        case 51...75:
            return RiskTier(label: "高风险", color: Color(red: 0.98, green: 0.55, blue: 0.30))
        default:
            return RiskTier(label: "极高风险", color: Color(red: 0.95, green: 0.30, blue: 0.30))
        }
    }
}
