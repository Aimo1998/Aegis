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

    var badge: String {
        switch self {
        case .c: return "🛑"
        case .b: return "🟡"
        case .a: return "🔴"
        }
    }

    /// 该等级包含的所有检测项
    var checks: [Detector] {
        switch self {
        case .c: return LevelC.all
        case .b: return LevelB.all
        case .a: return LevelA.all
        }
    }
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
}
