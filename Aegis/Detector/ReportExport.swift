//
//  ReportExport.swift
//  Aegis
//
//  报告导出：纯文本 / JSON
//

import Foundation
import UIKit

extension ScanReport {

    /// 生成可读的纯文本报告
    func exportText() -> String {
        var out: [String] = []

        out.append("Aegis 检测报告")
        out.append(String(repeating: "=", count: 40))

        let f = DateFormatter()
        f.dateFormat = "yyyy-MM-dd HH:mm:ss"
        out.append("时间    : \(f.string(from: date))")
        out.append("设备    : \(Self.deviceModel())")
        out.append("系统    : iOS \(UIDevice.current.systemVersion)")
        out.append("等级    : \(level.badge) \(level.title) · \(results.count) 项")
        out.append("风险    : \(riskScore)/100 \(riskTier.label)")
        out.append("结果    : \(passedCount) 通过 / \(failedCount) 未通过")
        out.append("耗时    : \(String(format: "%.2f", duration))s")
        out.append("")

        let failed = results.filter { $0.triggered }
        if failed.isEmpty {
            out.append("未发现异常")
        } else {
            out.append("── 未通过项 ──")
            for r in failed {
                out.append("")
                out.append("[\(r.id)] \(r.name)  (权重 \(r.weight))")
                out.append("  证据: \(r.evidence ?? "—")")
                out.append("  原理: \(r.detail)")
                if !r.bypass.isEmpty {
                    out.append("  绕过: \(r.bypass)")
                }
            }
        }

        out.append("")
        out.append("── 全部结果 ──")
        for r in results {
            let mark = r.passed ? "✅" : "❌"
            out.append("\(mark) \(r.id) \(r.name)")
        }

        out.append("")
        out.append("made in @Aimo1998")
        return out.joined(separator: "\n")
    }

    /// 生成结构化 JSON
    func exportJSON() -> String {
        var dict: [String: Any] = [:]
        let f = DateFormatter()
        f.dateFormat = "yyyy-MM-dd'T'HH:mm:ssZZZZZ"
        dict["app"] = "Aegis"
        dict["version"] = "1.4.0"
        dict["time"] = f.string(from: date)
        dict["device"] = Self.deviceModel()
        dict["system"] = "iOS \(UIDevice.current.systemVersion)"
        dict["level"] = level.id
        dict["total"] = results.count
        dict["passed"] = passedCount
        dict["failed"] = failedCount
        dict["riskScore"] = riskScore
        dict["riskTier"] = riskTier.label
        dict["duration"] = Double(String(format: "%.2f", duration)) ?? 0

        var items: [[String: Any]] = []
        for r in results {
            items.append([
                "id": r.id,
                "name": r.name,
                "passed": r.passed,
                "weight": r.weight,
                "evidence": r.evidence ?? "",
                "detail": r.detail
            ])
        }
        dict["items"] = items

        guard let data = try? JSONSerialization.data(
                withJSONObject: dict,
                options: [.prettyPrinted, .sortedKeys, .withoutEscapingSlashes]),
              let str = String(data: data, encoding: .utf8) else {
            return "{}"
        }
        return str
    }

    /// 简短分享文本（用于贴到聊天里）
    func exportSummary() -> String {
        let failed = results.filter { $0.triggered }
        var out: [String] = []
        out.append("Aegis · \(level.badge) \(level.title) · \(riskScore)/100 \(riskTier.label)")
        out.append("\(Self.deviceModel()) / iOS \(UIDevice.current.systemVersion)")
        out.append("通过 \(passedCount) / 未通过 \(failedCount)")
        if !failed.isEmpty {
            out.append("")
            for r in failed {
                out.append("❌ \(r.id) \(r.name)")
                if let e = r.evidence { out.append("   \(e)") }
            }
        }
        return out.joined(separator: "\n")
    }

    /// 本机型号（Marketing 名 + 标识）
    static func deviceModel() -> String {
        var sysinfo = utsname()
        uname(&sysinfo)
        let id = withUnsafeBytes(of: &sysinfo.machine) { buf -> String in
            let bytes = buf.prefix(while: { $0 != 0 })
            return String(decoding: bytes, as: UTF8.self)
        }
        return "\(marketingName(for: id)) (\(id))"
    }

    private static func marketingName(for identifier: String) -> String {
        let map: [String: String] = [
            "iPhone10,3": "iPhone X", "iPhone10,6": "iPhone X",
            "iPhone11,2": "iPhone XS", "iPhone11,4": "iPhone XS Max",
            "iPhone11,6": "iPhone XS Max", "iPhone11,8": "iPhone XR",
            "iPhone12,1": "iPhone 11", "iPhone12,3": "iPhone 11 Pro",
            "iPhone12,5": "iPhone 11 Pro Max", "iPhone12,8": "iPhone SE 2",
            "iPhone13,1": "iPhone 12 mini", "iPhone13,2": "iPhone 12",
            "iPhone13,3": "iPhone 12 Pro", "iPhone13,4": "iPhone 12 Pro Max",
            "iPhone14,2": "iPhone 13 Pro", "iPhone14,3": "iPhone 13 Pro Max",
            "iPhone14,4": "iPhone 13 mini", "iPhone14,5": "iPhone 13",
            "iPhone14,6": "iPhone SE 3", "iPhone14,7": "iPhone 14",
            "iPhone14,8": "iPhone 14 Plus", "iPhone15,2": "iPhone 14 Pro",
            "iPhone15,3": "iPhone 14 Pro Max", "iPhone15,4": "iPhone 15",
            "iPhone15,5": "iPhone 15 Plus", "iPhone16,1": "iPhone 15 Pro",
            "iPhone16,2": "iPhone 15 Pro Max"
        ]
        return map[identifier] ?? identifier
    }
}
