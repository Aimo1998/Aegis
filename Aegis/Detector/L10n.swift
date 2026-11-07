//
//  L10n.swift
//  Aegis
//
//  轻量双语：中文 / English，运行时切换，无需重启
//

import Foundation
import SwiftUI

final class L10n: ObservableObject {

    static let shared = L10n()

    enum Lang: String, CaseIterable, Identifiable {
        case zh = "zh"
        case en = "en"
        var id: String { rawValue }
        var title: String { self == .zh ? "中文" : "English" }
    }

    @AppStorage("aegis.lang") var rawLang: String = "zh" {
        didSet { objectWillChange.send() }
    }

    var lang: Lang {
        get { Lang(rawValue: rawLang) ?? .zh }
        set { rawLang = newValue.rawValue }
    }

    var isEnglish: Bool { lang == .en }

    /// 双语字符串
    func t(_ zh: String, _ en: String) -> String {
        isEnglish ? en : zh
    }

    // MARK: 检测项名称

    private static let namesEN: [String: String] = [
        "C1": "Filesystem Blacklist",
        "C2": "URL Scheme Probe",
        "C3": "Sandbox Escape",
        "C4": "Environment Variables",
        "C5": "Simulator & Hardware",

        "B1": "Rootless Path",
        "B2": "Injected Frameworks",
        "B3": "UI Tampering (IMP)",
        "B4": "Debugger & Anti-Injection",
        "B5": "RWX Memory",
        "B6": "Process Chain",
        "B7": "Symlink Residue",
        "B8": "Permission Anomaly",
        "B9": "Scheme Declaration",
        "B10": "Self Executable Path",
        "B11": "Dylib Count Baseline",
        "B12": "Local Service Ports",

        "A1": "API Cross-Validation",
        "A2": "Code Signature & TrustCache",
        "A3": "Kernel State",
        "A4": "Timing Attack",
        "A5": "Pointer Integrity",
        "A6": "App Attest",
        "A7": "Mount Point Analysis",
        "A8": "Image Path Consistency",
        "A9": "csops Integrity",
        "A10": "Mach-O Self Check",
        "A11": "Entitlements Check"
    ]

    /// 按 ID 取本地化名称，找不到时回退中文名
    func detectorName(id: String, fallback: String) -> String {
        guard isEnglish else { return fallback }
        return Self.namesEN[id] ?? fallback
    }

    // MARK: 分级

    func levelTitle(_ level: DetectionLevel) -> String {
        switch level {
        case .c: return t("C 级 · 基础特征", "Level C · Basic")
        case .b: return t("B 级 · 动态环境", "Level B · Dynamic")
        case .a: return t("A 级 · 深度对抗", "Level A · Deep")
        }
    }
}
