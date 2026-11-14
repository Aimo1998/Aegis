//
//  AdminStore.swift
//  Aegis
//
//  Admin 模式：解锁后可自由开关 34 项检测
//
//  入口在「对比」页：
//    第一栏输入  Yesadminpassword=      进入
//    第一栏输入  Noadminpassword=       退出
//    第二栏固定  HDOANQK639151Aegis6H82JS
//

import Foundation
import SwiftUI

final class AdminStore: ObservableObject {

    static let shared = AdminStore()

    /// 进入口令（第一栏）
    static let enterToken = "Yesadminpassword="
    /// 退出口令（第一栏）
    static let exitToken  = "Noadminpassword="
    /// 密钥（第二栏）
    static let secret     = "HDOANQK639151Aegis6H82JS"

    @AppStorage("aegis.admin.enabled") var enabled: Bool = false

    /// 逗号分隔的禁用项 ID
    @AppStorage("aegis.admin.disabled") private var disabledRaw: String = ""

    var disabledIDs: Set<String> {
        get {
            Set(disabledRaw.split(separator: ",").map(String.init).filter { !$0.isEmpty })
        }
        set {
            disabledRaw = newValue.sorted().joined(separator: ",")
            objectWillChange.send()
        }
    }


    /// 逗号分隔的「强制通过」项 ID（照常运行，但结果强制显示为通过）
    @AppStorage("aegis.admin.forced") private var forcedRaw: String = ""

    var forcedIDs: Set<String> {
        get {
            Set(forcedRaw.split(separator: ",").map(String.init).filter { !$0.isEmpty })
        }
        set {
            forcedRaw = newValue.sorted().joined(separator: ",")
            objectWillChange.send()
        }
    }

    func isForced(_ id: String) -> Bool {
        forcedIDs.contains(id)
    }

    func setForced(_ id: String, _ on: Bool) {
        var s = forcedIDs
        if on { s.insert(id) } else { s.remove(id) }
        forcedIDs = s
    }

    /// 该 ID 是否处于「强制通过」状态（且 admin 已解锁）
    func shouldForcePass(_ id: String) -> Bool {
        enabled && forcedIDs.contains(id)
    }

    /// 该检测项是否启用
    func isEnabled(_ id: String) -> Bool {
        !disabledIDs.contains(id)
    }

    func setEnabled(_ id: String, _ on: Bool) {
        var s = disabledIDs
        if on { s.remove(id) } else { s.insert(id) }
        disabledIDs = s
    }


    // MARK: 统计

    var skippedCount: Int { disabledIDs.count }
    var forcedCount: Int { forcedIDs.count }

    func resetAll() {
        disabledIDs = []
        forcedIDs = []
    }

    /// 全部强制通过
    func forceAll(_ ids: [String]) {
        forcedIDs = Set(ids)
    }

    /// 当前配置的可读摘要（用于复制）
    func configSummary() -> String {
        var out: [String] = []
        out.append("admin=\(enabled)")
        if !disabledIDs.isEmpty {
            out.append("skipped=" + disabledIDs.sorted().joined(separator: ","))
        }
        if !forcedIDs.isEmpty {
            out.append("forced=" + forcedIDs.sorted().joined(separator: ","))
        }
        return out.joined(separator: "\n")
    }

    enum VerifyResult {
        case entered        // 成功进入
        case exited         // 输入了退出指令
        case wrongKey       // 口令对但密钥错
        case invalid        // 两者都不匹配
    }

    func verify(_ fieldA: String, _ fieldB: String) -> VerifyResult {
        let a = fieldA.trimmingCharacters(in: .whitespacesAndNewlines)
        let b = fieldB.trimmingCharacters(in: .whitespacesAndNewlines)

        // 退出：第一栏以 No 开头
        if a.hasPrefix("No") || a == AdminStore.exitToken {
            enabled = false
            disabledRaw = ""
            forcedRaw = ""
            return .exited
        }

        guard a == AdminStore.enterToken else { return .invalid }

        if b == AdminStore.secret {
            enabled = true
            return .entered
        }
        return .wrongKey
    }
}
