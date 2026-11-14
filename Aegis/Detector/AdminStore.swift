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

    /// 该检测项是否启用
    func isEnabled(_ id: String) -> Bool {
        !disabledIDs.contains(id)
    }

    func setEnabled(_ id: String, _ on: Bool) {
        var s = disabledIDs
        if on { s.remove(id) } else { s.insert(id) }
        disabledIDs = s
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
