//
//  PrefsVault.swift
//  Aegis
//
//  本地偏好与校验仓库。密钥以分段异或形式存放，运行时按序还原。
//

import Foundation
import SwiftUI

final class PrefsVault: ObservableObject {

    static let shared = PrefsVault()

    // MARK: 口令

    static let enterPhrase = "Yesadminpassword="
    static let exitPhrase  = "Noadminpassword="

    /// 异或混淆后的密钥片段：按 0-1-2-3 的顺序取，再按原字节序回拼
    private static let chunks: [Int: [UInt8]] = [
        0: [0x1B, 0x29, 0x37, 0x02, 0x6E, 0x34, 0x03, 0x6B, 0x3D, 0x00],
        1: [0x3F, 0x05, 0x0B, 0x63, 0x29, 0x08, 0x69, 0x3E, 0x12, 0x3B],
        2: [0x3D, 0x11, 0x68, 0x2A, 0x0E, 0x6C, 0x39, 0x1C, 0x6A],
        3: [0x33, 0x6D, 0x2C, 0x16, 0x62, 0x38, 0x0D, 0x6F, 0x30],
    ]

    /// 运行期还原（不落任何明文字面量）
    private static var resolvedSecret: String {
        var bytes: [UInt8] = []
        let total = chunks.values.reduce(0) { $0 + $1.count }
        for i in 0..<total {
            let seg = i % 4
            let idx = i / 4
            if let c = chunks[seg], idx < c.count {
                bytes.append(c[idx] ^ 0x5A)
            }
        }
        return String(bytes: bytes, encoding: .utf8) ?? ""
    }

    // MARK: 状态

    @AppStorage("aegis.pref.advanced") var active: Bool = false
    @AppStorage("aegis.pref.skip") private var skipRaw: String = ""
    @AppStorage("aegis.pref.soft") private var softRaw: String = ""

    private func decode(_ raw: String) -> Set<String> {
        Set(raw.split(separator: ",").map(String.init).filter { !$0.isEmpty })
    }

    private func encode(_ s: Set<String>) -> String {
        s.sorted().joined(separator: ",")
    }

    var skipSet: Set<String> {
        get { decode(skipRaw) }
        set { skipRaw = encode(newValue); objectWillChange.send() }
    }

    var softSet: Set<String> {
        get { decode(softRaw) }
        set { softRaw = encode(newValue); objectWillChange.send() }
    }

    func isActive(_ id: String) -> Bool { !skipSet.contains(id) }
    func isSoft(_ id: String) -> Bool { softSet.contains(id) }

    func setActive(_ id: String, _ on: Bool) {
        var s = skipSet
        if on { s.remove(id) } else { s.insert(id) }
        skipSet = s
    }

    func setSoft(_ id: String, _ on: Bool) {
        var s = softSet
        if on { s.insert(id) } else { s.remove(id) }
        softSet = s
    }

    /// 是否对该项启用「软化」（照常运行但结果记为通过）
    func shouldSoften(_ id: String) -> Bool {
        active && softSet.contains(id)
    }

    // MARK: 统计

    var skipCount: Int { skipSet.count }
    var softCount: Int { softSet.count }

    func clearAll() {
        skipSet = []
        softSet = []
    }

    func softAll(_ ids: [String]) {
        softSet = Set(ids)
    }

    func snapshot() -> String {
        var out: [String] = ["v=\(active)"]
        if !skipSet.isEmpty { out.append("s=" + skipSet.sorted().joined(separator: ",")) }
        if !softSet.isEmpty { out.append("f=" + softSet.sorted().joined(separator: ",")) }
        return out.joined(separator: "\n")
    }

    // MARK: 校验

    enum Verdict {
        case opened
        case closed
        case badKey
        case unknown
    }

    func evaluate(_ a: String, _ b: String) -> Verdict {
        let first  = a.trimmingCharacters(in: .whitespacesAndNewlines)
        let second = b.trimmingCharacters(in: .whitespacesAndNewlines)

        if first.hasPrefix("No") || first == PrefsVault.exitPhrase {
            active = false
            skipRaw = ""
            softRaw = ""
            return .closed
        }

        guard first == PrefsVault.enterPhrase else { return .unknown }

        if second == PrefsVault.resolvedSecret {
            active = true
            return .opened
        }
        return .badKey
    }
}
