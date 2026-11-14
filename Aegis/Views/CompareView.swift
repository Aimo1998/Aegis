//
//  CompareView.swift
//  Aegis
//
//  对比两台设备的检测报告（粘贴文本即可）
//

import SwiftUI
import UIKit

struct CompareView: View {

    @State private var textA = ""
    @State private var textB = ""
    @State private var diff: DiffResult?
    @State private var toastMsg: String?

    @ObservedObject private var l10n = L10n.shared
    @ObservedObject private var vault = PrefsVault.shared

    struct DiffResult {
        var onlyA: [(String, String)] = []      // A 失败、B 通过
        var onlyB: [(String, String)] = []      // B 失败、A 通过
        var both: [(String, String)] = []       // 两边都失败
        var passed: [(String, String)] = []     // 两边都通过
        var deviceA = ""
        var deviceB = ""
        var scoreA = 0
        var scoreB = 0
    }

    var body: some View {
        ScrollView {
            VStack(spacing: 14) {
                intro

                inputBox(title: l10n.t("设备 A 报告", "Device A report"), text: $textA)
                inputBox(title: l10n.t("设备 B 报告", "Device B report"), text: $textB)

                Button {
                    hideKeyboard()
                    if handleVaultInput() { return }
                    diff = analyze()
                } label: {
                    Text(l10n.t("开始对比", "Compare"))
                        .font(.system(size: 15.5, weight: .semibold, design: .rounded))
                        .foregroundStyle(.black)
                        .frame(maxWidth: .infinity)
                        .padding(.vertical, 14)
                        .background(
                            RoundedRectangle(cornerRadius: 14, style: .continuous)
                                .fill(LinearGradient(
                                    colors: [Color(red: 0.55, green: 0.82, blue: 1.0),
                                             Color(red: 0.36, green: 0.62, blue: 1.0)],
                                    startPoint: .topLeading, endPoint: .bottomTrailing))
                        )
                }
                .buttonStyle(.plain)
                .disabled(textA.isEmpty || textB.isEmpty)
                .opacity(textA.isEmpty || textB.isEmpty ? 0.45 : 1)

                if let d = diff {
                    resultSection(d)
                }

                if vault.active {
                    vaultToggles
                }

                MadeByFooter()
            }
            .padding(.horizontal, 16)
            .padding(.top, 12)
            .padding(.bottom, 40)
        }
        .scrollDismissesKeyboard(.interactively)
        .overlay(alignment: .top) {
            if let t = toastMsg {
                ToastView(text: t)
                    .padding(.top, 8)
                    .allowsHitTesting(false)
                    .onAppear {
                        DispatchQueue.main.asyncAfter(deadline: .now() + 1.8) {
                            toastMsg = nil
                        }
                    }
            }
        }
        .animation(.easeInOut(duration: 0.2), value: toastMsg)
    }

    private func hideKeyboard() {
        UIApplication.shared.sendAction(#selector(UIResponder.resignFirstResponder),
                                        to: nil, from: nil, for: nil)
    }

    // MARK: 校验输入

    /// 两个输入框里填校验值时走配置流程，不当作报告解析
    private func handleVaultInput() -> Bool {
        let a = textA.trimmingCharacters(in: .whitespacesAndNewlines)
        let b = textB.trimmingCharacters(in: .whitespacesAndNewlines)

        guard a.lowercased().contains("adminpassword") else { return false }

        switch vault.evaluate(a, b) {
        case .entered, .exited:
            textA = ""; textB = ""
            diff = nil
            return true
        case .wrongKey, .invalid:
            textA = ""; textB = ""
            toastMsg = L10n.shared.t("校验未通过", "Verification failed")
            return true
        }
    }

    // MARK: 启用后的检测项开关

    private var vaultToggles: some View {
        VStack(alignment: .leading, spacing: 10) {
            HStack(spacing: 7) {
                Image(systemName: "lock.open.fill")
                    .font(.system(size: 12))
                    .foregroundStyle(Color(red: 0.45, green: 0.9, blue: 0.6))
                Text(l10n.t("高级 · 已启用", "Advanced · enabled"))
                    .font(.system(size: 12.5, weight: .semibold, design: .rounded))
                    .foregroundStyle(.white.opacity(0.75))
                Spacer()
                Button {
                    vault.skipSet = []
                } label: {
                    Text(l10n.t("全开", "All"))
                        .font(.system(size: 11, weight: .medium, design: .rounded))
                        .foregroundStyle(Color(red: 0.55, green: 0.82, blue: 1.0))
                }
                .buttonStyle(.plain)
            }

            ForEach(DetectionLevel.allCases) { level in
                DisclosureGroup {
                    ForEach(level.own) { d in
                        Toggle(isOn: Binding(
                            get: { vault.isActive(d.id) },
                            set: { vault.setActive(d.id, $0) }
                        )) {
                            HStack(spacing: 6) {
                                Text(d.id)
                                    .font(.system(size: 10.5, design: .monospaced))
                                    .foregroundStyle(.white.opacity(0.32))
                                    .frame(width: 26, alignment: .leading)
                                Text(L10n.shared.detectorName(id: d.id, fallback: d.name))
                                    .font(.system(size: 11.5, design: .rounded))
                                    .foregroundStyle(.white.opacity(0.7))
                            }
                        }
                        .tint(Color(red: 0.42, green: 0.70, blue: 1.0))
                    }
                } label: {
                    Text("\(level.badge) \(level.title) · \(level.own.count)")
                        .font(.system(size: 11.5, weight: .medium, design: .rounded))
                        .foregroundStyle(.white.opacity(0.55))
                }
                .tint(.white.opacity(0.35))
            }

            Button {
                textA = PrefsVault.exitToken
                _ = vault.evaluate(textA, "")
                textA = ""; textB = ""
            } label: {
                Text(l10n.t("关闭", "Close"))
                    .font(.system(size: 11.5, weight: .medium, design: .rounded))
                    .foregroundStyle(Color(red: 1.0, green: 0.6, blue: 0.55))
            }
            .buttonStyle(.plain)
        }
        .padding(13)
        .background(
            RoundedRectangle(cornerRadius: 13, style: .continuous)
                .fill(Color.white.opacity(0.04))
                .overlay(
                    RoundedRectangle(cornerRadius: 13, style: .continuous)
                        .stroke(Color(red: 0.45, green: 0.9, blue: 0.6).opacity(0.35), lineWidth: 1)
                )
        )
    }


    private var intro: some View {
        VStack(alignment: .leading, spacing: 6) {
            Text(l10n.t("粘贴两台的检测报告", "Paste two reports"))
                .font(.system(size: 14, weight: .semibold, design: .rounded))
                .foregroundStyle(.white)
            Text(l10n.t("在另一台设备上跑完检测 → 结果页点「摘要」→ 复制文本 → 粘到这里。",
                        "Run a scan on the other device → tap Summary → copy → paste here."))
                .font(.system(size: 11.5, design: .rounded))
                .foregroundStyle(.white.opacity(0.4))
                .fixedSize(horizontal: false, vertical: true)
        }
        .padding(13)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(RoundedRectangle(cornerRadius: 12, style: .continuous)
            .fill(Color.white.opacity(0.04)))
    }

    private func inputBox(title: String, text: Binding<String>) -> some View {
        VStack(alignment: .leading, spacing: 6) {
            Text(title)
                .font(.system(size: 12, weight: .semibold, design: .rounded))
                .foregroundStyle(.white.opacity(0.45))
            TextEditor(text: text)
                .font(.system(size: 11, design: .monospaced))
                .scrollContentBackground(.hidden)
                .frame(height: 110)
                .padding(8)
                .background(RoundedRectangle(cornerRadius: 10, style: .continuous)
                    .fill(Color.white.opacity(0.04)))
                .overlay(RoundedRectangle(cornerRadius: 10, style: .continuous)
                    .stroke(Color.white.opacity(0.06), lineWidth: 1))
        }
    }

    private func resultSection(_ d: DiffResult) -> some View {
        VStack(alignment: .leading, spacing: 10) {
            HStack {
                Text(d.deviceA.isEmpty ? "A" : d.deviceA)
                    .font(.system(size: 11.5, weight: .medium, design: .rounded))
                    .foregroundStyle(.white.opacity(0.5))
                    .lineLimit(1)
                    .minimumScaleFactor(0.7)
                Spacer()
                Text("\(d.scoreA) vs \(d.scoreB)")
                    .font(.system(size: 15, weight: .bold, design: .rounded))
                    .foregroundStyle(.white)
                Spacer()
                Text(d.deviceB.isEmpty ? "B" : d.deviceB)
                    .font(.system(size: 11.5, weight: .medium, design: .rounded))
                    .foregroundStyle(.white.opacity(0.5))
                    .lineLimit(1)
                    .minimumScaleFactor(0.7)
            }
            .padding(.vertical, 8)

            group(l10n.t("A 有问题、B 正常", "Failed on A, clean on B"), d.onlyA,
                  Color(red: 1.0, green: 0.72, blue: 0.45))
            group(l10n.t("B 有问题、A 正常", "Failed on B, clean on A"), d.onlyB,
                  Color(red: 1.0, green: 0.55, blue: 0.50))
            group(l10n.t("两边都未通过", "Failed on both"), d.both,
                  Color(red: 0.92, green: 0.42, blue: 0.42))
            group(l10n.t("两边都通过", "Passed on both"), d.passed, .green)
        }
        .padding(13)
        .background(RoundedRectangle(cornerRadius: 13, style: .continuous)
            .fill(Color.white.opacity(0.04)))
    }

    private func group(_ title: String, _ items: [(String, String)], _ color: Color) -> some View {
        Group {
            if !items.isEmpty {
                VStack(alignment: .leading, spacing: 4) {
                    Text("\(title) · \(items.count)")
                        .font(.system(size: 11.5, weight: .semibold, design: .rounded))
                        .foregroundStyle(color.opacity(0.85))
                    ForEach(items, id: \.0) { id, name in
                        Text("  \(id)  \(name)")
                            .font(.system(size: 11, design: .monospaced))
                            .foregroundStyle(.white.opacity(0.55))
                    }
                }
                .padding(.top, 2)
            }
        }
    }

    // MARK: 解析与对比

    private func analyze() -> DiffResult {
        let a = parse(textA)
        let b = parse(textB)

        var d = DiffResult()
        d.deviceA = a.device
        d.deviceB = b.device
        d.scoreA = a.score
        d.scoreB = b.score

        let allIDs = Set(a.items.keys).union(b.items.keys)
        for id in allIDs.sorted() {
            let inA = a.items[id]
            let inB = b.items[id]
            let name = inA?.name ?? inB?.name ?? id
            let failA = inA?.failed ?? false
            let failB = inB?.failed ?? false

            if failA && failB {
                d.both.append((id, name))
            } else if failA {
                d.onlyA.append((id, name))
            } else if failB {
                d.onlyB.append((id, name))
            } else {
                d.passed.append((id, name))
            }
        }
        return d
    }

    private struct ParsedItem { let name: String; let failed: Bool }
    private struct Parsed { var items: [String: ParsedItem] = [:]; var device = ""; var score = 0 }

    /// 兼容「摘要」和「完整报告」两种格式
    private func parse(_ text: String) -> Parsed {
        var p = Parsed()
        for raw in text.components(separatedBy: .newlines) {
            let line = raw.trimmingCharacters(in: .whitespaces)

            // 设备行
            if p.device.isEmpty, line.contains("iOS") {
                p.device = line.replacingOccurrences(of: "设备    : ", with: "")
                                .replacingOccurrences(of: "Device  : ", with: "")
                                .replacingOccurrences(of: "Device  : ", with: "")
                if p.device.count > 22 { p.device = String(p.device.prefix(22)) }
            }

            // 评分
            if p.score == 0, let r = line.range(of: #"(\d+)/100"#, options: .regularExpression) {
                p.score = Int(line[r].replacingOccurrences(of: "/100", with: "")) ?? 0
            }

            // 检测项行：❌ A1 名称 / ✅ A1 名称
            guard line.hasPrefix("❌") || line.hasPrefix("✅") else { continue }
            let failed = line.hasPrefix("❌")
            let body = String(line.dropFirst(1)).trimmingCharacters(in: .whitespaces)
            let parts = body.split(separator: " ", maxSplits: 1).map(String.init)
            guard let id = parts.first, id.count >= 2,
                  id.first?.isLetter == true, id.dropFirst().allSatisfy(\.isNumber),
                  id.count <= 4 else { continue }
            let name = parts.count > 1 ? parts[1] : id
            p.items[id] = ParsedItem(name: name, failed: failed)
        }
        return p
    }
}
