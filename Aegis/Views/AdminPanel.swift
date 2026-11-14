//
//  AdminPanel.swift
//  Aegis
//
//  管理面板：从菜单进入，仅 admin 解锁后可见
//  每一项三态循环：正常 → 跳过 → 强制通过 → 正常
//

import SwiftUI
import UIKit

enum AdminCheckState {
    case normal        // 正常运行
    case skipped       // 跳过（不计入）
    case forced        // 照常运行但强制显示通过
}

struct AdminPanel: View {

    @ObservedObject private var admin = AdminStore.shared
    @ObservedObject private var l10n = L10n.shared
    @Environment(\.dismiss) private var dismiss

    @State private var toast: String?

    var body: some View {
        ScrollView {
            VStack(spacing: 14) {
                summary
                ForEach(DetectionLevel.allCases) { level in
                    section(level)
                }
                actions
                MadeByFooter()
            }
            .padding(.horizontal, 16)
            .padding(.top, 12)
            .padding(.bottom, 40)
        }
        .background(Color(red: 0.05, green: 0.06, blue: 0.10).ignoresSafeArea())
        .navigationTitle(l10n.t("管理", "Admin"))
        .navigationBarTitleDisplayMode(.inline)
        .overlay(alignment: .top) {
            if let t = toast {
                ToastView(text: t)
                    .padding(.top, 8)
                    .allowsHitTesting(false)
            }
        }
        .animation(.easeInOut(duration: 0.2), value: toast)
    }

    // MARK: 顶部统计

    private var summary: some View {
        HStack(spacing: 0) {
            cell("\(admin.skippedCount)", l10n.t("跳过", "Skipped"),
                 Color(red: 1.0, green: 0.72, blue: 0.45))
            Rectangle().fill(Color.white.opacity(0.08)).frame(width: 1, height: 26)
            cell("\(admin.forcedCount)", l10n.t("强制通过", "Forced"),
                 Color(red: 0.45, green: 0.9, blue: 0.6))
            Rectangle().fill(Color.white.opacity(0.08)).frame(width: 1, height: 26)
            cell("\(34 - admin.skippedCount)", l10n.t("实际运行", "Running"),
                 .white.opacity(0.75))
        }
        .padding(.vertical, 14)
        .background(
            RoundedRectangle(cornerRadius: 14, style: .continuous)
                .fill(Color.white.opacity(0.05))
        )
    }

    private func cell(_ value: String, _ label: String, _ color: Color) -> some View {
        VStack(spacing: 3) {
            Text(value)
                .font(.system(size: 19, weight: .bold, design: .rounded))
                .foregroundStyle(color)
            Text(label)
                .font(.system(size: 10.5, design: .rounded))
                .foregroundStyle(.white.opacity(0.4))
        }
        .frame(maxWidth: .infinity)
    }

    // MARK: 分组

    private func section(_ level: DetectionLevel) -> some View {
        VStack(alignment: .leading, spacing: 6) {
            HStack(spacing: 6) {
                Text(level.badge).font(.system(size: 12))
                Text("\(level.title) · \(level.own.count)")
                    .font(.system(size: 12, weight: .semibold, design: .rounded))
                    .foregroundStyle(.white.opacity(0.55))
                Spacer()
            }
            .padding(.horizontal, 4)

            ForEach(level.own) { d in
                row(d)
            }
        }
    }

    private func row(_ d: Detector) -> some View {
        let state = stateOf(d.id)

        return Button {
            cycle(d.id)
        } label: {
            HStack(spacing: 9) {
                Text(icon(state))
                    .font(.system(size: 14))
                    .frame(width: 20)

                Text(d.id)
                    .font(.system(size: 10.5, design: .monospaced))
                    .foregroundStyle(.white.opacity(0.32))
                    .frame(width: 26, alignment: .leading)

                Text(L10n.shared.detectorName(id: d.id, fallback: d.name))
                    .font(.system(size: 12, design: .rounded))
                    .foregroundStyle(color(state).opacity(0.9))
                    .lineLimit(1)

                Spacer(minLength: 4)

                Text(label(state))
                    .font(.system(size: 10, weight: .medium, design: .rounded))
                    .foregroundStyle(color(state).opacity(0.75))
            }
            .padding(.horizontal, 12)
            .padding(.vertical, 9)
            .background(
                RoundedRectangle(cornerRadius: 10, style: .continuous)
                    .fill(Color.white.opacity(state == .normal ? 0.03 : 0.07))
                    .overlay(
                        RoundedRectangle(cornerRadius: 10, style: .continuous)
                            .stroke(color(state).opacity(state == .normal ? 0.05 : 0.25),
                                    lineWidth: 1)
                    )
            )
        }
        .buttonStyle(.plain)
    }

    private var actions: some View {
        VStack(spacing: 8) {
            Button {
                admin.resetAll()
                toast = l10n.t("已全部恢复", "All reset")
            } label: {
                actionLabel(l10n.t("全部恢复正常", "Reset all"),
                            Color(red: 0.55, green: 0.82, blue: 1.0))
            }
            .buttonStyle(.plain)

            Button {
                var all: [String] = []
                for level in DetectionLevel.allCases { all += level.own.map(\.id) }
                admin.forceAll(all)
                toast = l10n.t("全部强制通过", "All forced")
            } label: {
                actionLabel(l10n.t("全部强制通过", "Force all"),
                            Color(red: 0.45, green: 0.9, blue: 0.6))
            }
            .buttonStyle(.plain)

            Button {
                UIPasteboard.general.string = admin.configSummary()
                toast = l10n.t("配置已复制", "Config copied")
            } label: {
                actionLabel(l10n.t("复制当前配置", "Copy config"),
                            .white.opacity(0.6))
            }
            .buttonStyle(.plain)
        }
    }

    private func actionLabel(_ title: String, _ color: Color) -> some View {
        Text(title)
            .font(.system(size: 13, weight: .medium, design: .rounded))
            .foregroundStyle(color)
            .frame(maxWidth: .infinity)
            .padding(.vertical, 11)
            .background(
                RoundedRectangle(cornerRadius: 11, style: .continuous)
                    .fill(color.opacity(0.1))
            )
    }

    // MARK: 状态

    private func stateOf(_ id: String) -> AdminCheckState {
        if !admin.isEnabled(id) { return .skipped }
        if admin.isForced(id) { return .forced }
        return .normal
    }

    private func cycle(_ id: String) {
        switch stateOf(id) {
        case .normal:
            admin.setEnabled(id, false)
        case .skipped:
            admin.setEnabled(id, true)
            admin.setForced(id, true)
        case .forced:
            admin.setForced(id, false)
        }
    }

    private func icon(_ s: AdminCheckState) -> String {
        switch s {
        case .normal:  return "✅"
        case .skipped: return "⏭"
        case .forced:  return "🟢"
        }
    }

    private func label(_ s: AdminCheckState) -> String {
        switch s {
        case .normal:  return l10n.t("正常", "on")
        case .skipped: return l10n.t("跳过", "skip")
        case .forced:  return l10n.t("强制通过", "force")
        }
    }

    private func color(_ s: AdminCheckState) -> Color {
        switch s {
        case .normal:  return .white.opacity(0.7)
        case .skipped: return Color(red: 1.0, green: 0.72, blue: 0.45)
        case .forced:  return Color(red: 0.45, green: 0.9, blue: 0.6)
        }
    }
}
