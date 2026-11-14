//
//  AdminView.swift
//  Aegis
//
//  Admin 模式：解锁后可自由开关 34 项检测
//

import SwiftUI

struct AdminSection: View {

    @ObservedObject private var admin = AdminStore.shared
    @ObservedObject private var l10n = L10n.shared

    @State private var fieldA = ""
    @State private var fieldB = ""
    @State private var message: String?
    @State private var messageOK = false

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            header

            if admin.enabled {
                unlocked
            } else {
                locked
            }
        }
        .padding(13)
        .background(
            RoundedRectangle(cornerRadius: 13, style: .continuous)
                .fill(Color.white.opacity(0.04))
                .overlay(
                    RoundedRectangle(cornerRadius: 13, style: .continuous)
                        .stroke(admin.enabled
                                ? Color(red: 0.45, green: 0.9, blue: 0.6).opacity(0.4)
                                : Color.white.opacity(0.06),
                                lineWidth: 1)
                )
        )
    }

    private var header: some View {
        HStack(spacing: 8) {
            Image(systemName: admin.enabled ? "lock.open.fill" : "lock.fill")
                .font(.system(size: 13))
                .foregroundStyle(admin.enabled
                                 ? Color(red: 0.45, green: 0.9, blue: 0.6)
                                 : .white.opacity(0.4))
            Text(l10n.t("管理", "Admin"))
                .font(.system(size: 13, weight: .semibold, design: .rounded))
                .foregroundStyle(.white.opacity(0.75))
            Spacer()
            if admin.enabled {
                Text(l10n.t("已解锁", "unlocked"))
                    .font(.system(size: 10.5, weight: .medium, design: .rounded))
                    .foregroundStyle(Color(red: 0.45, green: 0.9, blue: 0.6))
            }
        }
    }

    // MARK: 未解锁

    private var locked: some View {
        VStack(spacing: 8) {
            field(l10n.t("口令", "Passphrase"), text: $fieldA)
            field(l10n.t("密钥", "Key"), text: $fieldB)

            Button {
                submit()
            } label: {
                Text(l10n.t("验证", "Verify"))
                    .font(.system(size: 13, weight: .semibold, design: .rounded))
                    .foregroundStyle(.black)
                    .frame(maxWidth: .infinity)
                    .padding(.vertical, 10)
                    .background(
                        RoundedRectangle(cornerRadius: 10, style: .continuous)
                            .fill(Color(red: 0.55, green: 0.82, blue: 1.0))
                    )
            }
            .buttonStyle(.plain)
            .disabled(fieldA.isEmpty)

            if let m = message {
                Text(m)
                    .font(.system(size: 11, design: .rounded))
                    .foregroundStyle(messageOK
                                     ? Color(red: 0.45, green: 0.9, blue: 0.6)
                                     : Color(red: 1.0, green: 0.55, blue: 0.5))
                    .frame(maxWidth: .infinity, alignment: .leading)
            }
        }
    }

    private func field(_ title: String, text: Binding<String>) -> some View {
        TextField(title, text: text)
            .textInputAutocapitalization(.never)
            .autocorrectionDisabled()
            .font(.system(size: 12, design: .monospaced))
            .padding(.horizontal, 10)
            .padding(.vertical, 9)
            .background(
                RoundedRectangle(cornerRadius: 9, style: .continuous)
                    .fill(Color.white.opacity(0.05))
            )
            .foregroundStyle(.white)
    }

    // MARK: 已解锁

    private var unlocked: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text(l10n.t("勾选要参与的检测项，取消即跳过", "Toggle the checks that should run"))
                .font(.system(size: 10.5, design: .rounded))
                .foregroundStyle(.white.opacity(0.35))

            ForEach(DetectionLevel.allCases) { level in
                DisclosureGroup {
                    ForEach(level.own) { d in
                        toggleRow(d)
                    }
                } label: {
                    Text("\(level.badge) \(level.title) · \(level.own.count)")
                        .font(.system(size: 12, weight: .medium, design: .rounded))
                        .foregroundStyle(.white.opacity(0.6))
                }
                .tint(.white.opacity(0.4))
            }

            Button {
                admin.disabledIDs = []
                message = l10n.t("已全部启用", "All enabled")
                messageOK = true
            } label: {
                Text(l10n.t("全部启用", "Enable all"))
                    .font(.system(size: 12, weight: .medium, design: .rounded))
                    .foregroundStyle(Color(red: 0.55, green: 0.82, blue: 1.0))
            }
            .buttonStyle(.plain)

            Button {
                fieldA = AdminStore.exitToken
                _ = admin.verify(fieldA, "")
                fieldA = ""
                fieldB = ""
                message = l10n.t("已退出管理", "Exited admin")
                messageOK = true
            } label: {
                Text(l10n.t("退出管理", "Exit admin"))
                    .font(.system(size: 12, weight: .medium, design: .rounded))
                    .foregroundStyle(Color(red: 1.0, green: 0.6, blue: 0.55))
            }
            .buttonStyle(.plain)
        }
    }

    private func toggleRow(_ d: Detector) -> some View {
        Toggle(isOn: Binding(
            get: { admin.isEnabled(d.id) },
            set: { admin.setEnabled(d.id, $0) }
        )) {
            HStack(spacing: 6) {
                Text(d.id)
                    .font(.system(size: 10.5, design: .monospaced))
                    .foregroundStyle(.white.opacity(0.35))
                    .frame(width: 26, alignment: .leading)
                Text(L10n.shared.detectorName(id: d.id, fallback: d.name))
                    .font(.system(size: 11.5, design: .rounded))
                    .foregroundStyle(.white.opacity(0.7))
            }
        }
        .tint(Color(red: 0.42, green: 0.70, blue: 1.0))
    }

    private func submit() {
        switch admin.verify(fieldA, fieldB) {
        case .entered:
            message = l10n.t("已解锁", "Unlocked")
            messageOK = true
            fieldA = ""; fieldB = ""
        case .exited:
            message = l10n.t("已退出管理", "Exited admin")
            messageOK = true
            fieldA = ""; fieldB = ""
        case .wrongKey:
            message = l10n.t("密钥不正确", "Wrong key")
            messageOK = false
        case .invalid:
            message = l10n.t("口令不正确", "Wrong passphrase")
            messageOK = false
        }
    }
}
