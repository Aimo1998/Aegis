//
//  ResultView.swift
//  Aegis
//
//  检测结果页：大 emoji + 判定文案 + 逐项清单
//

import SwiftUI

struct ResultView: View {

    let report: ScanReport
    let onRescan: () -> Void

    var body: some View {
        ScrollView {
            VStack(spacing: 24) {
                verdictHeader
                statBar

                VStack(spacing: 10) {
                    ForEach(groupedResults, id: \.level) { group in
                        sectionHeader(group.level)
                        ForEach(group.items) { item in
                            CheckRow(result: item)
                        }
                    }
                }

                rescanButton
                footer
            }
            .padding(.horizontal, 20)
            .padding(.top, 34)
            .padding(.bottom, 40)
        }
    }

    // MARK: 判定头

    private var verdictHeader: some View {
        VStack(spacing: 12) {
            Text(report.emoji)
                .font(.system(size: 104))
                .shadow(color: report.tint.opacity(0.45), radius: 24, x: 0, y: 8)

            Text(report.headline)
                .font(.system(size: 25, weight: .bold, design: .rounded))
                .foregroundStyle(report.isJailbroken ? report.tint : .white)
                .multilineTextAlignment(.center)

            Text(report.level.title + " · 共 \(report.results.count) 项")
                .font(.system(size: 13, weight: .medium, design: .rounded))
                .foregroundStyle(.white.opacity(0.42))
        }
        .padding(.bottom, 2)
    }

    // MARK: 统计条

    private var statBar: some View {
        HStack(spacing: 0) {
            statCell(value: "\(report.passedCount)", label: "通过", color: Color(red: 0.30, green: 0.82, blue: 0.50))
            divider
            statCell(value: "\(report.triggeredCount)", label: "未通过", color: report.tint)
            divider
            statCell(value: String(format: "%.2fs", report.duration), label: "耗时", color: .white.opacity(0.75))
        }
        .padding(.vertical, 15)
        .background(
            RoundedRectangle(cornerRadius: 16, style: .continuous)
                .fill(Color.white.opacity(0.05))
                .overlay(
                    RoundedRectangle(cornerRadius: 16, style: .continuous)
                        .stroke(Color.white.opacity(0.07), lineWidth: 1)
                )
        )
    }

    private var divider: some View {
        Rectangle()
            .fill(Color.white.opacity(0.08))
            .frame(width: 1, height: 30)
    }

    private func statCell(value: String, label: String, color: Color) -> some View {
        VStack(spacing: 3) {
            Text(value)
                .font(.system(size: 21, weight: .bold, design: .rounded))
                .foregroundStyle(color)
            Text(label)
                .font(.system(size: 11.5, weight: .medium, design: .rounded))
                .foregroundStyle(.white.opacity(0.40))
        }
        .frame(maxWidth: .infinity)
    }

    // MARK: 分组

    private struct ResultGroup {
        let level: DetectionLevel
        let items: [CheckResult]
    }

    private var groupedResults: [ResultGroup] {
        let order: [DetectionLevel] = [.c, .b, .a]
        return order.compactMap { lv in
            let items = report.results.filter { $0.level == lv }
            return items.isEmpty ? nil : ResultGroup(level: lv, items: items)
        }
    }

    private func sectionHeader(_ level: DetectionLevel) -> some View {
        HStack(spacing: 8) {
            Text(level.badge)
                .font(.system(size: 14))
            Text(level.title)
                .font(.system(size: 13, weight: .semibold, design: .rounded))
                .foregroundStyle(.white.opacity(0.55))
            Spacer()
        }
        .padding(.top, 10)
        .padding(.horizontal, 4)
    }

    // MARK: 底部

    private var rescanButton: some View {
        Button(action: onRescan) {
            HStack(spacing: 9) {
                Image(systemName: "arrow.clockwise")
                    .font(.system(size: 15, weight: .semibold))
                Text("重新检测")
                    .font(.system(size: 16, weight: .semibold, design: .rounded))
            }
            .foregroundStyle(.white)
            .frame(maxWidth: .infinity)
            .padding(.vertical, 15)
            .background(
                RoundedRectangle(cornerRadius: 15, style: .continuous)
                    .fill(Color.white.opacity(0.08))
                    .overlay(
                        RoundedRectangle(cornerRadius: 15, style: .continuous)
                            .stroke(Color.white.opacity(0.12), lineWidth: 1)
                    )
            )
        }
        .buttonStyle(.plain)
        .padding(.top, 12)
    }

    private var footer: some View {
        Text("Aegis 检测结果仅供参考，单项异常不必然等同于环境被入侵")
            .font(.system(size: 11.5, weight: .regular, design: .rounded))
            .foregroundStyle(.white.opacity(0.28))
            .multilineTextAlignment(.center)
            .padding(.horizontal, 16)
    }
}

// MARK: - 单行

struct CheckRow: View {

    let result: CheckResult
    @State private var expanded: Bool = false

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            Button {
                withAnimation(.easeInOut(duration: 0.2)) {
                    expanded.toggle()
                }
            } label: {
                HStack(alignment: .top, spacing: 10) {
                    Text(result.passed ? "✅" : "❌")
                        .font(.system(size: 15))

                    VStack(alignment: .leading, spacing: 3) {
                        // 用户指定格式：✅xxx检测通过 / ❌xxx检测未通过
                        Text("\(result.name)检测\(result.passed ? "通过" : "未通过")")
                            .font(.system(size: 14.5, weight: .medium, design: .rounded))
                            .foregroundStyle(result.passed
                                             ? Color.white.opacity(0.88)
                                             : Color(red: 1.0, green: 0.55, blue: 0.50))
                            .multilineTextAlignment(.leading)

                        if !result.passed, let ev = result.evidence, !expanded {
                            Text(ev)
                                .font(.system(size: 11.5, weight: .regular, design: .monospaced))
                                .foregroundStyle(.white.opacity(0.38))
                                .lineLimit(1)
                                .truncationMode(.middle)
                        }
                    }

                    Spacer(minLength: 4)

                    Image(systemName: expanded ? "chevron.up" : "chevron.down")
                        .font(.system(size: 11, weight: .semibold))
                        .foregroundStyle(.white.opacity(0.22))
                        .padding(.top, 3)
                }
                .padding(.horizontal, 14)
                .padding(.vertical, 12)
                .contentShape(Rectangle())
            }
            .buttonStyle(.plain)

            if expanded {
                VStack(alignment: .leading, spacing: 8) {
                    Text(result.detail)
                        .font(.system(size: 12, weight: .regular, design: .rounded))
                        .foregroundStyle(.white.opacity(0.52))
                        .fixedSize(horizontal: false, vertical: true)

                    if let ev = result.evidence {
                        HStack(alignment: .top, spacing: 6) {
                            Text("证据")
                                .font(.system(size: 10.5, weight: .bold, design: .rounded))
                                .foregroundStyle(.white.opacity(0.35))
                            Text(ev)
                                .font(.system(size: 11.5, weight: .regular, design: .monospaced))
                                .foregroundStyle(Color(red: 1.0, green: 0.72, blue: 0.45))
                                .fixedSize(horizontal: false, vertical: true)
                        }
                    }
                }
                .padding(.horizontal, 38)
                .padding(.bottom, 13)
                .transition(.opacity.combined(with: .move(edge: .top)))
            }
        }
        .background(
            RoundedRectangle(cornerRadius: 13, style: .continuous)
                .fill(Color.white.opacity(result.passed ? 0.035 : 0.065))
                .overlay(
                    RoundedRectangle(cornerRadius: 13, style: .continuous)
                        .stroke(result.passed
                                ? Color.white.opacity(0.05)
                                : Color(red: 1.0, green: 0.45, blue: 0.42).opacity(0.28),
                                lineWidth: 1)
                )
        )
    }
}
