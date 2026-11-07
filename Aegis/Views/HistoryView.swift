//
//  HistoryView.swift
//  Aegis
//
//  扫描历史 + 与上次同等级结果的变化对比
//

import SwiftUI

struct HistoryView: View {

    @ObservedObject private var store = HistoryStore.shared
    @State private var expandedID: UUID?

    private let bg = Color(red: 0.05, green: 0.06, blue: 0.10)

    var body: some View {
        ScrollView {
            VStack(spacing: 12) {
                if store.entries.isEmpty {
                    emptyState
                } else {
                    ForEach(store.entries) { entry in
                        entryCard(entry)
                    }
                }

                MadeByFooter()
            }
            .padding(.horizontal, 16)
            .padding(.top, 12)
            .padding(.bottom, 40)
        }
        .background(bg.ignoresSafeArea())
        .navigationTitle("历史记录")
        .navigationBarTitleDisplayMode(.inline)
        .toolbar {
            ToolbarItem(placement: .topBarTrailing) {
                if !store.entries.isEmpty {
                    Button(role: .destructive) {
                        store.clear()
                    } label: {
                        Image(systemName: "trash")
                    }
                }
            }
        }
    }

    private var emptyState: some View {
        VStack(spacing: 12) {
            Text("📭")
                .font(.system(size: 52))
            Text("还没有扫描记录")
                .font(.system(size: 15, weight: .medium, design: .rounded))
                .foregroundStyle(.white.opacity(0.5))
            Text("回到「检测」跑一次，这里就会出现记录")
                .font(.system(size: 12.5, design: .rounded))
                .foregroundStyle(.white.opacity(0.3))
        }
        .padding(.top, 90)
    }

    private func entryCard(_ entry: HistoryEntry) -> some View {
        let diff = store.diff(for: entry)
        let expanded = expandedID == entry.id

        return VStack(alignment: .leading, spacing: 0) {
            Button {
                withAnimation(.easeInOut(duration: 0.2)) {
                    expandedID = expanded ? nil : entry.id
                }
            } label: {
                HStack(spacing: 11) {
                    Text(entry.isJailbroken ? "😢" : "😋")
                        .font(.system(size: 26))

                    VStack(alignment: .leading, spacing: 3) {
                        HStack(spacing: 6) {
                            Text(entry.level.badge)
                                .font(.system(size: 11))
                            Text(entry.level.title)
                                .font(.system(size: 13, weight: .semibold, design: .rounded))
                                .foregroundStyle(.white.opacity(0.85))
                        }

                        Text(timeText(entry.date))
                            .font(.system(size: 11, design: .rounded))
                            .foregroundStyle(.white.opacity(0.35))
                    }

                    Spacer()

                    VStack(alignment: .trailing, spacing: 2) {
                        Text("\(entry.passed)/\(entry.total)")
                            .font(.system(size: 15, weight: .bold, design: .rounded))
                            .foregroundStyle(entry.isJailbroken
                                             ? Color(red: 1.0, green: 0.55, blue: 0.50)
                                             : .green)
                        Text(String(format: "%.1fs", entry.duration))
                            .font(.system(size: 10, design: .rounded))
                            .foregroundStyle(.white.opacity(0.28))
                    }

                    Image(systemName: expanded ? "chevron.up" : "chevron.down")
                        .font(.system(size: 11, weight: .semibold))
                        .foregroundStyle(.white.opacity(0.22))
                }
                .padding(.horizontal, 13)
                .padding(.vertical, 12)
                .contentShape(Rectangle())
            }
            .buttonStyle(.plain)

            if expanded {
                VStack(alignment: .leading, spacing: 9) {
                    if let prev = diff.previous {
                        if prev.total == entry.total {
                            comparisonBlock(diff: diff, previous: prev)
                        } else {
                            Text("扫描范围不同（上次 \(prev.total) 项，本次 \(entry.total) 项），无法直接对比")
                                .font(.system(size: 11.5, design: .rounded))
                                .foregroundStyle(Color(red: 1.0, green: 0.75, blue: 0.45).opacity(0.8))
                        }
                    } else {
                        Text("这是该等级的第一条记录，暂无对比基准")
                            .font(.system(size: 11.5, design: .rounded))
                            .foregroundStyle(.white.opacity(0.35))
                    }

                    if !entry.failedIDs.isEmpty {
                        VStack(alignment: .leading, spacing: 4) {
                            Text("本次未通过 \(entry.failedIDs.count) 项")
                                .font(.system(size: 11, weight: .semibold, design: .rounded))
                                .foregroundStyle(.white.opacity(0.4))
                            ForEach(entry.failedIDs, id: \.self) { id in
                                Text("❌ \(DetectorCatalog.name(for: id)) (\(id))")
                                    .font(.system(size: 11.5, design: .monospaced))
                                    .foregroundStyle(Color(red: 1.0, green: 0.62, blue: 0.58))
                            }
                        }
                    }
                }
                .padding(.horizontal, 14)
                .padding(.bottom, 13)
                .transition(.opacity.combined(with: .move(edge: .top)))
            }
        }
        .background(
            RoundedRectangle(cornerRadius: 13, style: .continuous)
                .fill(Color.white.opacity(0.04))
                .overlay(
                    RoundedRectangle(cornerRadius: 13, style: .continuous)
                        .stroke(Color.white.opacity(0.06), lineWidth: 1)
                )
        )
    }

    private func comparisonBlock(diff: HistoryStore.Diff, previous: HistoryEntry) -> some View {
        VStack(alignment: .leading, spacing: 5) {
            Text("对比上次（\(timeText(previous.date))）")
                .font(.system(size: 11, weight: .semibold, design: .rounded))
                .foregroundStyle(.white.opacity(0.4))

            if diff.newlyFailed.isEmpty && diff.recovered.isEmpty {
                Text("✅ 与上次完全一致")
                    .font(.system(size: 11.5, design: .rounded))
                    .foregroundStyle(.green.opacity(0.8))
            } else {
                ForEach(diff.newlyFailed, id: \.self) { id in
                    Text("🔴 新增失败：\(DetectorCatalog.name(for: id)) (\(id))")
                        .font(.system(size: 11.5, design: .monospaced))
                        .foregroundStyle(Color(red: 1.0, green: 0.55, blue: 0.50))
                }
                ForEach(diff.recovered, id: \.self) { id in
                    Text("🟢 已恢复：\(DetectorCatalog.name(for: id)) (\(id))")
                        .font(.system(size: 11.5, design: .monospaced))
                        .foregroundStyle(.green.opacity(0.85))
                }
            }
        }
    }

    private func timeText(_ date: Date) -> String {
        let f = DateFormatter()
        f.dateFormat = "MM-dd HH:mm"
        return f.string(from: date)
    }
}
