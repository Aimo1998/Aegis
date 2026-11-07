//
//  DylibListView.swift
//  Aegis
//
//  注入库清单：枚举当前进程所有已加载的 dylib
//

import SwiftUI

struct DylibListView: View {

    @State private var images: [LoadedImage] = []
    @State private var loading = false

    private var groups: [(ImageCategory, [LoadedImage])] {
        DylibScanner.grouped(images)
    }

    private var injectedCount: Int {
        images.filter { $0.category == .jailbreakInjected }.count
    }

    var body: some View {
        ScrollView {
            VStack(spacing: 14) {
                summaryCard

                if loading {
                    ProgressView()
                        .padding(40)
                } else if images.isEmpty {
                    Text("未枚举到映像")
                        .font(.system(size: 13, design: .rounded))
                        .foregroundStyle(.white.opacity(0.4))
                        .padding(40)
                } else {
                    ForEach(Array(groups.enumerated()), id: \.offset) { _, group in
                        sectionView(category: group.0, items: group.1)
                    }
                }

                MadeByFooter()
            }
            .padding(.horizontal, 16)
            .padding(.top, 12)
            .padding(.bottom, 40)
        }
        .background(Color(red: 0.05, green: 0.06, blue: 0.10).ignoresSafeArea())
        .navigationTitle("注入库清单")
        .navigationBarTitleDisplayMode(.inline)
        .onAppear(perform: reload)
        .toolbar {
            ToolbarItem(placement: .topBarTrailing) {
                Button {
                    reload()
                } label: {
                    Image(systemName: "arrow.clockwise")
                }
            }
        }
    }

    private var summaryCard: some View {
        HStack(spacing: 0) {
            statCell(value: "\(images.count)", label: "映像总数", color: .white.opacity(0.85))
            divider
            statCell(value: "\(injectedCount)", label: "越狱注入",
                     color: injectedCount > 0 ? Color(red: 1.0, green: 0.45, blue: 0.42) : .green)
            divider
            statCell(value: "\(groups.count)", label: "分类", color: .white.opacity(0.6))
        }
        .padding(.vertical, 14)
        .background(
            RoundedRectangle(cornerRadius: 14, style: .continuous)
                .fill(Color.white.opacity(0.05))
        )
    }

    private var divider: some View {
        Rectangle().fill(Color.white.opacity(0.08)).frame(width: 1, height: 26)
    }

    private func statCell(value: String, label: String, color: Color) -> some View {
        VStack(spacing: 3) {
            Text(value)
                .font(.system(size: 20, weight: .bold, design: .rounded))
                .foregroundStyle(color)
            Text(label)
                .font(.system(size: 11, weight: .medium, design: .rounded))
                .foregroundStyle(.white.opacity(0.4))
        }
        .frame(maxWidth: .infinity)
    }

    private func sectionView(category: ImageCategory, items: [LoadedImage]) -> some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack(spacing: 6) {
                Text(category.icon)
                    .font(.system(size: 12))
                Text("\(category.rawValue) · \(items.count)")
                    .font(.system(size: 12.5, weight: .semibold, design: .rounded))
                    .foregroundStyle(.white.opacity(0.55))
                Spacer()
            }
            .padding(.horizontal, 4)

            ForEach(items) { item in
                row(item)
            }
        }
    }

    private func row(_ item: LoadedImage) -> some View {
        HStack(alignment: .top, spacing: 9) {
            Circle()
                .fill(item.isSuspicious
                      ? Color(red: 1.0, green: 0.45, blue: 0.42)
                      : Color.white.opacity(0.15))
                .frame(width: 6, height: 6)
                .padding(.top, 6)

            VStack(alignment: .leading, spacing: 3) {
                Text(item.name)
                    .font(.system(size: 13, weight: .medium, design: .rounded))
                    .foregroundStyle(item.isSuspicious
                                     ? Color(red: 1.0, green: 0.62, blue: 0.58)
                                     : .white.opacity(0.86))
                    .lineLimit(1)

                Text(item.path)
                    .font(.system(size: 10.5, design: .monospaced))
                    .foregroundStyle(.white.opacity(0.32))
                    .lineLimit(2)
            }

            Spacer(minLength: 4)

            Text(item.sizeText)
                .font(.system(size: 10.5, design: .rounded))
                .foregroundStyle(.white.opacity(0.28))
        }
        .padding(.horizontal, 12)
        .padding(.vertical, 9)
        .background(
            RoundedRectangle(cornerRadius: 11, style: .continuous)
                .fill(Color.white.opacity(item.isSuspicious ? 0.075 : 0.035))
                .overlay(
                    RoundedRectangle(cornerRadius: 11, style: .continuous)
                        .stroke(item.isSuspicious
                                ? Color(red: 1.0, green: 0.45, blue: 0.42).opacity(0.28)
                                : Color.white.opacity(0.05),
                                lineWidth: 1)
                )
        )
    }

    private func reload() {
        loading = true
        DispatchQueue.global(qos: .userInitiated).async {
            let list = DylibScanner.scan()
            DispatchQueue.main.async {
                images = list
                loading = false
            }
        }
    }
}
