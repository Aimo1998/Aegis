//
//  RedTeamView.swift
//  Aegis
//
//  红队自测：主动篡改自己，验证检测器灵敏度
//

import SwiftUI

struct RedTeamView: View {

    @ObservedObject private var l10n = L10n.shared

    @State private var tamperResult: RedTeam.TestResult?
    @State private var dylibResult: RedTeam.TestResult?
    @State private var running = false

    private let bg = Color(red: 0.05, green: 0.06, blue: 0.10)

    var body: some View {
        ScrollView {
            VStack(spacing: 16) {
                introCard

                testCard(
                    icon: "🩹",
                    title: l10n.t("自我篡改测试", "Self-tamper test"),
                    subtitle: "临时把 UIView.layoutSubviews 的 IMP 换成动态 block，跑 B3 看能否捕获，测完立即还原",
                    result: tamperResult
                )

                testCard(
                    icon: "📚",
                    title: l10n.t("注入库可见性", "Image visibility"),
                    subtitle: "统计当前进程能枚举出多少 dylib，以及其中来自越狱路径的有几个",
                    result: dylibResult
                )

                runButton

                if let r = tamperResult, !r.detected {
                    warningCard
                }

                MadeByFooter()
            }
            .padding(.horizontal, 16)
            .padding(.top, 12)
            .padding(.bottom, 40)
        }
        .background(bg.ignoresSafeArea())
    }

    // MARK: 说明

    private var introCard: some View {
        VStack(alignment: .leading, spacing: 7) {
            Text(l10n.t("红队自测", "Red Team"))
                .font(.system(size: 15, weight: .bold, design: .rounded))
                .foregroundStyle(.white)

            Text(l10n.t("这些测试会主动篡改当前进程，用来验证检测器本身是否有效。所有改动在测试结束后立即还原，不会影响 App 正常运行。",
                  "These tests tamper with the current process to validate the detectors themselves. Everything is restored immediately after."))
                .font(.system(size: 12, design: .rounded))
                .foregroundStyle(.white.opacity(0.45))
                .fixedSize(horizontal: false, vertical: true)
        }
        .padding(14)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(
            RoundedRectangle(cornerRadius: 13, style: .continuous)
                .fill(Color.white.opacity(0.045))
        )
    }

    // MARK: 测试卡片

    private func testCard(icon: String, title: String, subtitle: String,
                          result: RedTeam.TestResult?) -> some View {
        VStack(alignment: .leading, spacing: 9) {
            HStack(spacing: 8) {
                Text(icon).font(.system(size: 17))
                Text(title)
                    .font(.system(size: 14, weight: .semibold, design: .rounded))
                    .foregroundStyle(.white)
                Spacer()
                if let r = result {
                    Text(r.detected ? "已捕获" : "未捕获")
                        .font(.system(size: 11, weight: .semibold, design: .rounded))
                        .foregroundStyle(r.detected ? .green : Color(red: 1.0, green: 0.6, blue: 0.4))
                        .padding(.horizontal, 8)
                        .padding(.vertical, 3)
                        .background(
                            Capsule().fill(
                                (r.detected ? Color.green : Color.orange).opacity(0.15))
                        )
                }
            }

            Text(subtitle)
                .font(.system(size: 11.5, design: .rounded))
                .foregroundStyle(.white.opacity(0.38))
                .fixedSize(horizontal: false, vertical: true)

            if let r = result {
                VStack(alignment: .leading, spacing: 4) {
                    Text(r.detail)
                        .font(.system(size: 11.5, design: .monospaced))
                        .foregroundStyle(r.detected
                                         ? Color(red: 0.4, green: 0.9, blue: 0.6)
                                         : Color(red: 1.0, green: 0.65, blue: 0.45))
                        .fixedSize(horizontal: false, vertical: true)

                    Text(String(format: "耗时 %.3fs", r.duration))
                        .font(.system(size: 10.5, design: .rounded))
                        .foregroundStyle(.white.opacity(0.28))
                }
                .padding(.top, 3)
            }
        }
        .padding(14)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(
            RoundedRectangle(cornerRadius: 13, style: .continuous)
                .fill(Color.white.opacity(0.04))
                .overlay(
                    RoundedRectangle(cornerRadius: 13, style: .continuous)
                        .stroke(Color.white.opacity(0.06), lineWidth: 1)
                )
        )
    }

    // MARK: 按钮

    private var runButton: some View {
        Button {
            runTests()
        } label: {
            HStack(spacing: 9) {
                if running {
                    ProgressView()
                        .tint(.black)
                        .scaleEffect(0.85)
                } else {
                    Image(systemName: "bolt.fill")
                        .font(.system(size: 14, weight: .semibold))
                }
                Text(running ? l10n.t("测试中…", "Running…") : l10n.t("开始自测", "Run tests"))
                    .font(.system(size: 15.5, weight: .semibold, design: .rounded))
            }
            .foregroundStyle(.black)
            .frame(maxWidth: .infinity)
            .padding(.vertical, 15)
            .background(
                RoundedRectangle(cornerRadius: 15, style: .continuous)
                    .fill(
                        LinearGradient(
                            colors: [
                                Color(red: 0.55, green: 0.82, blue: 1.0),
                                Color(red: 0.36, green: 0.62, blue: 1.0)
                            ],
                            startPoint: .topLeading,
                            endPoint: .bottomTrailing
                        )
                    )
            )
        }
        .buttonStyle(.plain)
        .disabled(running)
        .opacity(running ? 0.6 : 1)
    }

    private var warningCard: some View {
        HStack(alignment: .top, spacing: 8) {
            Text("⚠️").font(.system(size: 14))
            Text(l10n.t("B3 未能捕获自我篡改，说明 IMP 归属校验存在盲点。建议提高该等级的权重或补充检测手段。",
                          "B3 missed the self-tamper. The IMP provenance check has a blind spot."))
                .font(.system(size: 11.5, design: .rounded))
                .foregroundStyle(Color(red: 1.0, green: 0.72, blue: 0.45))
                .fixedSize(horizontal: false, vertical: true)
        }
        .padding(13)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(
            RoundedRectangle(cornerRadius: 12, style: .continuous)
                .fill(Color.orange.opacity(0.09))
        )
    }

    // MARK: 执行

    private func runTests() {
        running = true
        tamperResult = nil
        dylibResult = nil

        // 自我篡改要替换 UIView.layoutSubviews 的实现，必须在主线程执行，
        // 否则可能与正在绘制的 UIKit 产生竞态
        DispatchQueue.main.async {
            tamperResult = RedTeam.selfTamperTest()
        }

        // 注入库枚举是纯 IO（每个映像 stat 一次），放后台避免卡界面
        DispatchQueue.global(qos: .userInitiated).async {
            let d = RedTeam.dylibVisibilityTest()
            DispatchQueue.main.async {
                dylibResult = d
                running = false
            }
        }
    }
}
