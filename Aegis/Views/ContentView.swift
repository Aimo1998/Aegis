//
//  ContentView.swift
//  Aegis
//
//  主界面：左上角汉堡菜单切换四个模式
//

import SwiftUI
import UIKit

/// 主模式
enum AppMode: String, CaseIterable, Identifiable {
    case detect = "检测"
    case dylibs = "注入库"
    case history = "历史"
    case redteam = "红队自测"
    case sysinfo = "系统信息"
    case compare = "对比"

    var id: String { rawValue }

    var icon: String {
        switch self {
        case .detect:  return "shield.lefthalf.filled"
        case .dylibs:  return "square.stack.3d.up"
        case .history: return "clock.arrow.circlepath"
        case .redteam: return "testtube.2"
        case .sysinfo: return "info.circle"
        case .compare: return "rectangle.split.2x1"
        }
    }

    var subtitle: String { subtitleLocalized }

    // MARK: 本地化

    var title: String {
        switch self {
        case .detect:  return L10n.shared.t("检测", "Detect")
        case .dylibs:  return L10n.shared.t("注入库", "Images")
        case .history: return L10n.shared.t("历史", "History")
        case .redteam: return L10n.shared.t("红队自测", "Red Team")
        case .sysinfo: return L10n.shared.t("系统信息", "System Info")
        case .compare: return L10n.shared.t("对比", "Compare")
        }
    }

    var subtitleLocalized: String {
        switch self {
        case .detect:  return L10n.shared.t("越狱环境检测", "Jailbreak detection")
        case .dylibs:  return L10n.shared.t("已加载动态库清单", "Loaded dylib list")
        case .history: return L10n.shared.t("扫描记录与变化对比", "History & diff")
        case .redteam: return L10n.shared.t("验证检测器灵敏度", "Validate detectors")
        case .sysinfo: return L10n.shared.t("底层返回值诊断", "Raw value diagnostics")
        case .compare: return L10n.shared.t("两台设备报告对比", "Compare two reports")
        }
    }
}

struct ContentView: View {

    @StateObject private var engine = ScanEngine()
    @ObservedObject private var l10n = L10n.shared
    @ObservedObject private var adminStore = AdminStore.shared
    @State private var selectedLevel: DetectionLevel = .a
    @State private var mode: AppMode = .detect
    @State private var showMenu = false
    @State private var showAdmin = false
    @State private var cascade = false

    private let bgTop = Color(red: 0.05, green: 0.06, blue: 0.10)
    private let bgMid = Color(red: 0.09, green: 0.10, blue: 0.17)
    private let bgBot = Color(red: 0.04, green: 0.05, blue: 0.08)

    var body: some View {
        ZStack {
            LinearGradient(colors: [bgTop, bgMid, bgBot],
                           startPoint: .topLeading,
                           endPoint: .bottomTrailing)
                .ignoresSafeArea()

            VStack(spacing: 0) {
                topBar
                Divider().overlay(Color.white.opacity(0.06))

                switch mode {
                case .detect:  detectRoot
                case .dylibs:  DylibListView()
                case .history: HistoryView()
                case .redteam: RedTeamView()
                case .sysinfo: SystemInfoView()
                case .compare: CompareView()
                }
            }
        }
        .sheet(isPresented: $showMenu) {
            menuSheet
                .presentationDetents([.medium])
                .presentationDragIndicator(.visible)
        }
        .sheet(isPresented: $showAdmin) {
            NavigationStack {
                AdminPanel()
                    .toolbar {
                        ToolbarItem(placement: .topBarTrailing) {
                            Button(L10n.shared.t("完成", "Done")) { showAdmin = false }
                        }
                    }
            }
        }
        .animation(.easeInOut(duration: 0.22), value: engine.isScanning)
        .animation(.easeInOut(duration: 0.22), value: engine.report == nil)
    }

    // MARK: 顶栏

    private var topBar: some View {
        HStack(spacing: 12) {
            Button {
                showMenu = true
            } label: {
                Image(systemName: "line.3.horizontal")
                    .font(.system(size: 17, weight: .semibold))
                    .foregroundStyle(.white.opacity(0.85))
                    .frame(width: 38, height: 38)
                    .background(
                        RoundedRectangle(cornerRadius: 10, style: .continuous)
                            .fill(Color.white.opacity(0.06))
                    )
            }
            .buttonStyle(.plain)

            VStack(alignment: .leading, spacing: 1) {
                Text(mode.title)
                    .font(.system(size: 16, weight: .semibold, design: .rounded))
                    .foregroundStyle(.white)
                Text(mode.subtitleLocalized)
                    .font(.system(size: 10.5, design: .rounded))
                    .foregroundStyle(.white.opacity(0.35))
            }

            Spacer()

            if mode == .detect && engine.report != nil && !engine.isScanning {
                Button {
                    engine.reset()
                } label: {
                    Image(systemName: "arrow.counterclockwise")
                        .font(.system(size: 14, weight: .semibold))
                        .foregroundStyle(.white.opacity(0.6))
                        .frame(width: 34, height: 34)
                        .background(
                            RoundedRectangle(cornerRadius: 9, style: .continuous)
                                .fill(Color.white.opacity(0.05))
                        )
                }
                .buttonStyle(.plain)
            }
        }
        .padding(.horizontal, 14)
        .padding(.top, 4)
        .padding(.bottom, 10)
    }

    // MARK: 菜单

    private var menuSheet: some View {
        ZStack {
            Color(red: 0.07, green: 0.08, blue: 0.13).ignoresSafeArea()

            ScrollView {
                VStack(spacing: 10) {
                HStack {
                    Text(L10n.shared.t("模式", "Modes"))
                        .font(.system(size: 17, weight: .bold, design: .rounded))
                        .foregroundStyle(.white)
                    Spacer()
                }
                .padding(.horizontal, 20)
                .padding(.top, 18)
                .padding(.bottom, 4)

                ForEach(AppMode.allCases) { m in
                    Button {
                        mode = m
                        showMenu = false
                    } label: {
                        HStack(spacing: 13) {
                            Image(systemName: m.icon)
                                .font(.system(size: 16, weight: .medium))
                                .foregroundStyle(mode == m
                                                 ? Color(red: 0.45, green: 0.72, blue: 1.0)
                                                 : .white.opacity(0.55))
                                .frame(width: 26)

                            VStack(alignment: .leading, spacing: 2) {
                                Text(m.title)
                                    .font(.system(size: 15, weight: .semibold, design: .rounded))
                                    .foregroundStyle(.white)
                                Text(m.subtitleLocalized)
                                    .font(.system(size: 11, design: .rounded))
                                    .foregroundStyle(.white.opacity(0.35))
                            }

                            Spacer()

                            if mode == m {
                                Image(systemName: "checkmark.circle.fill")
                                    .font(.system(size: 17))
                                    .foregroundStyle(Color(red: 0.45, green: 0.72, blue: 1.0))
                            }
                        }
                        .padding(.horizontal, 16)
                        .padding(.vertical, 12)
                        .background(
                            RoundedRectangle(cornerRadius: 13, style: .continuous)
                                .fill(Color.white.opacity(mode == m ? 0.08 : 0.035))
                                .overlay(
                                    RoundedRectangle(cornerRadius: 13, style: .continuous)
                                        .stroke(mode == m
                                                ? Color(red: 0.45, green: 0.72, blue: 1.0).opacity(0.4)
                                                : Color.white.opacity(0.04),
                                                lineWidth: 1)
                                )
                        )
                    }
                    .buttonStyle(.plain)
                    .padding(.horizontal, 16)
                }

                if AdminStore.shared.enabled {
                    adminRow
                }
                langRow
                githubRow

                Spacer(minLength: 8)
                }
            }
        }
    }

    // MARK: 管理入口

    private var adminRow: some View {
        Button {
            showMenu = false
            showAdmin = true
        } label: {
            HStack(spacing: 13) {
                Image(systemName: "lock.open.fill")
                    .font(.system(size: 16, weight: .medium))
                    .foregroundStyle(Color(red: 0.45, green: 0.9, blue: 0.6))
                    .frame(width: 26)

                VStack(alignment: .leading, spacing: 2) {
                    Text(L10n.shared.t("管理", "Admin"))
                        .font(.system(size: 15, weight: .semibold, design: .rounded))
                        .foregroundStyle(.white)
                    Text(L10n.shared.t("检测项开关 · 跳过 / 强制通过",
                                           "Per-detector skip / force pass"))
                        .font(.system(size: 11, design: .rounded))
                        .foregroundStyle(.white.opacity(0.35))
                }

                Spacer()

                Text("\(adminStore.skippedCount)/\(adminStore.forcedCount)")
                    .font(.system(size: 10.5, design: .monospaced))
                    .foregroundStyle(.white.opacity(0.3))
            }
            .padding(.horizontal, 16)
            .padding(.vertical, 12)
            .background(
                RoundedRectangle(cornerRadius: 13, style: .continuous)
                    .fill(Color(red: 0.45, green: 0.9, blue: 0.6).opacity(0.08))
                    .overlay(
                        RoundedRectangle(cornerRadius: 13, style: .continuous)
                            .stroke(Color(red: 0.45, green: 0.9, blue: 0.6).opacity(0.3),
                                    lineWidth: 1)
                    )
            )
        }
        .buttonStyle(.plain)
        .padding(.horizontal, 16)
        .padding(.top, 4)
    }

    // MARK: 语言切换

    private var langRow: some View {
        Button {
            let next: L10n.Lang = L10n.shared.lang == .zh ? .en : .zh
            L10n.shared.lang = next
        } label: {
            HStack(spacing: 13) {
                Image(systemName: "globe")
                    .font(.system(size: 16, weight: .medium))
                    .foregroundStyle(.white.opacity(0.55))
                    .frame(width: 26)

                Text(L10n.shared.t("语言", "Language"))
                    .font(.system(size: 15, weight: .semibold, design: .rounded))
                    .foregroundStyle(.white)

                Spacer()

                Text(L10n.shared.lang.title)
                    .font(.system(size: 13, weight: .medium, design: .rounded))
                    .foregroundStyle(Color(red: 0.45, green: 0.72, blue: 1.0))
            }
            .padding(.horizontal, 16)
            .padding(.vertical, 12)
            .background(
                RoundedRectangle(cornerRadius: 13, style: .continuous)
                    .fill(Color.white.opacity(0.035))
                    .overlay(
                        RoundedRectangle(cornerRadius: 13, style: .continuous)
                            .stroke(Color.white.opacity(0.04), lineWidth: 1)
                    )
            )
        }
        .buttonStyle(.plain)
        .padding(.horizontal, 16)
        .padding(.top, 4)
    }

    // MARK: GitHub 跳转

    private var githubRow: some View {
        Button {
            openAuthorGitHub()
        } label: {
            HStack(spacing: 13) {
                Image(systemName: "link")
                    .font(.system(size: 16, weight: .medium))
                    .foregroundStyle(.white.opacity(0.55))
                    .frame(width: 26)

                Text(L10n.shared.t("跳转至作者Github", "Author on GitHub"))
                    .font(.system(size: 15, weight: .semibold, design: .rounded))
                    .foregroundStyle(.white)

                Spacer()

                Image(systemName: "arrow.up.right")
                    .font(.system(size: 11, weight: .semibold))
                    .foregroundStyle(.white.opacity(0.3))
            }
            .padding(.horizontal, 16)
            .padding(.vertical, 12)
            .background(
                RoundedRectangle(cornerRadius: 13, style: .continuous)
                    .fill(Color.white.opacity(0.035))
                    .overlay(
                        RoundedRectangle(cornerRadius: 13, style: .continuous)
                            .stroke(Color.white.opacity(0.04), lineWidth: 1)
                    )
            )
        }
        .buttonStyle(.plain)
        .padding(.horizontal, 16)
        .padding(.top, 4)
    }

    /// 三级跳转：GitHub App 用户页 → GitHub App 首页 → 默认浏览器
    private func openAuthorGitHub() {
        let candidates = [
            "github://Aimo1998",        // 部分版本支持直达用户页
            "github://"                 // 只要 App 在，至少能打开
        ]

        for candidate in candidates {
            guard let url = URL(string: candidate),
                  UIApplication.shared.canOpenURL(url) else { continue }
            UIApplication.shared.open(url, options: [:], completionHandler: nil)
            return
        }

        // 没装 GitHub App，退回默认浏览器
        if let webURL = URL(string: "https://github.com/Aimo1998") {
            UIApplication.shared.open(webURL, options: [:], completionHandler: nil)
        }
    }

    // MARK: 检测模式

    @ViewBuilder
    private var detectRoot: some View {
        if engine.isScanning {
            scanningView
        } else if let report = engine.report {
            ResultView(report: report, onRescan: {
                engine.reset()
            }, engine: engine)
        } else {
            homeView
        }
    }

    private var homeView: some View {
        ScrollView {
            VStack(spacing: 22) {
                header
                levelPicker
                startButton
                footerNote
                MadeByFooter()
            }
            .padding(.horizontal, 20)
            .padding(.top, 24)
            .padding(.bottom, 40)
        }
    }

    private var header: some View {
        VStack(spacing: 10) {
            ZStack {
                Circle()
                    .fill(
                        RadialGradient(
                            colors: [
                                Color(red: 0.35, green: 0.62, blue: 1.0).opacity(0.32),
                                Color.clear
                            ],
                            center: .center,
                            startRadius: 6,
                            endRadius: 66
                        )
                    )
                    .frame(width: 132, height: 132)

                Image(systemName: "shield.lefthalf.filled")
                    .font(.system(size: 54, weight: .semibold))
                    .foregroundStyle(
                        LinearGradient(
                            colors: [
                                Color(red: 0.50, green: 0.76, blue: 1.0),
                                Color(red: 0.33, green: 0.55, blue: 0.98)
                            ],
                            startPoint: .top,
                            endPoint: .bottom
                        )
                    )
            }

            Text("Aegis")
                .font(.system(size: 33, weight: .bold, design: .rounded))
                .foregroundStyle(.white)

            Text(L10n.shared.t("越狱环境检测", "Jailbreak Detection"))
                .font(.system(size: 13, weight: .medium, design: .rounded))
                .foregroundStyle(.white.opacity(0.5))
                .kerning(2.2)
        }
        .padding(.bottom, 2)
    }

    private var levelPicker: some View {
        VStack(spacing: 10) {
            ForEach(DetectionLevel.allCases) { level in
                LevelCard(level: level,
                          selected: selectedLevel == level,
                          count: level.checks(cascade: cascade).count) {
                    selectedLevel = level
                }
            }

            cascadeToggle
        }
    }

    /// 递进检测开关
    private var cascadeToggle: some View {
        VStack(alignment: .leading, spacing: 6) {
            Toggle(isOn: $cascade) {
                HStack(spacing: 7) {
                    Image(systemName: "arrow.down.right.and.arrow.up.left")
                        .font(.system(size: 12, weight: .medium))
                        .foregroundStyle(.white.opacity(0.5))
                    Text(L10n.shared.t("递进检测", "Cascade"))
                        .font(.system(size: 14, weight: .medium, design: .rounded))
                        .foregroundStyle(.white.opacity(0.85))
                }
            }
            .tint(Color(red: 0.42, green: 0.70, blue: 1.0))

            Text(cascade
                 ? L10n.shared.t("已开启：B 级会同时跑 C 级，A 级会跑 C+B+A",
                                 "On: B runs C too, A runs C+B+A")
                 : L10n.shared.t("已关闭：仅运行所选等级自身的检测项",
                                 "Off: only the selected level runs"))
                .font(.system(size: 11, design: .rounded))
                .foregroundStyle(.white.opacity(0.32))
                .padding(.leading, 2)
        }
        .padding(.horizontal, 15)
        .padding(.vertical, 13)
        .background(
            RoundedRectangle(cornerRadius: 15, style: .continuous)
                .fill(Color.white.opacity(0.03))
                .overlay(
                    RoundedRectangle(cornerRadius: 15, style: .continuous)
                        .stroke(Color.white.opacity(0.05), lineWidth: 1)
                )
        )
    }

    private var startButton: some View {
        Button {
            engine.scan(level: selectedLevel, cascade: cascade)
        } label: {
            HStack(spacing: 10) {
                Image(systemName: "waveform.path.ecg")
                    .font(.system(size: 16, weight: .semibold))
                Text(L10n.shared.t("开始检测", "Start Scan"))
                    .font(.system(size: 17, weight: .semibold, design: .rounded))
            }
            .foregroundStyle(.black)
            .frame(maxWidth: .infinity)
            .padding(.vertical, 16)
            .background(
                LinearGradient(
                    colors: [
                        Color(red: 0.55, green: 0.82, blue: 1.0),
                        Color(red: 0.36, green: 0.62, blue: 1.0)
                    ],
                    startPoint: .topLeading,
                    endPoint: .bottomTrailing
                )
            )
            .clipShape(RoundedRectangle(cornerRadius: 16, style: .continuous))
            .shadow(color: Color(red: 0.36, green: 0.62, blue: 1.0).opacity(0.3),
                    radius: 14, x: 0, y: 7)
        }
        .buttonStyle(.plain)
    }

    private var footerNote: some View {
        Text(L10n.shared.t("检测全程本地执行，不联网、不上传任何数据",
                               "Runs fully offline. No network, no upload."))
            .font(.system(size: 11.5, design: .rounded))
            .foregroundStyle(.white.opacity(0.3))
            .multilineTextAlignment(.center)
    }

    private var scanningView: some View {
        VStack(spacing: 24) {
            Spacer()

            ZStack {
                Circle()
                    .stroke(Color.white.opacity(0.08), lineWidth: 10)
                    .frame(width: 140, height: 140)

                Circle()
                    .trim(from: 0, to: CGFloat(engine.progress))
                    .stroke(
                        AngularGradient(
                            colors: [
                                Color(red: 0.50, green: 0.76, blue: 1.0),
                                Color(red: 0.36, green: 0.62, blue: 1.0),
                                Color(red: 0.66, green: 0.52, blue: 1.0)
                            ],
                            center: .center
                        ),
                        style: StrokeStyle(lineWidth: 10, lineCap: .round)
                    )
                    .frame(width: 140, height: 140)
                    .rotationEffect(.degrees(-90))
                    .animation(.easeInOut(duration: 0.25), value: engine.progress)

                Text("\(Int(engine.progress * 100))%")
                    .font(.system(size: 28, weight: .bold, design: .rounded))
                    .foregroundStyle(.white)
            }

            VStack(spacing: 7) {
                Text(L10n.shared.t("正在检测", "Scanning"))
                    .font(.system(size: 19, weight: .semibold, design: .rounded))
                    .foregroundStyle(.white)
                Text(engine.currentCheck.isEmpty ? L10n.shared.t("准备中…", "Preparing…") : engine.currentCheck)
                    .font(.system(size: 13, design: .rounded))
                    .foregroundStyle(.white.opacity(0.45))
                    .animation(.easeInOut(duration: 0.2), value: engine.currentCheck)
            }

            Spacer()
        }
        .padding(30)
    }
}

// MARK: - 等级卡片

struct LevelCard: View {
    let level: DetectionLevel
    let selected: Bool
    let count: Int
    let action: () -> Void

    var body: some View {
        Button(action: action) {
            HStack(spacing: 13) {
                Text(level.badge)
                    .font(.system(size: 22))

                VStack(alignment: .leading, spacing: 2) {
                    Text(level.title)
                        .font(.system(size: 15, weight: .semibold, design: .rounded))
                        .foregroundStyle(.white)
                    Text("\(level.subtitleLocalized) · \(count) " + L10n.shared.t("项", "items"))
                        .font(.system(size: 11.5, design: .rounded))
                        .foregroundStyle(.white.opacity(0.4))
                }

                Spacer()

                Image(systemName: selected ? "checkmark.circle.fill" : "circle")
                    .font(.system(size: 20))
                    .foregroundStyle(selected
                                     ? Color(red: 0.42, green: 0.70, blue: 1.0)
                                     : Color.white.opacity(0.18))
            }
            .padding(.horizontal, 15)
            .padding(.vertical, 13)
            .background(
                RoundedRectangle(cornerRadius: 15, style: .continuous)
                    .fill(Color.white.opacity(selected ? 0.085 : 0.04))
                    .overlay(
                        RoundedRectangle(cornerRadius: 15, style: .continuous)
                            .stroke(selected
                                    ? Color(red: 0.42, green: 0.70, blue: 1.0).opacity(0.55)
                                    : Color.white.opacity(0.06),
                                    lineWidth: selected ? 1.4 : 1)
                    )
            )
        }
        .buttonStyle(.plain)
    }
}
