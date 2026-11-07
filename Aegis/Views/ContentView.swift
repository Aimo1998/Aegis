//
//  ContentView.swift
//  Aegis
//
//  主界面：左上角汉堡菜单切换四个模式
//

import SwiftUI

/// 主模式
enum AppMode: String, CaseIterable, Identifiable {
    case detect = "检测"
    case dylibs = "注入库"
    case history = "历史"
    case redteam = "红队自测"

    var id: String { rawValue }

    var icon: String {
        switch self {
        case .detect:  return "shield.lefthalf.filled"
        case .dylibs:  return "square.stack.3d.up"
        case .history: return "clock.arrow.circlepath"
        case .redteam: return "flask"
        }
    }

    var subtitle: String {
        switch self {
        case .detect:  return "越狱环境检测"
        case .dylibs:  return "已加载动态库清单"
        case .history: return "扫描记录与变化对比"
        case .redteam: return "验证检测器灵敏度"
        }
    }
}

struct ContentView: View {

    @StateObject private var engine = ScanEngine()
    @State private var selectedLevel: DetectionLevel = .a
    @State private var mode: AppMode = .detect
    @State private var showMenu = false

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
                }
            }
        }
        .sheet(isPresented: $showMenu) {
            menuSheet
                .presentationDetents([.medium])
                .presentationDragIndicator(.visible)
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
                Text(mode.rawValue)
                    .font(.system(size: 16, weight: .semibold, design: .rounded))
                    .foregroundStyle(.white)
                Text(mode.subtitle)
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

            VStack(spacing: 10) {
                HStack {
                    Text("模式")
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
                                Text(m.rawValue)
                                    .font(.system(size: 15, weight: .semibold, design: .rounded))
                                    .foregroundStyle(.white)
                                Text(m.subtitle)
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

                Spacer(minLength: 8)
            }
        }
    }

    // MARK: 检测模式

    @ViewBuilder
    private var detectRoot: some View {
        if engine.isScanning {
            scanningView
        } else if let report = engine.report {
            ResultView(report: report) {
                engine.reset()
            }
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

            Text("越狱环境检测")
                .font(.system(size: 13, weight: .medium, design: .rounded))
                .foregroundStyle(.white.opacity(0.5))
                .kerning(2.2)
        }
        .padding(.bottom, 2)
    }

    private var levelPicker: some View {
        VStack(spacing: 10) {
            ForEach(DetectionLevel.allCases) { level in
                LevelCard(level: level, selected: selectedLevel == level) {
                    selectedLevel = level
                }
            }
        }
    }

    private var startButton: some View {
        Button {
            engine.scan(level: selectedLevel)
        } label: {
            HStack(spacing: 10) {
                Image(systemName: "waveform.path.ecg")
                    .font(.system(size: 16, weight: .semibold))
                Text("开始检测")
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
        Text("检测全程本地执行，不联网、不上传任何数据")
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
                Text("正在检测")
                    .font(.system(size: 19, weight: .semibold, design: .rounded))
                    .foregroundStyle(.white)
                Text(engine.currentCheck.isEmpty ? "准备中…" : engine.currentCheck)
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
                    Text("\(level.subtitle) · \(level.checks.count) 项")
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
