//
//  ContentView.swift
//  Aegis
//
//  首屏：选择检测等级 → 扫描 → 结果页
//

import SwiftUI

struct ContentView: View {

    @StateObject private var engine = ScanEngine()
    @State private var selectedLevel: DetectionLevel = .a
    @State private var showResult: Bool = false

    var body: some View {
        ZStack {
            background

            if engine.isScanning {
                scanningView
            } else if let report = engine.report {
                ResultView(report: report) {
                    engine.reset()
                }
                .transition(.opacity.combined(with: .scale(scale: 0.96)))
            } else {
                homeView
            }
        }
        .animation(.easeInOut(duration: 0.28), value: engine.isScanning)
        .animation(.easeInOut(duration: 0.28), value: engine.report == nil)
    }

    // MARK: 背景

    private var background: some View {
        LinearGradient(
            colors: [
                Color(red: 0.05, green: 0.06, blue: 0.10),
                Color(red: 0.09, green: 0.10, blue: 0.17),
                Color(red: 0.04, green: 0.05, blue: 0.08)
            ],
            startPoint: .topLeading,
            endPoint: .bottomTrailing
        )
        .ignoresSafeArea()
    }

    // MARK: 首屏

    private var homeView: some View {
        ScrollView {
            VStack(spacing: 26) {
                header
                levelPicker
                startButton
                footerNote
            }
            .padding(.horizontal, 22)
            .padding(.top, 46)
            .padding(.bottom, 40)
        }
    }

    private var header: some View {
        VStack(spacing: 14) {
            ZStack {
                Circle()
                    .fill(
                        RadialGradient(
                            colors: [
                                Color(red: 0.35, green: 0.62, blue: 1.0).opacity(0.35),
                                Color.clear
                            ],
                            center: .center,
                            startRadius: 6,
                            endRadius: 74
                        )
                    )
                    .frame(width: 148, height: 148)

                Image(systemName: "shield.lefthalf.filled")
                    .font(.system(size: 62, weight: .semibold))
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
                .font(.system(size: 38, weight: .bold, design: .rounded))
                .foregroundStyle(.white)

            Text("越狱环境检测")
                .font(.system(size: 15, weight: .medium, design: .rounded))
                .foregroundStyle(.white.opacity(0.55))
                .kerning(2.5)
        }
        .padding(.bottom, 6)
    }

    private var levelPicker: some View {
        VStack(spacing: 12) {
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
                    .font(.system(size: 17, weight: .semibold))
                Text("开始检测")
                    .font(.system(size: 18, weight: .semibold, design: .rounded))
            }
            .foregroundStyle(.black)
            .frame(maxWidth: .infinity)
            .padding(.vertical, 17)
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
            .clipShape(RoundedRectangle(cornerRadius: 17, style: .continuous))
            .shadow(color: Color(red: 0.36, green: 0.62, blue: 1.0).opacity(0.35),
                    radius: 16, x: 0, y: 8)
        }
        .buttonStyle(.plain)
        .padding(.top, 4)
    }

    private var footerNote: some View {
        Text("检测全程本地执行，不联网、不上传任何数据")
            .font(.system(size: 12, weight: .regular, design: .rounded))
            .foregroundStyle(.white.opacity(0.32))
            .multilineTextAlignment(.center)
            .padding(.top, 2)
    }

    // MARK: 扫描中

    private var scanningView: some View {
        VStack(spacing: 26) {
            Spacer()

            ZStack {
                Circle()
                    .stroke(Color.white.opacity(0.08), lineWidth: 10)
                    .frame(width: 150, height: 150)

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
                    .frame(width: 150, height: 150)
                    .rotationEffect(.degrees(-90))
                    .animation(.easeInOut(duration: 0.25), value: engine.progress)

                Text("\(Int(engine.progress * 100))%")
                    .font(.system(size: 30, weight: .bold, design: .rounded))
                    .foregroundStyle(.white)
            }

            VStack(spacing: 8) {
                Text("正在检测")
                    .font(.system(size: 20, weight: .semibold, design: .rounded))
                    .foregroundStyle(.white)

                Text(engine.currentCheck.isEmpty ? "准备中…" : engine.currentCheck)
                    .font(.system(size: 14, weight: .regular, design: .rounded))
                    .foregroundStyle(.white.opacity(0.5))
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
            HStack(spacing: 14) {
                Text(level.badge)
                    .font(.system(size: 25))

                VStack(alignment: .leading, spacing: 3) {
                    Text(level.title)
                        .font(.system(size: 16, weight: .semibold, design: .rounded))
                        .foregroundStyle(.white)

                    Text("\(level.subtitle) · \(level.checks.count) 项")
                        .font(.system(size: 12.5, weight: .regular, design: .rounded))
                        .foregroundStyle(.white.opacity(0.45))
                }

                Spacer()

                Image(systemName: selected ? "checkmark.circle.fill" : "circle")
                    .font(.system(size: 21))
                    .foregroundStyle(selected
                                     ? Color(red: 0.42, green: 0.70, blue: 1.0)
                                     : Color.white.opacity(0.18))
            }
            .padding(.horizontal, 17)
            .padding(.vertical, 15)
            .background(
                RoundedRectangle(cornerRadius: 16, style: .continuous)
                    .fill(Color.white.opacity(selected ? 0.085 : 0.04))
                    .overlay(
                        RoundedRectangle(cornerRadius: 16, style: .continuous)
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

#Preview {
    ContentView()
        .preferredColorScheme(.dark)
}
