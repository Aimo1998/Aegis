//
//  ScanEngine.swift
//  Aegis
//
//  扫描调度器：按等级顺序执行检测项，汇总结果。
//

import Foundation
import SwiftUI

final class ScanEngine: ObservableObject {

    @Published var isScanning: Bool = false
    @Published var progress: Double = 0
    @Published var currentCheck: String = ""
    @Published var report: ScanReport?

    /// 每次扫描递增，用于让被 reset 掉的扫描自行退出
    private var token: Int = 0

    /// 开始扫描指定等级
    func scan(level: DetectionLevel, cascade: Bool = false) {
        guard !isScanning else { return }

        token += 1
        let myToken = token

        isScanning = true
        progress = 0
        report = nil
        currentCheck = ""

        // Admin 模式下可单独禁用某些检测项
        let allChecks = level.checks(cascade: cascade)
        let checks = AdminStore.shared.enabled
            ? allChecks.filter { AdminStore.shared.isEnabled($0.id) }
            : allChecks

        // 必须在后台线程跑：
        //  - canOpenURL 内部要回主线程，如果在主线程调用会死锁
        //  - 文件/内存遍历也不该阻塞 UI
        DispatchQueue.global(qos: .userInitiated).async { [weak self] in
            guard let self = self else { return }

            let startedAt = Date()
            var results: [CheckResult] = []

            for (index, detector) in checks.enumerated() {
                // 已被 reset，放弃后续检测
                if self.token != myToken { return }

                DispatchQueue.main.async {
                    self.currentCheck = detector.name
                }

                let evidence = detector.run()

                let result = CheckResult(
                    id: detector.id,
                    level: detector.level,
                    name: detector.name,
                    detail: detector.detail,
                    triggered: evidence != nil,
                    evidence: evidence
                )
                results.append(result)

                let p = Double(index + 1) / Double(max(checks.count, 1))
                DispatchQueue.main.async {
                    self.progress = p
                }
            }

            let duration = Date().timeIntervalSince(startedAt)
            let finalReport = ScanReport(
                level: level,
                results: results,
                startedAt: startedAt,
                duration: duration
            )

            DispatchQueue.main.async {
                guard self.token == myToken else { return }
                self.report = finalReport
                self.isScanning = false
                self.progress = 1
                self.currentCheck = ""
                // 写入历史，供「历史记录」页做变化对比
                HistoryStore.shared.add(finalReport)
            }
        }
    }

    func reset() {
        token += 1          // 使进行中的扫描失效
        report = nil
        progress = 0
        currentCheck = ""
        isScanning = false
    }
    /// 全部检测项索引（单项重测用）
    private var allDetectors: [Detector] {
        LevelC.all + LevelB.all + LevelA.all
    }

    /// 单项重测：只重跑指定 ID 的检测，原地更新报告
    func rerun(id: String, onUpdate: (() -> Void)? = nil) {
        guard let old = report else { return }
        guard let detector = allDetectors.first(where: { $0.id == id }) else { return }
        guard let idx = old.results.firstIndex(where: { $0.id == id }) else { return }

        DispatchQueue.global(qos: .userInitiated).async { [weak self] in
            let evidence = detector.run()

            DispatchQueue.main.async {
                guard let self = self, let cur = self.report else { return }
                guard let i = cur.results.firstIndex(where: { $0.id == id }) else { return }

                var results = cur.results
                results[i] = CheckResult(
                    id: detector.id,
                    level: detector.level,
                    name: detector.name,
                    detail: detector.detail,
                    triggered: (evidence != nil),
                    evidence: evidence
                )

                let updated = ScanReport(
                    level: cur.level,
                    results: results,
                    startedAt: cur.startedAt,
                    duration: cur.duration
                )
                self.report = updated
                onUpdate?()
            }
        }
    }

}
