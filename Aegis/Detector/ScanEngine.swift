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

    /// 开始扫描指定等级
    func scan(level: DetectionLevel) {
        guard !isScanning else { return }

        isScanning = true
        progress = 0
        report = nil
        currentCheck = ""

        let checks = level.checks

        // 必须在后台线程跑：
        //  - canOpenURL 内部要回主线程，如果在主线程调用会死锁
        //  - 文件/内存遍历也不该阻塞 UI
        DispatchQueue.global(qos: .userInitiated).async { [weak self] in
            guard let self = self else { return }

            let startedAt = Date()
            var results: [CheckResult] = []

            for (index, detector) in checks.enumerated() {
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
                self.report = finalReport
                self.isScanning = false
                self.progress = 1
                self.currentCheck = ""
            }
        }
    }

    func reset() {
        report = nil
        progress = 0
        currentCheck = ""
        isScanning = false
    }
}
