//
//  RedTeam.swift
//  Aegis
//
//  红队自测：主动篡改自己的方法实现，验证检测器能不能抓到
//

import Foundation
import UIKit
import ObjectiveC
import Darwin

enum RedTeam {

    struct TestResult {
        let detected: Bool
        let detail: String
        let duration: TimeInterval
    }

    /// 自我篡改测试：
    /// 把 UIView.layoutSubviews 的 IMP 临时替换成一个动态生成的 block，
    /// 然后跑 B3（UI 篡改检测），看它能不能发现 IMP 已经不在任何映像里。
    /// 测完立刻恢复原实现。
    static func selfTamperTest() -> TestResult {
        let start = Date()

        let sel = NSSelectorFromString("layoutSubviews")
        guard let method = class_getInstanceMethod(UIView.self, sel) else {
            return TestResult(detected: false, detail: "未找到 UIView.layoutSubviews", duration: 0)
        }

        let originalIMP = method_getImplementation(method)
        let block: @convention(block) (AnyObject) -> Void = { _ in }
        let fakeIMP = imp_implementationWithBlock(block)

        // 替换
        method_setImplementation(method, fakeIMP)

        // 跑检测
        let evidence = LevelB.uiTamperCheck.run()

        // 立刻恢复（无论检测结果如何）
        method_setImplementation(method, originalIMP)

        let duration = Date().timeIntervalSince(start)

        if let e = evidence {
            return TestResult(detected: true,
                              detail: "B3 成功捕获自我篡改：" + e,
                              duration: duration)
        }
        return TestResult(detected: false,
                          detail: "B3 未捕获（IMP 替换后 dladdr 仍返回合法映像，检测存在盲点）",
                          duration: duration)
    }

    /// 注入库可见性测试：
    /// 检查 B2 在当前进程里能枚举出多少个 dylib
    static func dylibVisibilityTest() -> TestResult {
        let start = Date()
        let total = Int(aegis_dyld_image_count())
        let images = DylibScanner.scan()
        let injected = images.filter { $0.category == .jailbreakInjected }
        let duration = Date().timeIntervalSince(start)

        let detail = "共枚举 \(total) 个映像，其中越狱路径注入 \(injected.count) 个"
        return TestResult(detected: !injected.isEmpty, detail: detail, duration: duration)
    }
}
