//
//  ShareSheet.swift
//  Aegis
//
//  系统分享面板 + 剪贴板便捷操作
//

import SwiftUI
import UIKit

struct ShareSheet: UIViewControllerRepresentable {
    let text: String

    func makeUIViewController(context: Context) -> UIActivityViewController {
        let vc = UIActivityViewController(activityItems: [text], applicationActivities: nil)
        vc.completionWithItemsHandler = { _, _, _, _ in }
        return vc
    }

    func updateUIViewController(_ uiViewController: UIActivityViewController, context: Context) {}
}

/// 轻提示
struct ToastView: View {
    let text: String

    var body: some View {
        Text(text)
            .font(.system(size: 13, weight: .medium, design: .rounded))
            .foregroundStyle(.white)
            .padding(.horizontal, 16)
            .padding(.vertical, 10)
            .background(
                Capsule().fill(Color.white.opacity(0.14))
            )
            .transition(.opacity.combined(with: .scale(scale: 0.9)))
    }
}
