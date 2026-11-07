//
//  SharedFooter.swift
//  Aegis
//
//  全局署名页脚
//

import SwiftUI

/// 每个页面底部的署名
/// 字号与颜色和免责声明保持一致
struct MadeByFooter: View {
    var body: some View {
        Text("made in @Aimo1998")
            .font(.system(size: 11.5, weight: .regular, design: .rounded))
            .foregroundStyle(.white.opacity(0.28))
            .frame(maxWidth: .infinity)
            .multilineTextAlignment(.center)
            .padding(.top, 16)
            .padding(.bottom, 4)
    }
}
