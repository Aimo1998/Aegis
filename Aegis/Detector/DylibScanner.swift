//
//  DylibScanner.swift
//  Aegis
//
//  扫描当前进程已加载的全部动态库，按来源分类
//

import Foundation
import Darwin

/// 一个已加载的映像
struct LoadedImage: Identifiable {
    let id = UUID()
    let path: String
    let name: String
    let sizeText: String
    let category: ImageCategory

    var isSuspicious: Bool {
        category == .jailbreakInjected
    }
}

enum ImageCategory: String, CaseIterable {
    case app = "本 App"
    case jailbreakInjected = "越狱注入"
    case systemFramework = "系统框架"
    case systemLib = "系统库"
    case dyldCache = "dyld 共享缓存"
    case other = "其他"

    var icon: String {
        switch self {
        case .app: return "🟦"
        case .jailbreakInjected: return "🔴"
        case .systemFramework: return "🟩"
        case .systemLib: return "🟢"
        case .dyldCache: return "⚪️"
        case .other: return "🟡"
        }
    }
}

enum DylibScanner {

    /// 越狱相关路径特征
    private static let jailbreakMarkers = [
        "/var/jb", "/.jbroot", "/private/preboot", "substrate",
        "ellekit", "libhooker", "substitute", "tweak", "orion"
    ]

    static func scan() -> [LoadedImage] {
        let raw = aegis_dyld_image_count()
        guard raw > 0 else { return [] }
        let count = Int(raw)

        var list: [LoadedImage] = []
        let fm = FileManager.default

        for i in 0..<count {
            guard let cname = aegis_dyld_image_name(Int32(i)) else { continue }
            let path = String(cString: cname)
            guard !path.isEmpty else { continue }

            let name = (path as NSString).lastPathComponent

            // 文件大小
            var sizeText = "—"
            if let attrs = try? fm.attributesOfItem(atPath: path),
               let size = attrs[.size] as? NSNumber {
                sizeText = ByteCountFormatter.string(
                    fromByteCount: size.int64Value, countStyle: .file)
            }

            list.append(LoadedImage(
                path: path,
                name: name,
                sizeText: sizeText,
                category: categorize(path)
            ))
        }
        return list
    }

    private static func categorize(_ path: String) -> ImageCategory {
        let lower = path.lowercased()

        if lower.contains("/aegis.app/") { return .app }

        for m in jailbreakMarkers where lower.contains(m) {
            return .jailbreakInjected
        }

        if lower.hasPrefix("/system/library/frameworks/") { return .systemFramework }
        if lower.hasPrefix("/usr/lib/") { return .systemLib }
        if lower.contains("/system/") { return .systemLib }
        if lower.hasPrefix("/private/preboot") { return .systemLib }

        // dyld 共享缓存里的库通常没有真实文件
        if !FileManager.default.fileExists(atPath: path) { return .dyldCache }

        return .other
    }

    /// 按分类分组，越狱注入排最前
    static func grouped(_ images: [LoadedImage]) -> [(ImageCategory, [LoadedImage])] {
        let order: [ImageCategory] = [
            .jailbreakInjected, .app, .other, .systemFramework, .systemLib, .dyldCache
        ]
        return order.compactMap { cat in
            let items = images.filter { $0.category == cat }
            return items.isEmpty ? nil : (cat, items)
        }
    }
}
