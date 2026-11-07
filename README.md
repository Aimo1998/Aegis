# Aegis · iOS 越狱环境检测

一个纯本地的越狱检测 App，按 **C → B → A** 三级递进，覆盖从传统有根越狱到 RootHide 级别的高级隐藏。

> 检测全程本地执行，不联网、不上传任何数据。

---

## 一、快速出 ipa（三种方式）

### 方式 1：GitHub Actions（无需 Mac，推荐）

1. 新建一个 GitHub 仓库（Private 也可以）
2. 把本目录所有文件推到仓库根目录
3. 进仓库 → **Actions** → `Build Aegis IPA` → **Run workflow**
4. 约 3~5 分钟后，在该次运行页面底部 **Artifacts** 下载 `Aegis-unsigned-ipa`
5. 解压得到 `Aegis.ipa`

workflow 文件：`.github/workflows/build-ipa.yml`

### 方式 2：本地 macOS

```bash
brew install xcodegen
./build.sh
# 产物：./Aegis.ipa
```

或手动：

```bash
xcodegen generate
open Aegis.xcodeproj     # 用 Xcode 打开，选 Generic iOS Device，Archive
```

### 方式 3：已有 Xcode 时手工建工程

1. Xcode → New Project → App，名字 `Aegis`，Interface 选 **SwiftUI**
2. 把 `Aegis/` 下所有 `.swift`、`.c`、`.h` 拖进工程
3. Build Settings 里设置：
   - `Objective-C Bridging Header` = `Aegis/Aegis-Bridging-Header.h`
   - `Info.plist File` = `Aegis/Info.plist`
   - 链接 `DeviceCheck.framework`

---

## 二、装到设备

ipa 是**未签名**的，用下面任一方式安装：

| 方式 | 说明 |
|---|---|
| **TrollStore** | 把 `Aegis.ipa` 拖进 Filza → 用 TrollStore 打开安装（最省事） |
| **自签工具** | Sideloadly / AltStore / ESign 等，用你自己的 Apple ID 签 |
| **越狱设备 + ldid** | 见下方 |

越狱设备手工安装：

```bash
mkdir -p /var/mobile/aegis && cd /var/mobile/aegis
unzip -o /var/mobile/Documents/Aegis.ipa

cp -R Payload/Aegis.app /var/jb/Applications/
chown -R root:wheel /var/jb/Applications/Aegis.app

ldid -S /var/jb/Applications/Aegis.app/Aegis

uicache -p /var/jb/Applications/Aegis.app
```

---

## 三、检测项清单

### 🛑 C 级 · 基础特征匹配（4 项）

| ID | 检测项 | 实现 |
|---|---|---|
| C1 | 文件系统黑名单 | `lstat` + `FileManager` 检查 50+ 越狱特征路径（Cydia/Sileo/ssh/apt/Substrate/`/var/jb` 等） |
| C2 | URL Scheme 探测 | `canOpenURL` 检查 cydia/sileo/filza/zbra/trollstore 等 9 个协议 |
| C3 | 沙盒逃逸写入 | 尝试向 `/private`、`/var/jb`、`/tmp` 写探针文件，成功即异常 |
| C4 | 子进程创建 | `fork()`，成功创建子进程即异常 |

### 🟡 B 级 · 现代环境与注入（6 项）

| ID | 检测项 | 实现 |
|---|---|---|
| B1 | 动态库注入扫描 | `_dyld_image_count` 遍历，匹配 ElleKit / MobileSubstrate / Substitute / libhooker / Orion / frida 等 16 个特征 |
| B2 | 环境变量审查 | `DYLD_INSERT_LIBRARIES`、`DYLD_FORCE_FLAT_NAMESPACE`、`_MSSafeMode`、`JB_ROOT` 等 9 个变量 |
| B3 | 调试器 / 追踪 | `sysctl KERN_PROC` 读 `kinfo_proc` 检查 `P_TRACED`；`ptrace(PT_DENY_ATTACH)` 返回值校验 |
| B4 | Frida 注入 | 探测 27042/27043/27044 端口 + `dlsym` 查找 `gum_init` 等符号 |
| B5 | RWX 内存段 | `vm_region_64` 遍历，统计 W+X 且不属于任何已加载映像的页 |
| B6 | 无根路径探测 | 原始 `SYS_lstat` 探测 `/var/jb`、`/.jbroot` 等 10 个挂载点 + `getfsstat` 挂载表扫描 |

### 🔴 A 级 · 深度对抗（5 项）

| ID | 检测项 | 实现 |
|---|---|---|
| A1 | API 交叉验证 | 同一路径用 `lstat`(libc) 与 `SYS_lstat`(原始 syscall) 双查，比对返回值 / inode / 文件类型；再用 `FileManager` 做第三重交叉 |
| A2 | 代码签名审查 | `csops(CS_OPS_STATUS)` 读 csflags，检查 `CS_VALID` 是否被注入、`CS_DEBUGGED` 是否被抹、`CS_HARD`/`CS_KILL`/`CS_RESTRICT` 是否被剥离 |
| A3 | 内核状态探测 | `kern.bootargs` 查 `-s`/`amfi_get_out_of_my_way`/`cs_enforcement_disable` 等越狱启动参数；`getfsstat` 查动态 jbroot 挂载 |
| A4 | 防篡改与指针完整性 | 检查 `lstat`/`getfsstat`/`sysctl`/`ptrace`/`csops` 的函数地址是否仍落在合法映像内（检测内联 Hook / PAC 指针伪造），并做 `dladdr` 与 dyld 路径交叉 |
| A5 | App Attest 完整性 | `DCAppAttestService.generateKey`；无 entitlement 时自动跳过（不计通过也不计失败） |

---

## 四、UI 结构

```
首页
├── 盾牌图标 + Aegis 标题
├── 三张等级卡片（C/B/A，可点选）
└── 「开始检测」按钮

扫描中
└── 环形进度 + 当前检测项名称

结果页
├── 大 emoji：😋 未检测到 / 😢 检测到
├── 结论：未检测到越狱环境 / 检测到越狱环境
├── 统计条：通过 N / 未通过 N / 耗时
├── 分组清单（C/B/A）
│   └── ✅xxx检测通过 / ❌xxx检测未通过（点击展开说明与证据）
└── 「重新检测」
```

---

## 五、文件结构

```
Aegis/
├── project.yml                       # XcodeGen 工程定义
├── build.sh                          # 本地一键构建
├── .github/workflows/build-ipa.yml   # CI：自动出 ipa
├── Aegis/
│   ├── AegisApp.swift                # App 入口
│   ├── Info.plist                    # 含 LSApplicationQueriesSchemes
│   ├── AegisShim.h / .c              # 原始 syscall / csops / vm_region 包装
│   ├── Aegis-Bridging-Header.h
│   ├── Detector/
│   │   ├── Models.swift              # 检测项模型与结果聚合
│   │   ├── LevelC.swift              # C 级 4 项
│   │   ├── LevelB.swift              # B 级 6 项
│   │   ├── LevelA.swift              # A 级 5 项
│   │   └── ScanEngine.swift          # 扫描调度
│   └── Views/
│       ├── ContentView.swift         # 首页 + 扫描中
│       └── ResultView.swift          # 结果页
```

---

## 六、已知限制

1. **A5 App Attest 需要付费开发者账号** 的 `com.apple.developer.devicecheck.appattest-environment` entitlement，否则 `isSupported` 为 false，该项自动跳过。
2. **C2 URL Scheme** 必须在 `Info.plist` 的 `LSApplicationQueriesSchemes` 中声明，否则 `canOpenURL` 一律返回 false（已配置好）。
3. **A2 csops** 走的是 `syscall(169, ...)`，不同 iOS 版本号可能变化，若真机报错可改 `AegisShim.c` 里的 syscall 号。
4. **检测结果仅供参考**：单项异常不必然等同于环境被入侵，建议看整体命中数量。
5. 本工程在无 Mac 环境下编写，**未经过 Xcode 实际编译验证**。若 CI 报错，把报错发我，我按提示改。

---

## 七、想调整的方向

告诉我你要改哪里，我直接改代码：

- 增加/删除检测项
- 调整判定策略（比如"命中 ≥3 项才判定越狱"）
- UI 配色、布局、文案
- 增加检测报告导出（文本 / 截图分享）
- 增加"详细日志"页面
- 改成 Objective-C 实现
