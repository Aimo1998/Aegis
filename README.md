# Aegis

> 一个纯本地的 iOS 越狱环境检测 App —— 三级递进，17 项检测，覆盖从传统有根越狱到 RootHide 级别的高级隐藏。

**全程离线运行，不联网、不上传任何数据。**

```
🔵 C 级 · 基础特征          5 项
🟡 B 级 · 现代无根与注入     6 项
🔴 A 级 · 深度对抗与底层校验  6 项
```

---

## 特性

- **三级递进**：C 级快速识别传统越狱；B 级针对 rootless（`/var/jb`）与注入框架；A 级专门对抗 RootHide 那类「进程级隔离 + Hook 伪装」
- **API 交叉验证**：同一语义走 `libc` 与裸 `syscall` 两条路，结果不一致即暴露 Hook
- **计时攻击检测**：用 `mach_absolute_time` 采样，返回值能伪造，耗时伪造不了
- **IMP 归属校验**：拿关键 selector 的 IMP 反查 `dladdr`，判断方法有没有被重定向到越狱路径下的 dylib
- **零第三方依赖**：纯 SwiftUI + Darwin + DeviceCheck
- **底层全走 C shim**：`fork` / `ptrace` / `_dyld_*` / `getfsstat` 在 Swift 里被标 unavailable 或签名难对齐，统一由 `AegisShim.c` 封装

---

## 检测项矩阵

### 🔵 C 级 · 基础特征（5 项）

| ID | 检测项 | 实现要点 |
|---|---|---|
| C1 | 文件系统黑名单 | `lstat` + `FileManager` 双查 48 个特征路径（Cydia / Sileo / ssh / apt / Substrate / `/var/jb` 等） |
| C2 | URL Scheme 探测 | `canOpenURL` 检查 cydia / sileo / filza / zbra / trollstore 等 9 个协议 |
| C3 | 沙盒逃逸与进程创建 | 向 `/private`、`/var/jb`、`/tmp` 写探针；`syscall(SYS_fork)` 建子进程 |
| C4 | 环境变量审查 | `DYLD_INSERT_LIBRARIES` / `DYLD_FRAMEWORK_PATH` 等 8 个变量，判断是否含非系统路径 |
| C5 | 模拟器与硬件指纹 | `TARGET_OS_SIMULATOR` + `hw.machine` + Secure Enclave / 生物识别硬件存在性 |

### 🟡 B 级 · 现代无根与注入（6 项）

| ID | 检测项 | 实现要点 |
|---|---|---|
| B1 | 无根路径探测 | 裸 `SYS_lstat` 探 10 个 rootless 挂载点 + `getfsstat` 挂载表扫描 |
| B2 | 注入框架扫描 | `_dyld_image_count` 遍历，匹配 ElleKit / MobileSubstrate / Substitute / libhooker / systemhook / TweakLoader 等 16 个特征 |
| B3 | UI 篡改检测 | 取 `UIApplication` / `UIView` / `UISwitch` / `UIWindow` 等 8 个关键 selector 的 IMP，`dladdr` 反查来源映像 |
| B4 | 调试与反注入 | `sysctl P_TRACED` + `PT_DENY_ATTACH` 自检 + Frida 端口 27042/27043/27044 + `gum_*` 符号 |
| B5 | RWX 内存段 | `vm_region_64` 遍历，挑出 W+X 且不归属任何已加载映像的页 |
| B6 | 进程链检测 | `sysctl KERN_PROC_ALL` 拉全进程表，匹配 jailbreakd / linjector / frida-server / dropbear 等 19 个特征 |

### 🔴 A 级 · 深度对抗与底层校验（6 项）

| ID | 检测项 | 实现要点 |
|---|---|---|
| A1 | API 交叉验证 | `lstat`(libc) vs `SYS_lstat`(裸 syscall) 比对返回值 / inode / 文件类型，再加 `FileManager` 第三重交叉 |
| A2 | 代码签名与 TrustCache | `csops(CS_OPS_STATUS)` 读 csflags，检查 `CS_VALID` 被强注、`CS_DEBUGGED` 被抹、`CS_HARD`/`CS_KILL` 被剥、缺 `CS_PLATFORM`/`CS_INSTALLER` |
| A3 | 内核状态探测 | `kern.bootargs` 查 `amfi_get_out_of_my_way` / `cs_enforcement_disable`；`getfsstat` 查异常挂载 |
| A4 | 计时攻击检测 | `mach_absolute_time` 采样 300 次，对比正常路径 / 越狱路径 / 纯 syscall 基线，>4x 或 <0.15x 判为可疑 |
| A5 | 防篡改与指针完整性 | 关键 API 的函数地址是否仍在合法映像内（内联 Hook / PAC 伪造），`dladdr` 交叉验证来源库 |
| A6 | App Attest 完整性 | `DCAppAttestService.generateKey`，无 entitlement 时自动跳过 |

---

## 安装方式

### 方式一：deb（越狱设备，推荐）

```bash
dpkg -i Aegis.deb
```

`postinst` 自动完成：

```bash
ldid -S /var/jb/Applications/Aegis.app/Aegis   # ad-hoc 签名
chown -R root:wheel /var/jb/Applications/Aegis.app
uicache -p /var/jb/Applications/Aegis.app      # 刷新图标
```

卸载：

```bash
dpkg -r com.aegis.detector
```

### 方式二：ipa（TrollStore / 自签）

```bash
unzip -o Aegis.ipa -d /tmp/aegis
cp -R /tmp/aegis/Payload/Aegis.app /var/jb/Applications/
chown -R root:wheel /var/jb/Applications/Aegis.app
ldid -S /var/jb/Applications/Aegis.app/Aegis
uicache -p /var/jb/Applications/Aegis.app
```

或直接把 ipa 丢给 TrollStore。

> 未签名 ipa 用系统安装器点「安装」会失败，属正常现象——iOS 只接受已签名 App。

---

## 构建

### Codemagic（无需 Mac）

仓库内已附 `codemagic.yaml`，在 [codemagic.io](https://codemagic.io) 关联本仓库后直接触发构建，产物同时输出 `Aegis.deb` 与 `Aegis.ipa`。

### 本地 macOS

```bash
brew install xcodegen
./build.sh
```

### GitHub Actions

`.github/workflows/build-ipa.yml` 已就绪。注意 macOS runner 排队可能较久。

---

## 技术说明

### 为什么底层调用都走 C shim

Swift 里这些符号要么被标 `unavailable`，要么签名难对齐：

| 符号 | Swift 下的问题 |
|---|---|
| `fork()` | `unavailable: Please use threads or posix_spawn*()` |
| `ptrace()` / `PT_DENY_ATTACH` | 符号与常量都不导出；iOS SDK 没有 `<sys/ptrace.h>` |
| `_dyld_image_count()` / `_dyld_get_image_name()` | 不随 `import Darwin` 暴露 |
| `getfsstat()` | 数组指针与元组重绑定容易踩坑 |
| `csops()` | 私有 syscall，无 libc 包装 |

统一封装进 `AegisShim.c`，Swift 侧只调简单接口：

```c
int  aegis_dyld_image_count(void);
const char *aegis_dyld_image_name(int index);
int  aegis_ptrace_deny_attach(void);
int  aegis_fork_raw(void);
int  aegis_mount_points(char *out, size_t outSize);
int  aegis_list_process_names(char *out, size_t outSize);
int  aegis_csops(uint32_t pid, uint32_t ops, void *useraddr, uint32_t usersize);
bool aegis_read_bootargs(char *buf, size_t bufSize, size_t *outLen);
```

### 计时攻击为什么有效

RootHide 一类方案能在返回值和文件属性上做手脚，但**无法同时伪造耗时**：

- 被 Hook 的路径 → 拦截 → 判断 → 返回伪造结果，耗时显著上升（通常 >4x）
- 直接伪造 ENOENT → 跳过真实 VFS 查找，耗时异常短（<0.15x）

以 `getpid()`（纯 syscall）与 `/System/Library`（正常 lstat）作为双基线，偏差超过阈值即判定可疑。

---

## 已知限制

1. **A6 App Attest** 需付费开发者账号的 `com.apple.developer.devicecheck.appattest-environment` entitlement；免费签环境下 `isSupported` 为 false，该项自动跳过
2. **C2 URL Scheme** 必须在 `Info.plist` 的 `LSApplicationQueriesSchemes` 中声明，否则 `canOpenURL` 恒为 false
3. **计时攻击**依赖设备负载，高负载下可能出现假阳性，阈值（4x / 0.15x）可按实际环境调整
4. 检测结果仅供参考，**单项异常不必然等同于环境被入侵**，建议结合整体命中数量判断

---

## 目录结构

```
Aegis/
├── project.yml                      # XcodeGen 工程定义
├── build.sh                         # 本地一键构建
├── codemagic.yaml                   # Codemagic CI（产出 deb + ipa）
├── .github/workflows/build-ipa.yml  # GitHub Actions
└── Aegis/
    ├── AegisApp.swift
    ├── Info.plist                   # 含 LSApplicationQueriesSchemes
    ├── AegisShim.h / .c             # syscall / ptrace / dyld / 进程表封装
    ├── Aegis-Bridging-Header.h
    ├── Assets.xcassets/AppIcon.appiconset/
    ├── Detector/
    │   ├── Models.swift             # 检测项模型 + 结果聚合
    │   ├── LevelC.swift             # 🔵 5 项
    │   ├── LevelB.swift             # 🟡 6 项
    │   ├── LevelA.swift             # 🔴 6 项
    │   └── ScanEngine.swift         # 扫描调度
    └── Views/
        ├── ContentView.swift        # 首页 + 扫描中
        └── ResultView.swift         # 结果页
```

---

## 环境要求

- iOS **16.0+**（`kerning` / `tracking` 等 SwiftUI API 需要 16+）
- 构建：Xcode 15+ / XcodeGen
- 测试环境：Dopamine3 arm64

---

## 免责声明

本项目仅用于**安全研究与自有设备环境检测**。检测结果不构成任何安全结论，请勿用于未授权的设备审计。
