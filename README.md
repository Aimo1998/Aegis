# Aegis

[Click me to switch English.](README_EN.md)

> 一个纯本地的 iOS 越狱环境检测 App —— 三级递进，34 项检测，覆盖从传统有根越狱到 RootHide 级别的高级隐藏。

**全程离线运行，不联网、不上传任何数据。**

```
🔵 C 级 · 基础特征          5 项
🟡 B 级 · 现代无根与注入     14 项
🔴 A 级 · 深度对抗与底层校验  14 项
```

---

## 特性

- **三级递进**：C 级快速识别传统越狱；B 级针对 rootless（`/var/jb`）与注入框架；A 级专门对抗 RootHide 那类「进程级隔离 + Hook 伪装」
- **API 交叉验证**：同一语义走 `libc` 与裸 `syscall` 两条路，结果不一致即暴露 Hook
- **计时攻击检测**：用 `mach_absolute_time` 采样，返回值能伪造，耗时伪造不了
- **IMP 归属校验**：拿关键 selector 的 IMP 反查 `dladdr`，判断方法有没有被重定向到越狱路径下的 dylib
- **零第三方依赖**：纯 SwiftUI + Darwin + DeviceCheck
- **报告导出**：纯文本 / JSON / 摘要三种格式，点击即复制到剪贴板并弹系统分享面板
- **单项重测**：结果页展开任意未通过项，可只重跑这一项，报告原地更新
- **中英双语**：34 项检测的名称、原理、绕过说明全部双语，运行时切换无需重启
- **系统信息诊断页**：把所有检测依赖的底层返回值（sysctl / csops / lstat-vs-syscall / 挂载表 / 进程表）原样列出，便于核对判定是否准确
- **底层全走 C shim**：`fork` / `ptrace` / `_dyld_*` / `getfsstat` 在 Swift 里被标 unavailable 或签名难对齐，统一由 `AegisShim.c` 封装

---

## 检测项矩阵

### 🔵 C 级 · 基础特征（6 项）

| ID | 检测项 | 实现要点 |
|---|---|---|
| C1 | 文件系统黑名单 | `lstat` + `FileManager` 双查 48 个特征路径（Cydia / Sileo / ssh / apt / Substrate / `/var/jb` 等） |
| C2 | URL Scheme 探测 | `canOpenURL` 检查 cydia / sileo / filza / zbra / trollstore 等 9 个协议 |
| C3 | 沙盒逃逸与进程创建 | 向 `/private`、`/var/jb`、`/tmp` 写探针；`syscall(SYS_fork)` 建子进程 |
| C4 | 环境变量审查 | `DYLD_INSERT_LIBRARIES` / `DYLD_FRAMEWORK_PATH` 等 8 个变量，判断是否含非系统路径 |
| C5 | 模拟器与硬件指纹 | `TARGET_OS_SIMULATOR` + `hw.machine` + Secure Enclave / 生物识别硬件存在性 |
| C6 | 区域与系统一致性 | `NSLocale` 区域码合法性、区域/语言矛盾组合、时区是否匹配 |

### 🟡 B 级 · 现代无根与注入（14 项）

| ID | 检测项 | 实现要点 |
|---|---|---|
| B1 | 无根路径探测 | 裸 `SYS_lstat` 探 10 个 rootless 挂载点 + `getfsstat` 挂载表扫描 |
| B2 | 注入框架扫描 | `_dyld_image_count` 遍历，匹配 ElleKit / MobileSubstrate / Substitute / libhooker / systemhook / TweakLoader 等 16 个特征 |
| B3 | UI 篡改检测 | 取 `UIApplication` / `UIView` / `UISwitch` / `UIWindow` 等 8 个关键 selector 的 IMP，`dladdr` 反查来源映像 |
| B4 | 调试与反注入 | `sysctl P_TRACED` + `PT_DENY_ATTACH` 自检 + Frida 端口 27042/27043/27044 + `gum_*` 符号 |
| B5 | RWX 内存段 | `vm_region_64` 遍历，挑出 W+X 且不归属任何已加载映像的页 |
| B6 | 进程链检测 | `sysctl KERN_PROC_ALL` 拉全进程表，匹配 jailbreakd / linjector / frida-server / dropbear 等 19 个特征 |
| B7 | 符号链接残留 | `lstat`（不跟随）检查 `/var/jb`、`/.jbroot` 等是否为符号链接，并 `readlink` 读出目标 |
| B8 | 权限异常探测 | 逐个路径取 `errno`，区分「不存在(ENOENT)」与「存在但被拒(EACCES/EPERM)」 |
| B9 | Scheme 声明自检 | 检查 `LSApplicationQueriesSchemes` 是否覆盖 10 个越狱 Scheme，标出 C2 的盲区 |
| B10 | 自身运行路径 | 检查可执行文件是否位于 `/var/jb`、`/private/preboot`、`/.jbroot` 下 |
| B11 | 动态库数量基线 | 正常 150~320；>420 判批量注入，<90 判环境被裁剪 |
| B12 | 本地服务端口 | 扫 22 / 1337 / 4444 / 8080 / 9090 / 31337 / 27042-27044 |
| B13 | 注入过滤不一致性 | 挂载表有 `/var/jb`，dyld 中却无 ellekit/substrate |
| B14 | 屏蔽插件特征 | 匹配 noJailbreak / Shadow / Choicy / HBIDHook / Liberty / vnodebypass / A-Bypass / FlyJB 等 14 个 |

### 🔴 A 级 · 深度对抗与底层校验（14 项）

| ID | 检测项 | 实现要点 |
|---|---|---|
| A1 | API 交叉验证 | `lstat`(libc) vs `SYS_lstat`(裸 syscall) 比对返回值 / inode / 文件类型，再加 `FileManager` 第三重交叉 |
| A2 | 代码签名与 TrustCache | `csops(CS_OPS_STATUS)` 读 csflags，检查 `CS_VALID` 被强注、`CS_DEBUGGED` 被抹、`CS_HARD`/`CS_KILL` 被剥、缺 `CS_PLATFORM`/`CS_INSTALLER` |
| A3 | 内核状态探测 | `kern.bootargs` 查 `amfi_get_out_of_my_way` / `cs_enforcement_disable`；`getfsstat` 查异常挂载 |
| A4 | 计时攻击检测 | `mach_absolute_time` 采样 300 次，对比正常路径 / 越狱路径 / 纯 syscall 基线，>4x 或 <0.15x 判为可疑 |
| A5 | 防篡改与指针完整性 | 关键 API 的函数地址是否仍在合法映像内（内联 Hook / PAC 伪造），`dladdr` 交叉验证来源库 |
| A6 | App Attest 完整性 | `DCAppAttestService.generateKey`，无 entitlement 时自动跳过 |
| A7 | 挂载点深度分析 | `getfsstat` + `statfs` 检查根文件系统可写性、`/System/Library` 挂载 flags、挂载点总数异常 |
| A8 | 映像路径一致性 | 同一映像分别用 `_dyld_get_image_name` 与 `dladdr` 解析，比对路径是否分歧 |
| A9 | csops 完整性 | 连调 3 次 `csops(CS_OPS_STATUS)`，返回值不稳定即判 Hook；`CS_VALID` 必须置位 |
| A10 | Mach-O 自检 | 绕过 `_dyld_*`，直接解析主程序 load commands 的 `LC_LOAD_DYLIB`，与 dyld 视图交叉比对 |
| A11 | Entitlements 校验 | `SecTask` 读 `application-identifier` / `get-task-allow` / `platform-application` |
| A12 | 插件列表完整性 | TweakInject 目录存在但零 tweak 加载 |
| A13 | RootHide 路径熵值 | 对含 `jb` 的挂载点算香农熵，>4.3 判随机化命名 |
| A14 | Rootful 路径残留 | 解析各 dylib 的 `LC_LOAD_DYLIB`，找 `/Library/MobileSubstrate` 等旧路径 |

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

## 报告导出

结果页底部有三个按钮，点击后**立即写入剪贴板**并弹出系统分享面板：

| 格式 | 内容 |
|---|---|
| 完整报告 | 时间 / 设备 / 系统 / 等级 / 风险分 / 每项的 ID、名称、权重、证据、原理、绕过 |
| JSON | 结构化数据，`items` 数组里每个检测项一条，适合程序处理 |
| 摘要 | 精简版，只列未通过项和证据，适合贴到聊天里 |

```
Aegis · 🟡 B 级 · 动态环境 · 23/100 低风险
iPhone X (iPhone10,3) / iOS 16.7.8
通过 9 / 未通过 3

❌ B1 无根路径探测
   /var/jb、/var/jb/usr、/var/jb/usr/lib、/var/jb/Library
❌ B10 二进制加密状态
   Mach-O 未加密（cryptid=0，非 App Store 分发）
```

JSON 里的 `version` 字段读自 `CFBundleShortVersionString`，不会和 App 版本脱节。

---

## 单项重测

展开任意 ❌ 项，底部有「重测此项」。只重跑当前这一项，报告原地更新、评分重新计算，不用整级重扫。

适合场景：改了环境（关掉 Frida、卸载某个 tweak）后想确认某一项的变化，而不想等 28 项跑完。

---

## 对比模式

菜单第四项。把另一台设备导出的「摘要」粘进来，逐项对比：

```
Failed on both · 3
  B1   无根路径探测
  B10  二进制加密状态
  B12  本地服务端口
```

分四组输出：A 有问题 B 正常 / B 有问题 A 正常 / 两边都未通过 / 两边都通过。

解析器同时兼容中文 `设备    : ` 和英文 `Device  : ` 两种前缀。

---

## 风险评分

34 项检测各有权重（合计 **503 分**），命中项权重按比例换算成 0–100 的风险分：

| 分数 | 等级 | 含义 |
|---|---|---|
| 0 | 安全 | 未命中任何项 |
| 1–25 | 低风险 | 只有基础特征命中（如残留的文件路径） |
| 26–50 | 中风险 | 出现注入或调试痕迹 |
| 51–75 | 高风险 | 多项深度检测同时命中 |
| 76–100 | 极高风险 | 底层状态全面不一致，典型 RootHide 特征 |

| ID | 权重 | ID | 权重 | ID | 权重 |
|---|---|---|---|---|---|
| C1 | 8 | B1 | 12 | A1 | 25 |
| C2 | 6 | B2 | 15 | A2 | 20 |
| C3 | 15 | B3 | 18 | A3 | 15 |
| C4 | 10 | B4 | 12 | A4 | 22 |
| C5 | 5 | B5 | 15 | A5 | 25 |
| — | — | B6 | 10 | A6 | 10 |
| — | — | B7 | 12 | A7 | 20 |
| — | — | B8 | 15 | A8 | 22 |
| — | — | B9 | 6 | A9 | 18 |
| — | — | B10 | 10 | A10 | 24 |
| — | — | B11 | 8 | A11 | 22 |
| — | — | B12 | 10 | — | — |
| C6 | 6 | B13 | 14 | A12 | 20 |
| — | — | B14 | 12 | A13 | 24 |
| — | — | — | — | A14 | 22 |

> 判定仍沿用「任一命中即 😢」，评分只用于表达严重程度。若要按分数阈值判定，改 `ScanReport.isJailbroken` 即可。

---

## 绕过提示

每项 ❌ 展开后，除原理与证据，还会显示一行 **绕过** —— 说明骗过该类检测通常需要什么手段：

```
❌ API 交叉验证检测未通过
   原理  同一路径分别用 lstat 与 SYS_lstat 查询，比对返回值 / inode / 类型……
   绕过  必须同时 Hook libc 与裸 syscall 且结果完全一致，极易露馅
   证据  /var/jb: lstat=0 raw=0，inode/type 不一致
```

这让结果更有信息量：一眼能看出哪项是「硬检测」（如 A5 需完整伪造指针链），哪项只是「软特征」（如 C2 卸载工具 App 即消失）。

---

## 主界面模式

左上角 `☰` 在四个模式间切换：

| 模式 | 内容 |
|---|---|
| 🛡 **检测** | 选等级 → 扫描 → 结果（含风险评分卡片） |
| 📚 **注入库** | 枚举全部已加载 dylib，按来源分 6 类，越狱注入标红排最前 |
| 🕒 **历史** | 每次扫描自动存档（最多 60 条），可对比上一条同等级记录，标出新增失败 / 已恢复项 |
| 🧪 **红队自测** | 主动替换自身 IMP 验证 B3 灵敏度；统计注入库可见性 |
| 🧾 **系统信息** | 底层返回值诊断：sysctl、csflags 位解析、lstat 与裸 syscall 对比、挂载表、进程表 |
| 📊 **对比** | 粘贴两台设备的报告，逐项对比出各自独有的失败项 |

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
4. **C5 硬件指纹**只认「明确的模拟器架构」（`x86_64` / `arm64` / `i386`）；识别不出的机型一律视为真机，优先避免假阳性
5. 检测结果仅供参考，**单项异常不必然等同于环境被入侵**，建议结合整体命中数量判断

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
    │   ├── Models.swift             # 检测项模型 + 结果聚合 + 风险评分
    │   ├── LevelC.swift             # 🔵 5 项
    │   ├── LevelB.swift             # 🟡 12 项
    │   ├── LevelA.swift             # 🔴 11 项
    │   ├── ScanEngine.swift         # 扫描调度
    │   ├── DylibScanner.swift       # 已加载映像枚举与分类
    │   ├── HistoryStore.swift       # 历史记录 + 权重/绕过元数据
    │   ├── RedTeam.swift            # 自我篡改与注入可见性测试
    │   ├── ReportExport.swift       # 报告导出（文本 / JSON / 摘要）
    │   ├── L10n.swift               # 中英双语
    │   └── DetectorTextEN.swift     # 28 项的英文原理与绕过
    └── Views/
        ├── ContentView.swift        # 顶栏 + 汉堡菜单 + 首页 + 扫描中
        ├── ResultView.swift         # 结果页（评分卡 + 展开证据/绕过）
        ├── DylibListView.swift      # 注入库清单
        ├── HistoryView.swift        # 历史记录与变化对比
        ├── RedTeamView.swift        # 红队自测
        ├── SystemInfoView.swift     # 系统信息诊断
        ├── CompareView.swift        # 两台设备报告对比
        └── SharedFooter.swift       # 全局署名
```

---

## 环境要求

- iOS **16.0+**（`kerning` / `tracking` 等 SwiftUI API 需要 16+）
- 构建：Xcode 15+ / XcodeGen
- 测试环境：Dopamine3 arm64

---

## 免责声明

本项目仅用于**安全研究与自有设备环境检测**。检测结果不构成任何安全结论，请勿用于未授权的设备审计。
