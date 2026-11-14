## Aegis v1.2.1

iOS 越狱环境检测 —— **34 项检测，三级递进**，全程离线。

### 本次新增 6 项检测

**🛑 C 级 · 基础特征（5 → 6 项）**

| ID | 名称 | 实现 |
|---|---|---|
| C6 | 区域与系统一致性 | 校验 `NSLocale` 区域码合法性、区域与语言的矛盾组合（cn:en / us:zh 等）、时区是否与区域匹配 |

**🟡 B 级 · 现代无根与注入（12 → 14 项）**

| ID | 名称 | 实现 |
|---|---|---|
| B13 | 注入过滤不一致性 | 挂载表里有 `/var/jb` 或 jbroot，但 dyld 映像里找不到任何越狱框架 |
| B14 | 屏蔽插件特征 | 直接匹配 noJailbreak / Shadow / Choicy / HBIDHook / Liberty / vnodebypass / A-Bypass / FlyJB / KernBypass 等 14 个 |

**🔴 A 级 · 深度对抗与底层校验（11 → 14 项）**

| ID | 名称 | 实现 |
|---|---|---|
| A12 | 插件列表完整性 | TweakInject / MobileSubstrate 目录挂载着，但没有任何该目录下的 dylib 被加载 |
| A13 | RootHide 路径熵值 | 对含 jb 的挂载点计算字符分布香农熵，> 4.3 判定为随机化命名（`/.jbroot-<hex>` 这类） |
| A14 | Rootful 路径残留 | 解析越狱路径下每个 dylib 的 `LC_LOAD_DYLIB`，查找 `/Library/MobileSubstrate`、`/usr/lib/substrate` 残留 |

### 配套改动

- 权重 **405 → 503**
- 新增 C 函数 `aegis_image_load_dylibs`，用于读取任意已加载映像的 `LC_LOAD_DYLIB`
- 34 项的中文名称、原理说明、绕过提示全部补齐英文

### 安装

**deb（越狱设备，推荐）**
```bash
dpkg -i Aegis.deb
```
`postinst` 自动完成 `ldid -S`、`chown`、`uicache`。

**ipa（TrollStore / 自签）**
```bash
unzip -o Aegis.ipa -d /tmp/aegis
cp -R /tmp/aegis/Payload/Aegis.app /var/jb/Applications/
chown -R root:wheel /var/jb/Applications/Aegis.app
ldid -S /var/jb/Applications/Aegis.app/Aegis
uicache -p /var/jb/Applications/Aegis.app
```

### 要求
- iOS 16.0+ / arm64
- 全程离线，不联网、不上传任何数据
