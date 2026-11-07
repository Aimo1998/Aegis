## Aegis v1.2.0

iOS 越狱环境检测 —— **28 项检测，三级递进**，全程离线。

### 本次新增 4 个功能

**报告导出**（结果页底部）
- 完整报告：每项的原理、证据、权重、绕过说明
- JSON：结构化，`version` 读自 Info.plist
- 摘要：精简版，适合贴到聊天里
- 点击即复制到剪贴板 + 弹出系统分享面板

**单项重测**
展开任意 ❌ 项 → 「重测此项」，只跑这一项，报告原地更新。

**中英双语**
28 项的名称、原理、绕过全部双语，菜单里切换，无需重启。

**对比模式**
粘贴两台设备的报告，逐项对比出各自独有的失败项。

---

### 检测项 23 → 28

| ID | 名称 | 实现 |
|---|---|---|
| B10 | 二进制加密状态 | 读 `LC_ENCRYPTION_INFO_64` 的 cryptid，App Store 为 1，自签名/越狱为 0 |
| B11 | 动态库数量基线 | 正常 150~320，>700 判批量注入 |
| B12 | 本地服务端口 | 22 / 1337 / 4444 / 8080 / 9090 / 31337 / 27042-27044 |
| A10 | Mach-O 自检 | 绕过 `_dyld_*`，直接解析 `LC_LOAD_DYLIB` |
| A11 | Entitlements 校验 | `SecTask` 读 application-identifier 等 |

（另外 B7 / B8 / B9 / A7 / A8 / A9 是上一轮加入的）

---

### 11 项按真机实测校准

在 iPhone X / iOS 16.7.8 / Dopamine rootless 上跑完 28 项后修掉的误报与失效：

| 项 | 原问题 | 修法 |
|---|---|---|
| C5 | `hw.model` 在 iOS 返回平台代号 D22AP | 改用 `hw.machine` |
| C3 | `/tmp` 是沙盒内符号链接 | 移除该探测 |
| B7 | Dopamine 的 `/var/jb` 本就指向 preboot | 排除这类链接 |
| B10 | 沙盒读不到 `/var/jb`，检查永远失败 | 改用 cryptid |
| B11 | 阈值 420 太严 | 提到 700 |
| B4 | 与 B12 重复扫端口 | 端口归 B12 |
| B9 | 配置问题当越狱证据 | 权重 6 → 1 |
| A4 | 拿 lstat 比 getpid，25000 倍属正常 | 三条 lstat 互比 |
| A8 | dladdr 全失败时假装通过 | 加解析率自检 |
| A11 | ldid 空签名被当重签名 | 缺失不判异常 |
| A2 | ad-hoc 签名必然缺 CS_RESTRICT | 只判内核强制的位 |

校准后在本机的 B 级结果为 **9 通过 / 3 未通过**，三项全部是真实特征：

```
❌ B1   无根路径        /var/jb 存在
❌ B10  二进制加密状态  cryptid=0
❌ B12  本地服务端口    27042/frida
```

---

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
