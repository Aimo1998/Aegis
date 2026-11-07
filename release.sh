#!/bin/bash
#
# Aegis 发布脚本
#
# 用法:
#   ./release.sh <版本号> <deb路径> <ipa路径> [说明文件]
#
# 示例:
#   ./release.sh 1.2.0 build/Aegis.deb build/Aegis.ipa
#   ./release.sh 1.2.0 build/Aegis.deb build/Aegis.ipa RELEASE_NOTES.md
#
# 发行版命名固定为:  Aegis v<版本号>
# 例如  Aegis v1.2.0
#
# 需要环境变量 GH_TOKEN（有 repo 权限的 GitHub PAT）

set -euo pipefail

OWNER="Aimo1998"
REPO="Aegis"

VERSION="${1:-}"
DEB="${2:-}"
IPA="${3:-}"
NOTES_FILE="${4:-}"

if [ -z "$VERSION" ] || [ -z "$DEB" ] || [ -z "$IPA" ]; then
    echo "用法: ./release.sh <版本号> <deb路径> <ipa路径> [说明文件]"
    echo "示例: ./release.sh 1.2.0 build/Aegis.deb build/Aegis.ipa"
    exit 1
fi

if [ -z "${GH_TOKEN:-}" ]; then
    echo "错误: 未设置 GH_TOKEN"
    exit 1
fi

TAG="v${VERSION}"
NAME="Aegis v${VERSION}"

[ -f "$DEB" ] || { echo "找不到 deb: $DEB"; exit 1; }
[ -f "$IPA" ] || { echo "找不到 ipa: $IPA"; exit 1; }

# 说明正文：优先读文件，否则生成默认模板
if [ -n "$NOTES_FILE" ] && [ -f "$NOTES_FILE" ]; then
    BODY="$(cat "$NOTES_FILE")"
else
    BODY="## ${NAME}

iOS 越狱环境检测工具 —— 17 项检测 + 5 个功能模块，全程离线。

### 安装

**deb（越狱设备，推荐）**
\`\`\`bash
dpkg -i Aegis.deb
\`\`\`

**ipa（TrollStore / 自签）**
\`\`\`bash
unzip -o Aegis.ipa -d /tmp/aegis
cp -R /tmp/aegis/Payload/Aegis.app /var/jb/Applications/
chown -R root:wheel /var/jb/Applications/Aegis.app
ldid -S /var/jb/Applications/Aegis.app/Aegis
uicache -p /var/jb/Applications/Aegis.app
\`\`\`

### 要求
- iOS 16.0+ / arm64
"
fi

echo "==> 创建 Release: ${NAME}  (tag: ${TAG})"

PAYLOAD=$(python3 - "$TAG" "$NAME" "$BODY" <<'PY'
import json, sys
tag, name, body = sys.argv[1], sys.argv[2], sys.argv[3]
print(json.dumps({
    "tag_name": tag,
    "name": name,
    "body": body,
    "draft": False,
    "prerelease": False,
    "target_commitish": "main"
}))
PY
)

RESP=$(curl -s -X POST \
    -H "Authorization: token ${GH_TOKEN}" \
    -H "Accept: application/vnd.github+json" \
    "https://api.github.com/repos/${OWNER}/${REPO}/releases" \
    -d "$PAYLOAD")

RID=$(echo "$RESP" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('id',''))")

if [ -z "$RID" ]; then
    echo "创建失败:"
    echo "$RESP" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('message'), d.get('errors'))"
    exit 1
fi

echo "    Release id: ${RID}"

for f in "$DEB" "$IPA"; do
    NAME_ONLY=$(basename "$f")
    SIZE=$(du -h "$f" | cut -f1)
    echo "==> 上传 ${NAME_ONLY} (${SIZE})"

    curl -s -X POST \
        -H "Authorization: token ${GH_TOKEN}" \
        -H "Content-Type: application/octet-stream" \
        --data-binary @"$f" \
        "https://uploads.github.com/repos/${OWNER}/${REPO}/releases/${RID}/assets?name=${NAME_ONLY}" \
    | python3 -c "
import sys, json
d = json.load(sys.stdin)
if 'id' in d:
    print('    ✅', d['name'], d['size'], 'bytes')
else:
    print('    ❌', d.get('message'), d.get('errors'))
    sys.exit(1)
"
done

echo
echo "完成: https://github.com/${OWNER}/${REPO}/releases/tag/${TAG}"
