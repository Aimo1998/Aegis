#!/bin/bash
# Aegis 本地构建脚本（需要 macOS + Xcode）
# 用法: ./build.sh
# 产物: ./Aegis.ipa

set -e

echo "==> 检查环境"
xcodebuild -version
command -v xcodegen >/dev/null 2>&1 || {
    echo "缺少 XcodeGen，安装中…"
    brew install xcodegen
}

echo "==> 生成工程"
xcodegen generate

echo "==> 编译（未签名）"
xcodebuild \
    -project Aegis.xcodeproj \
    -scheme Aegis \
    -configuration Release \
    -sdk iphoneos \
    -derivedDataPath build \
    CODE_SIGN_IDENTITY="" \
    CODE_SIGNING_REQUIRED=NO \
    CODE_SIGNING_ALLOWED=NO \
    DEVELOPMENT_TEAM="" \
    build

APP="build/Build/Products/Release-iphoneos/Aegis.app"
[ -d "$APP" ] || { echo "编译产物不存在: $APP"; exit 1; }

echo "==> 打包 IPA"
rm -rf Payload Aegis.ipa
mkdir -p Payload
cp -R "$APP" Payload/
zip -qr Aegis.ipa Payload

echo
echo "完成: $(pwd)/Aegis.ipa"
ls -lh Aegis.ipa
echo
echo "安装到越狱设备（TrollStore 或命令行）:"
echo "  scp Aegis.ipa root@<device>:/var/mobile/Documents/"
echo "  或用 Filza 打开 ipa → 用 TrollStore 安装"
