#!/bin/bash
# 本地 / GitHub Actions 通用编译脚本（Mac + Xcode / iphoneos SDK）
# v28 方案 B：Tweak.m (ObjC) + LineProxyHook.swift (Swift) 混编成一个 dylib
set -euo pipefail

ROOT="$(cd "$(dirname "$0")" && pwd)"
OUT_DIR="${ROOT}/build"
OUT_DYLIB="${OUT_DIR}/LineAccount.dylib"
MIN_IOS="${MIN_IOS:-15.0}"
TARGET="arm64-apple-ios${MIN_IOS}"

mkdir -p "${OUT_DIR}"

for f in Tweak.m LineProxyHook.swift LineProxyHook-Bridging.h; do
  if [[ ! -f "${ROOT}/${f}" ]]; then
    echo "[!] 缺少 ${f}（当前目录文件：）"
    ls -la "${ROOT}"
    exit 1
  fi
done

if ! command -v xcrun >/dev/null 2>&1; then
  echo "[!] 需要 macOS + Xcode Command Line Tools"
  exit 1
fi

SDK="$(xcrun --sdk iphoneos --show-sdk-path)"
CLANG="$(xcrun --sdk iphoneos --find clang)"
SWIFTC="$(xcrun --sdk iphoneos --find swiftc)"
echo "[*] SDK: ${SDK}"
echo "[*] target: ${TARGET}"

echo "[*] 1/3 编译 Swift → LineProxyHook.o"
"${SWIFTC}" \
  -sdk "${SDK}" -target "${TARGET}" \
  -import-objc-header "${ROOT}/LineProxyHook-Bridging.h" \
  -parse-as-library -O -wmo \
  -emit-object -o "${OUT_DIR}/LineProxyHook.o" \
  "${ROOT}/LineProxyHook.swift"

echo "[*] 2/3 编译 ObjC → Tweak.o"
"${CLANG}" -arch arm64 \
  -isysroot "${SDK}" \
  -miphoneos-version-min="${MIN_IOS}" \
  -fobjc-arc \
  -c -o "${OUT_DIR}/Tweak.o" \
  "${ROOT}/Tweak.m"

echo "[*] 3/3 链接 → LineAccount.dylib（swiftc 拉 Swift runtime）"
"${SWIFTC}" \
  -sdk "${SDK}" -target "${TARGET}" \
  -emit-library -o "${OUT_DYLIB}" \
  "${OUT_DIR}/Tweak.o" "${OUT_DIR}/LineProxyHook.o" \
  -framework Foundation \
  -framework UIKit \
  -framework Security \
  -framework CoreGraphics \
  -framework QuartzCore \
  -framework Network

# 可选：伪签名，方便后续重签工具处理
if command -v ldid >/dev/null 2>&1; then
  ldid -S "${OUT_DYLIB}" || true
fi

echo "[+] OK: ${OUT_DYLIB}"
ls -lh "${OUT_DYLIB}"
file "${OUT_DYLIB}"
