#!/bin/bash
# 本地 / GitHub Actions 通用编译脚本（Mac + Xcode / iphoneos SDK）
set -euo pipefail

ROOT="$(cd "$(dirname "$0")" && pwd)"
OUT_DIR="${ROOT}/build"
OUT_DYLIB="${OUT_DIR}/LineAccount.dylib"
MIN_IOS="${MIN_IOS:-15.0}"

mkdir -p "${OUT_DIR}"

if ! command -v xcrun >/dev/null 2>&1; then
  echo "[!] 需要 macOS + Xcode Command Line Tools"
  exit 1
fi

SDK="$(xcrun --sdk iphoneos --show-sdk-path)"
echo "[*] SDK: ${SDK}"
echo "[*] Building LineAccount.dylib ..."

clang -arch arm64 -shared \
  -o "${OUT_DYLIB}" \
  -framework Foundation \
  -framework UIKit \
  -framework Security \
  -isysroot "${SDK}" \
  -miphoneos-version-min="${MIN_IOS}" \
  -fobjc-arc \
  "${ROOT}/Tweak.m"

# 可选：伪签名，方便后续重签工具处理
if command -v ldid >/dev/null 2>&1; then
  ldid -S "${OUT_DYLIB}" || true
fi

echo "[+] OK: ${OUT_DYLIB}"
ls -lh "${OUT_DYLIB}"
file "${OUT_DYLIB}"
