# LINE 多账号容器 Dylib

与 `HookDylib` 同一套路：`constructor` 启动 → 注入到 `LINE.app` → 重签安装。

## 功能

- 每次打开 LINE 先显示「账号1~4」首页
- 选择后创建/切换独立容器（沙盒目录 + App Group + Keychain 前缀）
- 选完自动重启一次，再进入对应账号

## GitHub 编译

可以。仓库已加 Actions：`.github/workflows/build-line-account.yml`

1. 把本仓库推到 GitHub
2. Actions → **Build LineAccount.dylib** → 下载产物 `LineAccount.dylib`

本地（Mac）也可：

```bash
chmod +x LineAccountDylib/build.sh
./LineAccountDylib/build.sh
```

Windows 不能直接编 iOS arm64，需用 GitHub Actions 或 Mac。

## 注入到 LINE

```bash
# 1. 拷贝 dylib
mkdir -p Payload/LINE.app/Frameworks
cp LineAccountDylib/build/LineAccount.dylib Payload/LINE.app/Frameworks/

# 2. 给主程序加加载命令（Mac）
# 若没有 insert_dylib，可用 optool / lief 等
insert_dylib --strip-codesig --all-yes \
  @executable_path/Frameworks/LineAccount.dylib \
  Payload/LINE.app/LINE \
  Payload/LINE.app/LINE

# 3. 打包
python make_ipa.py

# 4. 重签安装
```

检查是否加载成功：

```bash
otool -L Payload/LINE.app/LINE | grep LineAccount
```

## 容器位置（设备上）

```
AppHome/LineAccountSlots/account_1/
  Documents/
  Library/...
  AppGroup/group.com.linecorp.line/
  ...
```

Keychain 项会加前缀：`line.slot.1.` / `line.slot.2.` ...
