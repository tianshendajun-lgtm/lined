# -*- coding: utf-8 -*-
"""
将 LineAccount.dylib 注入到 Payload/LINE.app
优先使用 insert_dylib；若无则尝试 lief

关键修复（2026-07）：
  之前的版本用 `otool -L` 判断"是否已注入"，但 Windows 下没有 otool，
  try/except 静默失败后总是会再插一条 LC_LOAD_DYLIB，
  导致主二进制里堆积了 30+ 条重复的 LineAccount.dylib 加载命令。
  现在改为：
    1) 自己维护一份 <BINARY>.pristine 干净原始二进制备份（第一次运行时生成）。
    2) 每次注入前都先从 pristine 还原，保证永远是"只注入一次"的干净状态，
       无论 inject.py 被重复运行多少次。
"""
import os
import shutil
import struct
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
APP = os.path.join(ROOT, "Payload", "KakaoTalk.app")
BINARY = os.path.join(APP, "KakaoTalk")
PRISTINE = BINARY + ".pristine"
FRAMEWORKS = os.path.join(APP, "Frameworks")
SRC_DYLIB = os.path.join(ROOT, "LineAccountDylib", "build", "LineAccount.dylib")
DST_DYLIB = os.path.join(FRAMEWORKS, "LineAccount.dylib")
LOAD_PATH = "@executable_path/Frameworks/LineAccount.dylib"

LC_LOAD_DYLIB = 0xC
LC_LOAD_WEAK_DYLIB = 0x18


def count_lineaccount_loads(binary_path):
    """跨平台（不依赖 otool）统计主二进制里已有多少条 LineAccount.dylib 加载命令。"""
    with open(binary_path, "rb") as f:
        data = f.read()

    magic = struct.unpack_from("<I", data, 0)[0]
    if magic != 0xFEEDFACF:  # 只处理 64 位非 fat（LINE 主程序是纯 arm64）
        return -1

    ncmds = struct.unpack_from("<I", data, 16)[0]
    pos = 32
    count = 0
    for _ in range(ncmds):
        cmd, cmdsize = struct.unpack_from("<II", data, pos)
        if cmd in (LC_LOAD_DYLIB, LC_LOAD_WEAK_DYLIB):
            name_off = struct.unpack_from("<I", data, pos + 8)[0]
            name = data[pos + name_off : pos + cmdsize].split(b"\x00")[0]
            if b"LineAccount.dylib" in name:
                count += 1
        pos += cmdsize
    return count


def ensure_clean_binary():
    """保证每次注入前，BINARY 都是「从未注入过」的干净状态。"""
    if not os.path.isfile(PRISTINE):
        # 第一次运行：如果当前主程序已经被污染（历史遗留），无法自动修复，
        # 提示用户手动从原始解密包还原一次。
        existing = count_lineaccount_loads(BINARY)
        if existing > 0:
            print(f"[!] 检测到主二进制已有 {existing} 条 LineAccount.dylib 加载命令，")
            print("    但还没有 pristine 备份，说明这不是干净的原始解密包。")
            print("    请先用未注入过的原始解密 Payload 覆盖此文件，再重新运行本脚本。")
            return False
        shutil.copy2(BINARY, PRISTINE)
        print(f"[+] 已保存干净原始二进制备份: {PRISTINE}")
        return True

    shutil.copy2(PRISTINE, BINARY)
    print(f"[*] 已从干净备份还原主二进制: {BINARY}")
    return True


def main():
    if not os.path.isfile(SRC_DYLIB):
        print("[!] 找不到 dylib，请先编译:")
        print("    LineAccountDylib/build.sh  或  GitHub Actions")
        print(f"    期望路径: {SRC_DYLIB}")
        return 1
    if not os.path.isfile(BINARY):
        print(f"[!] 找不到主程序: {BINARY}")
        return 1

    if not ensure_clean_binary():
        return 1

    os.makedirs(FRAMEWORKS, exist_ok=True)
    shutil.copy2(SRC_DYLIB, DST_DYLIB)
    print(f"[+] 已复制: {DST_DYLIB}")

    insert = shutil.which("insert_dylib")
    if insert:
        cmd = [insert, "--strip-codesig", "--all-yes", LOAD_PATH, BINARY, BINARY]
        print("[*] 运行:", " ".join(cmd))
        subprocess.check_call(cmd)
        print("[+] insert_dylib 完成")
    else:
        # fallback: lief
        try:
            import lief
        except ImportError:
            print("[!] 未找到 insert_dylib，且未安装 lief")
            print("    Mac: brew install insert_dylib 或自行安装")
            print("    或: pip install lief 后再运行本脚本")
            return 1

        fat = lief.MachO.parse(BINARY)
        binary = fat.at(0) if hasattr(fat, "at") else fat
        if isinstance(binary, lief.MachO.FatBinary):
            target = None
            for b in binary:
                if b.header.cpu_type == lief.MachO.Header.CPU_TYPE.ARM64:
                    target = b
                    break
            if target is None:
                target = binary.at(0)
            target.add_library(LOAD_PATH)
            binary.write(BINARY)
        else:
            binary.add_library(LOAD_PATH)
            binary.write(BINARY)
        print("[+] lief 注入完成")

    final_count = count_lineaccount_loads(BINARY)
    if final_count != 1:
        print(f"[!] 警告: 注入后 LineAccount.dylib 加载命令数 = {final_count}（应为 1），请检查")
    else:
        print("[+] 校验通过: 主二进制里恰好 1 条 LineAccount.dylib 加载命令")

    print("[*] 下一步: python make_ipa.py 然后重签安装")
    return 0


if __name__ == "__main__":
    sys.exit(main())
