# -*- coding: utf-8 -*-
"""
将 LineAccount.dylib 注入到 Payload/LINE.app
优先使用 insert_dylib；若无则尝试 lief
"""
import os
import shutil
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
APP = os.path.join(ROOT, "Payload", "LINE.app")
BINARY = os.path.join(APP, "LINE")
FRAMEWORKS = os.path.join(APP, "Frameworks")
SRC_DYLIB = os.path.join(ROOT, "LineAccountDylib", "build", "LineAccount.dylib")
DST_DYLIB = os.path.join(FRAMEWORKS, "LineAccount.dylib")
LOAD_PATH = "@executable_path/Frameworks/LineAccount.dylib"


def main():
    if not os.path.isfile(SRC_DYLIB):
        print("[!] 找不到 dylib，请先编译:")
        print("    LineAccountDylib/build.sh  或  GitHub Actions")
        print(f"    期望路径: {SRC_DYLIB}")
        return 1
    if not os.path.isfile(BINARY):
        print(f"[!] 找不到主程序: {BINARY}")
        return 1

    os.makedirs(FRAMEWORKS, exist_ok=True)
    shutil.copy2(SRC_DYLIB, DST_DYLIB)
    print(f"[+] 已复制: {DST_DYLIB}")

    # 已注入则跳过
    try:
        out = subprocess.check_output(["otool", "-L", BINARY], text=True, stderr=subprocess.STDOUT)
        if "LineAccount.dylib" in out:
            print("[*] 主程序已包含 LineAccount.dylib，跳过注入")
            return 0
    except Exception:
        pass

    insert = shutil.which("insert_dylib")
    if insert:
        cmd = [insert, "--strip-codesig", "--all-yes", LOAD_PATH, BINARY, BINARY]
        print("[*] 运行:", " ".join(cmd))
        subprocess.check_call(cmd)
        print("[+] insert_dylib 完成")
        return 0

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
        # 取 arm64
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
    print("[*] 下一步: python make_ipa.py 然后重签安装")
    return 0


if __name__ == "__main__":
    sys.exit(main())
