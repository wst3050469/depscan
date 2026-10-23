#!/usr/bin/env python3
"""DepScan 直接入口: python dep-scan-cli.py <项目目录>  (无需包结构/安装)"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
try:
    from depscan.report import render
    from depscan.scanner import scan
except ImportError:
    from report import render
    from scanner import scan


def main() -> int:
    if len(sys.argv) != 2:
        print("用法: python dep-scan-cli.py <项目目录>")
        return 2
    target = Path(sys.argv[1])
    if not target.is_dir():
        print(f"目录不存在: {target}")
        return 2
    print(render(scan(target)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
