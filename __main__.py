"""CLI: python -m depscan <项目目录>"""
import sys
from pathlib import Path

from .report import render
from .scanner import scan


def main() -> int:
    if len(sys.argv) != 2:
        print("用法: python -m depscan <项目目录>")
        return 2
    target = Path(sys.argv[1])
    if not target.is_dir():
        print(f"目录不存在: {target}")
        return 2
    print(render(scan(target)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
