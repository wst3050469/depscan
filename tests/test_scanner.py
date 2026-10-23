"""DepScan 单测：python -m unittest discover -s tests （在 /opt/need-radar 下跑）。"""
import sys
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))
sys.path.insert(0, str(REPO_ROOT.parent))  # 兼容包内用法(depscan.scanner)
try:  # 仓库根即包体: 直接导入
    from scanner import parse_go, parse_npm, parse_pip, scan  # noqa: E402
    from vulndb import _in_range, lookup  # noqa: E402
except ImportError:  # 作为 depscan 包安装/从父目录运行
    from depscan.scanner import parse_go, parse_npm, parse_pip, scan  # noqa: E402
    from depscan.vulndb import _in_range, lookup  # noqa: E402

FIXTURES = Path(__file__).resolve().parent / "fixtures"


class TestVersionRange(unittest.TestCase):
    def test_lt(self):
        self.assertTrue(_in_range("1.2.5", "<1.2.6"))
        self.assertFalse(_in_range("1.2.6", "<1.2.6"))

    def test_interval(self):
        self.assertTrue(_in_range("4.17.15", ">=4.0.0,<4.17.21"))
        self.assertFalse(_in_range("4.17.21", ">=4.0.0,<4.17.21"))

    def test_star(self):
        self.assertTrue(_in_range("9.9.9", "*"))


class TestLookup(unittest.TestCase):
    def test_hit(self):
        hits = lookup("npm", "lodash", "4.17.15")
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0]["fix_version"], "4.17.21")

    def test_miss_by_version(self):
        self.assertEqual(lookup("npm", "lodash", "4.17.21"), [])

    def test_miss_by_name(self):
        self.assertEqual(lookup("npm", "express", "4.18.2"), [])


class TestParsers(unittest.TestCase):
    def test_npm(self):
        deps = parse_npm(FIXTURES / "sample_npm" / "package.json")
        names = {d[1] for d in deps}
        self.assertIn("lodash", names)
        self.assertEqual(dict((d[1], d[2]) for d in deps)["lodash"], "4.17.15")

    def test_pip(self):
        deps = parse_pip(FIXTURES / "sample_pip" / "requirements.txt")
        self.assertIn(("pypi", "litellm", "1.53.1"), deps)

    def test_go(self):
        deps = parse_go(FIXTURES / "sample_go" / "go.mod")
        self.assertIn(("go", "golang.org/x/net", "0.20.0"), deps)


class TestScanE2E(unittest.TestCase):
    def test_scan_all_three(self):
        result = scan(FIXTURES)
        hit_names = {f["name"] for f in result["findings"]}
        for expect in ("lodash", "minimist", "litellm", "requests", "pillow", "golang.org/x/net"):
            self.assertIn(expect, hit_names, f"样例项目应中招: {expect}")
        self.assertIn("express", {d[1] for d in result["deps"]})

    def test_unlocked_flagged(self):
        result = scan(FIXTURES / "sample_npm")
        un = [f for f in result["findings"] if f["advisories"][0]["id"] == "UNLOCKED"]
        self.assertEqual(len(un), 1)  # eslint-plugin-x 未锁版本


if __name__ == "__main__":
    unittest.main()
