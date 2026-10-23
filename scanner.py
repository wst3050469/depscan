"""DepScan 扫描核心：识别项目依赖清单并比对漏洞库。

支持清单：
  npm  — package.json (dependencies/devDependencies)
  pip  — requirements.txt (pkg==1.2.3 / pkg>=1.0)
  go   — go.mod (require 块)

用法: findings = scan(Path("./myproject"))
隐私设计：只处理包名+版本号，永不读取/上传用户源码。
"""
from __future__ import annotations

import json
import re
from pathlib import Path

try:  # 作为 depscan 包被导入
    from .vulndb import lookup
except ImportError:  # 直接以脚本方式运行(仓库根即包体)
    from vulndb import lookup

# 版本修饰符收敛到裸版本（range 交集第一版从简：取锁/下限版本参与比对，未锁版本记 advisory 全量提示）
_VER_RE = re.compile(r"(\d+(?:\.\d+){0,2})")


def _norm(version_raw: str) -> str | None:
    m = _VER_RE.search(version_raw or "")
    return m.group(1) if m else None


def parse_npm(path: Path) -> list[tuple[str, str, str | None]]:
    data = json.loads(path.read_text(encoding="utf-8"))
    out = []
    for group in ("dependencies", "devDependencies"):
        for name, spec in (data.get(group) or {}).items():
            out.append(("npm", name, _norm(str(spec))))
    return out


def parse_pip(path: Path) -> list[tuple[str, str, str | None]]:
    out = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith(("#", "-")):
            continue
        m = re.match(r"^([A-Za-z0-9_.\-]+)\s*(?:\[[^\]]*\])?\s*(?:==|>=|~=)?\s*([\w.\-]*)", line)
        if m:
            out.append(("pypi", m.group(1), _norm(m.group(2))))
    return out


def parse_go(path: Path) -> list[tuple[str, str, str | None]]:
    out = []
    in_require = False
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line.startswith("require"):
            rest = line[len("require"):].strip()
            if rest.startswith("("):  # 多行块 require (
                in_require = True
                continue
            if rest:  # 单行 require x v1.2.3
                parts = rest.split()
                if len(parts) >= 2:
                    out.append(("go", parts[0], _norm(parts[1])))
            continue
        if in_require and line == ")":
            in_require = False
            continue
        if in_require and line:
            parts = line.split()
            if len(parts) >= 2:
                out.append(("go", parts[0], _norm(parts[1])))
    return out


_PARSERS = {
    "package.json": parse_npm,
    "requirements.txt": parse_pip,
    "go.mod": parse_go,
}


def scan(project_dir: Path, db: dict | None = None) -> dict:
    """扫一个项目目录。返回 {deps: [...], findings: [...], manifests: [...]}。"""
    project_dir = Path(project_dir)
    deps, findings, manifests = [], [], []
    for fname, parser in _PARSERS.items():
        for path in project_dir.rglob(fname):
            if "node_modules" in path.parts:
                continue
            manifests.append(str(path.relative_to(project_dir)))
            deps.extend(parser(path))
    for eco, name, ver in deps:
        if ver is None:  # 未锁版本：无法比对，列出提示
            findings.append({"ecosystem": eco, "name": name, "version": None,
                             "advisories": [{"id": "UNLOCKED", "title": "未锁版本，无法比对，请锁版本后重扫",
                                             "severity": "low", "fix_version": "-"}]})
            continue
        hits = lookup(eco, name, ver, db)
        if hits:
            findings.append({"ecosystem": eco, "name": name, "version": ver, "advisories": hits})
    return {"deps": deps, "findings": findings, "manifests": manifests}
