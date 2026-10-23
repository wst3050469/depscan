"""DepScan 漏洞库查询：版本解析 + 受影响范围匹配。

版本范围语法（data/vulndb.json 的 affected 字段）：
  "<1.2.6"            只小于该版本
  ">=4.0.0,<4.17.21"  区间（逗号=AND）
  "*"                 全版本
零第三方依赖，Python 3.10+。
"""
from __future__ import annotations

import json
from pathlib import Path

_DB_PATH = Path(__file__).resolve().parent / "data" / "vulndb.json"


def parse_version(v: str) -> tuple:
    """'1.2.3-rc1' -> (1, 2, 3)，预发布后缀忽略（保守：仍参与主版本比较）。"""
    v = v.strip().lstrip("vV")
    parts = []
    for seg in v.split("."):
        num = ""
        for ch in seg:
            if ch.isdigit():
                num += ch
            else:
                break
        parts.append(int(num) if num else 0)
    while len(parts) < 3:
        parts.append(0)
    return tuple(parts[:3])


def _in_range(version: str, range_expr: str) -> bool:
    ver = parse_version(version)
    for cond in range_expr.split(","):
        cond = cond.strip()
        if not cond or cond == "*":
            continue
        for op in ("<=", ">=", "==", "<", ">", "="):
            if cond.startswith(op):
                target = parse_version(cond[len(op):])
                ok = {
                    "<": ver < target, ">": ver > target,
                    "<=": ver <= target, ">=": ver >= target,
                    "==": ver == target, "=": ver == target,
                }[op]
                if not ok:
                    return False
                break
        else:  # 无操作符按 == 处理
            if ver != parse_version(cond):
                return False
    return True


def load_db(path: Path | None = None) -> dict:
    with open(path or _DB_PATH, encoding="utf-8") as f:
        db = json.load(f)
    return {k: v for k, v in db.items() if not k.startswith("_")}


def lookup(ecosystem: str, name: str, version: str, db: dict | None = None) -> list[dict]:
    """查 (生态, 包名, 版本) 命中的漏洞条目列表。"""
    db = db or load_db()
    hits = []
    for adv in db.get(ecosystem, []):
        if adv["name"].lower() != name.lower():
            continue
        try:
            if _in_range(version, adv.get("affected", "*")):
                hits.append(adv)
        except (ValueError, KeyError):
            continue
    return hits
