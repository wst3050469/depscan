"""DepScan 人话报告：三级分级——中招了(严重/高) / 有风险(中) / 没事。"""
from __future__ import annotations

_SEV_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
_SEV_ZH = {"critical": "严重", "high": "高危", "medium": "中危", "low": "提示", "info": "提示"}


def render(scan_result: dict) -> str:
    findings = scan_result["findings"]
    lines = ["=== DepScan 依赖安全体检报告 ===",
             f"清单: {', '.join(scan_result['manifests']) or '未发现'}",
             f"依赖总数: {len(scan_result['deps'])}   有问题: {len(findings)}", ""]
    if not findings:
        lines.append("✅ 没事：未发现已知漏洞或投毒记录。（注意：仅比对内置种子库，不等于绝对安全）")
        return "\n".join(lines)

    bucket = {"bad": [], "warn": [], "info": []}
    for f in findings:
        worst = min(_SEV_RANK.get(a.get("severity", "info"), 4) for a in f["advisories"])
        key = "bad" if worst <= 1 else ("warn" if worst == 2 else "info")
        bucket[key].append(f)

    def _emit(title, items):
        if not items:
            return
        lines.append(title)
        for f in items:
            lines.append(f"  [{f['ecosystem']}] {f['name']}@{f['version']}")
            for a in f["advisories"]:
                lines.append(f"    - {_SEV_ZH.get(a.get('severity', 'info'), '提示')} {a.get('id')}: {a.get('title')}")
                fix = a.get("fix_version", "-")
                lines.append(f"      怎么修: 升级到 {fix}" if fix not in ("-", None)
                             else f"      怎么修: {a.get('summary', '暂无补丁，关注官方公告')}")
        lines.append("")

    _emit("🔴 中招了（严重/高危，尽快修）", bucket["bad"])
    _emit("🟡 有风险（中危，建议排期修）", bucket["warn"])
    _emit("🔵 提示", bucket["info"])
    lines.append("隐私说明: 本次扫描只读取了包名与版本号，未读取、未上传任何源码。")
    return "\n".join(lines)
