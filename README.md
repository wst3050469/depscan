# DepScan — Lightweight Dependency Security Scanner

One command to find poisoned / vulnerable packages in your project. No signup, no CI, no source code upload.

**Download (official site):** https://ad.lingjing.wang/depscan · 中文文档见 `docs/README_zh.md`

```
python dep-scan-cli.py ./myproject
```

Supports: npm (package.json) · pip (requirements.txt) · Go (go.mod)

## Sample output
```
=== DepScan Dependency Security Report ===
🔴 COMPROMISED (critical/high — fix now)
  [pypi] litellm@1.53.1
    - CRITICAL PYPI-2026-LITELLM: LiteLLM PyPI supply-chain poisoning
      Fix: upgrade to 1.53.2
🟡 AT RISK (medium)
🔵 NOTES
```

## Why
2026 supply-chain attacks (PyPI poisoning, compromised CAs) hit small teams hardest — no security staff, no budget for enterprise suites. DepScan is: local-first, zero-config, human-readable.

## Privacy
Only package names and versions are read. Your source code never leaves your machine.

## Install & Test
```bash
python -m unittest discover -s tests   # 11 tests
python dep-scan-cli.py tests/fixtures       # try the sample project
```

Vulnerability database: 1,043 real records (736 PyPI / 267 npm / 40 Go, incl. supply-chain poisoning entries), refreshed weekly from the public OSV feed via `python refresh_db.py`. License: MIT.
