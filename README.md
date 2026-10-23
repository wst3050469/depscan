# DepScan — Lightweight Dependency Security Scanner

One command to find poisoned / vulnerable packages in your project. No signup, no CI, no source code upload.

```
python -m depscan ./myproject
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
python -m depscan tests/fixtures       # try the sample project
```

Seed vulnerability database included (daily refresh via OSSVuln planned). License: MIT.
