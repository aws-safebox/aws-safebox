# AWS SafeBox MVP

Local safety wrapper for AI-assisted infrastructure work.

## Status
Day 1 starter scaffold. This version intentionally has no AWS permissions and
does not execute cloud commands automatically.

## Requirements
- macOS
- Python 3.11+
- Git
- Optional: Terraform/OpenTofu for later integration

## Quick start

```bash
cd aws-safebox-mvp
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -U pip
python -m pip install -e ".[dev]"
pytest -q
python -m safebox --help
```

The first implementation focuses on a deterministic policy engine. We will add
AWS/Terraform integrations only after the policy behavior is tested.
