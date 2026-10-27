"""Regenerate src/crotalus/data/top_packages.txt for the typosquat rule.

Run with: python scripts/update_top_packages.py

Source: hugovk/top-pypi-packages, a monthly list of PyPI's most downloaded
projects over the last 30 days.
"""

from __future__ import annotations

from datetime import date
from pathlib import Path

import httpx

from crotalus.pypi import normalize_name  # pep normalizer
from crotalus.rules.metadata.typosquat import TOP_PACKAGES_FILE

URL = "https://hugovk.github.io/top-pypi-packages/top-pypi-packages.min.json"
COUNT = 5000


def main() -> None:
    # A one-off download, not PyPI, so a plain httpx.get() is enough.
    response = httpx.get(URL, timeout=30)
    response.raise_for_status()
    rows = response.json()["rows"]  # [{"project": ..., "download_count": ...}, ...]

    # The source is already sorted by downloads; keep that order, drop duplicates
    # that only differ before normalization.
    names = list(dict.fromkeys(normalize_name(row["project"]) for row in rows))[:COUNT]

    header = f"# Top {len(names)} PyPI packages by downloads, most first.\n# Source: {URL}\n"
    header += f"# Generated {date.today()} by scripts/update_top_packages.py\n"
    TOP_PACKAGES_FILE.parent.mkdir(exist_ok=True)
    TOP_PACKAGES_FILE.write_text(header + "\n".join(names) + "\n", encoding="utf-8")
    print(f"Wrote {len(names)} names to {Path(TOP_PACKAGES_FILE)}")


if __name__ == "__main__":
    main()
