from __future__ import annotations

import shutil
from pathlib import Path


def main() -> None:
    root = Path(__file__).resolve().parents[1]
    targets = [
        root / "runtime",
        root / ".pytest_cache",
        root / ".ruff_cache",
        root / ".coverage",
        root / "data" / "demo_train.csv",
        root / "data" / "demo_test.csv",
    ]
    for target in targets:
        if target.is_dir():
            shutil.rmtree(target)
        elif target.is_file():
            target.unlink()
    for target in [*root.rglob("__pycache__"), *root.glob("*.egg-info")]:
        if target.is_dir():
            shutil.rmtree(target)
    print("Removed generated runtime and test-cache files. Model artifacts were preserved.")


if __name__ == "__main__":
    main()
