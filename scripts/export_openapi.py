from __future__ import annotations

import json
from pathlib import Path

from app.main import app


def main() -> None:
    output = Path(__file__).resolve().parents[1] / "docs" / "openapi.json"
    output.write_text(json.dumps(app.openapi(), indent=2) + "\n", encoding="utf-8")
    print(f"Wrote OpenAPI {app.version} contract to {output}")


if __name__ == "__main__":
    main()
