from __future__ import annotations

import hashlib
from pathlib import Path


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def main() -> None:
    root = Path(__file__).resolve().parents[1]
    paths = [
        root / "artifacts" / "model.joblib",
        root / "artifacts" / "model_metadata.json",
        root / "artifacts" / "sbom.cdx.json",
        root / "docs" / "openapi.json",
    ]
    missing = [path for path in paths if not path.is_file()]
    if missing:
        raise SystemExit(f"Cannot checksum missing files: {missing}")
    output = root / "CHECKSUMS.sha256"
    lines = [f"{sha256(path)}  {path.relative_to(root).as_posix()}" for path in paths]
    output.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"Wrote {len(lines)} integrity checksums to {output}")


if __name__ == "__main__":
    main()
