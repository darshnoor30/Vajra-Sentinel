from __future__ import annotations

import argparse
from pathlib import Path

import numpy as np
import pandas as pd


def _positive(rng: np.random.Generator, center: float, sigma: float, size: int) -> np.ndarray:
    return np.maximum(rng.lognormal(np.log(center), sigma, size), 0.001)


def generate(rows: int, seed: int) -> pd.DataFrame:
    """Create deterministic lab data for testing plumbing, never benchmarking quality."""

    rng = np.random.default_rng(seed)
    labels = rng.choice([0, 1], size=rows, p=[0.62, 0.38])
    attack_categories = np.where(
        labels == 0,
        "Normal",
        rng.choice(["Reconnaissance", "Exploits", "DoS", "Backdoors"], size=rows),
    )
    records: list[dict[str, object]] = []
    for label, category in zip(labels, attack_categories, strict=True):
        if label == 0:
            protocol = rng.choice(["tcp", "udp", "icmp"], p=[0.72, 0.25, 0.03])
            service = rng.choice(
                ["http", "https", "dns", "ssh", "-"], p=[0.29, 0.35, 0.2, 0.04, 0.12]
            )
            duration = float(_positive(rng, 1.8, 0.8, 1)[0])
            spkts = int(max(1, rng.poisson(18)))
            dpkts = int(max(0, rng.poisson(16)))
            sbytes = int(_positive(rng, 8_000, 1.0, 1)[0])
            dbytes = int(_positive(rng, 14_000, 1.0, 1)[0])
        elif category == "Reconnaissance":
            protocol, service = "tcp", "-"
            duration = float(rng.uniform(0.005, 0.16))
            spkts, dpkts = int(rng.integers(1, 4)), int(rng.integers(0, 2))
            sbytes, dbytes = int(rng.integers(40, 500)), int(rng.integers(0, 200))
        elif category == "DoS":
            protocol = rng.choice(["tcp", "udp"], p=[0.6, 0.4])
            service = rng.choice(["http", "dns", "-"])
            duration = float(rng.uniform(0.01, 2.5))
            spkts, dpkts = int(rng.integers(300, 5000)), int(rng.integers(0, 40))
            sbytes, dbytes = int(rng.integers(80_000, 6_000_000)), int(rng.integers(0, 20_000))
        elif category == "Backdoors":
            protocol, service = "tcp", rng.choice(["ssh", "-", "https"])
            duration = float(rng.uniform(20, 800))
            spkts, dpkts = int(rng.integers(20, 300)), int(rng.integers(5, 140))
            sbytes, dbytes = int(rng.integers(50_000, 8_000_000)), int(rng.integers(500, 200_000))
        else:  # Exploits
            protocol, service = "tcp", rng.choice(["http", "https", "ftp", "smtp"])
            duration = float(rng.uniform(0.05, 18))
            spkts, dpkts = int(rng.integers(8, 180)), int(rng.integers(1, 80))
            sbytes, dbytes = int(rng.integers(4_000, 900_000)), int(rng.integers(200, 90_000))
        records.append(
            {
                "dur": round(duration, 6),
                "proto": protocol,
                "service": service,
                "spkts": spkts,
                "dpkts": dpkts,
                "sbytes": sbytes,
                "dbytes": dbytes,
                "attack_cat": category,
                "label": int(label),
            }
        )
    return pd.DataFrame(records)


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate synthetic IDS pipeline smoke-test data")
    parser.add_argument("--train-output", type=Path, default=Path("data/demo_train.csv"))
    parser.add_argument("--test-output", type=Path, default=Path("data/demo_test.csv"))
    parser.add_argument("--train-rows", type=int, default=12_000)
    parser.add_argument("--test-rows", type=int, default=4_000)
    args = parser.parse_args()
    if args.train_rows < 1000 or args.test_rows < 500:
        parser.error("Use at least 1,000 training and 500 test rows")
    args.train_output.parent.mkdir(parents=True, exist_ok=True)
    args.test_output.parent.mkdir(parents=True, exist_ok=True)
    generate(args.train_rows, 20260828).to_csv(args.train_output, index=False)
    generate(args.test_rows, 20260829).to_csv(args.test_output, index=False)
    print(f"Wrote {args.train_rows:,} training rows to {args.train_output}")
    print(f"Wrote {args.test_rows:,} test rows to {args.test_output}")
    print("DATA ORIGIN: synthetic-smoke-test (not a performance benchmark)")


if __name__ == "__main__":
    main()
