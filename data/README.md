# Dataset policy

Vajra Sentinel separates two very different artifacts:

1. **Synthetic smoke-test data** validates that feature engineering, model serialization, hash verification, runtime scoring, and dashboard governance work end to end. Its metrics are never presented as model-quality evidence.
2. **UNSW-NB15 official train/test files** support a reproducible supervised experiment on a recognized IDS dataset. They are not redistributed in this repository because the official files are large and the source controls distribution.

Official source: <https://research.unsw.edu.au/projects/unsw-nb15-dataset>

Expected filenames:

- `data/UNSW_NB15_training-set.csv` — 175,341 records
- `data/UNSW_NB15_testing-set.csv` — 82,332 records

Required columns are `dur`, `proto`, `service`, `spkts`, `dpkts`, `sbytes`, `dbytes`, and `label`. The training code deliberately uses only features that the live Suricata EVE flow adapter can reproduce. This prevents the common portfolio mistake of training on fields that do not exist in production.

After downloading the two official files, run:

```bash
python -m ml.train \
  --train-csv data/UNSW_NB15_training-set.csv \
  --test-csv data/UNSW_NB15_testing-set.csv \
  --data-origin UNSW-NB15-official
```

The output metadata records dataset SHA-256 hashes, exact row counts, runtime versions, the validation-selected threshold, and independent-test metrics.

