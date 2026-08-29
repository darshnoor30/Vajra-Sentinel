# Contributing

1. Open an issue describing the defensive use case, evidence source, false-positive risks, and intended test.
2. Create a focused branch; do not include real credentials, packet captures, or private IP inventories.
3. Add or update tests for every detection or response behavior.
4. Run `make validate` before opening a pull request.
5. For new detections, document the threshold, evidence, limitations, ATT&CK context, and response eligibility.
6. For model changes, preserve the sensor feature contract or version it explicitly; never tune on the independent test set.
7. Response changes must remain reversible, bounded, audited, and dry-run by default.

By contributing, you agree that the work is for authorized defensive use and is licensed under MIT.

