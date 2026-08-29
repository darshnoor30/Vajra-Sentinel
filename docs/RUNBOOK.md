# Operations runbook

## 1. Pre-deployment checklist

- Confirm written authorization and define `HOME_NET`.
- Run Suricata configuration validation with `suricata -T`.
- Record expected traffic rates and high-volume services.
- Set a long random `VAJRA_API_KEY`; never use the demo key on a shared host.
- Set `VAJRA_DEMO_MODE=false`.
- Bind the app to localhost or a management interface behind TLS and authentication.
- Keep `VAJRA_IPS_MODE=dry-run` for the tuning period.
- Restrict EVE file permissions; the application only needs read access.
- Back up the SQLite database or replace it with the approved production store.

## 2. Start and verify

```bash
python -m app.main
curl --fail http://127.0.0.1:8765/api/v1/health
curl --fail http://127.0.0.1:8765/metrics
```

Expected health states:

- `database: ready`
- `eve_sensor: watching` after the configured file exists
- `ml_model: ready` or intentionally `unavailable` in rules-only mode
- `response: dry-run` during validation

## 3. Triage workflow

1. Open the newest incident, not just the loudest raw alert.
2. Check source/destination, time window, flow or Community ID, packet count reference, signature action, and behavior thresholds.
3. Correlate SSH findings with authentication logs; a connection is not a failed login.
4. Correlate beacon findings with endpoint process/network ownership.
5. Search for the source across adjacent systems and identity logs.
6. Record a case note and move the incident to `triaged`.
7. Contain only confirmed, scoped activity.

## 4. Active-response change procedure

1. Obtain change approval and an emergency rollback owner.
2. Review protected networks, management IPs, DNS, VPN, proxies, scanners, and monitoring systems.
3. Run `sudo ./suricata/nftables-setup.sh`.
4. Test one known lab address with a short TTL.
5. Set `VAJRA_IPS_MODE=active` and the exact acknowledgement value.
6. Verify nftables counters and audit records.
7. Revert through the API or delete the dedicated table with the cleanup script.

Never enable active mode on a remote-only host without an out-of-band recovery path.

## 5. Incident rollback

- Revert the block through `DELETE /api/v1/response/blocks/{id}`.
- If the application is unavailable, delete the individual set element with nftables.
- For complete cleanup, run `sudo ./suricata/nftables-cleanup.sh`; it removes only `inet vajra_sentinel`.
- Document the cause, impact, and tuning change.

## 6. Backup and retention

The default evidence database is `runtime/vajra.db`. Stop writes or use SQLite's online backup API before copying. Define retention according to legal, privacy, and incident-response requirements. Raw EVE/PCAP retention is outside this application.

