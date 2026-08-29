# Security policy

## Supported version

Version 1.x receives security fixes for this portfolio release.

## Reporting a vulnerability

Do not open a public issue containing exploit details, credentials, or real network evidence. Contact the repository owner privately with the affected version, reproduction steps, impact, and a safe proof of concept. Expect acknowledgement within seven days.

## Safe deployment rules

- Use only on networks you own or have explicit authorization to monitor.
- Never expose the development server directly to the internet.
- Replace the demo API key, disable demo mode, and add authenticated TLS termination.
- Keep response in dry-run until rules, protected networks, rollback, and out-of-band access are validated.
- Treat joblib artifacts as executable input. Load only the locally trained, hash-matched artifact and metadata pair.
- Do not commit raw network captures, credentials, or production telemetry.

## Data handling

The evidence store retains network metadata and a sanitized EVE record. Packet/payload/body/auth/cookie fields are removed before persistence. Configure retention and access based on organizational policy and local law.
