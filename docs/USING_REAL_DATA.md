# Using real sign-in logs

`detect.py` reads one CSV with one row per sign-in attempt:

```bash
python detect.py --logs data/real/signins.csv --out outputs/real
```

**Only use logs you're authorised to analyse.** Sign-in logs contain personal data. Keep them on approved systems, in `data/real/` (ignored by Git), and delete them when you're done.

## Columns

| Column | Required | Example |
|---|---|---|
| `timestamp` | yes | `2026-10-04 02:10:31` |
| `username` | yes | `aoife.murphy` |
| `src_ip` | yes | `198.51.100.23` |
| `country` | yes | `Ireland` |
| `lat`, `lon` | yes | `53.35`, `-6.26` (city-level is enough) |
| `device_id` | yes | any stable device identifier |
| `app` | yes | `Microsoft 365` |
| `result` | yes | `success` or `failure` |
| `failure_reason` | yes (blank on success) | `Invalid password`, `MFA denied by user` (anything containing "MFA" counts as an MFA denial) |
| `city`, `os`, `mfa_result` | optional | used in reasons and the dashboard |
| `label`, `scenario` | optional | only if you have known incidents to measure against |

The first 14 days are used as the baseline, so provide at least about 4 weeks of logs. Change `baseline_days` in `config/settings.json` if you need to.

## Microsoft Entra ID sign-in logs

1. Export from **Entra admin center → Monitoring → Sign-in logs → Download** (CSV), or use Microsoft Graph (`/auditLogs/signIns`).
2. Map these fields:

| This tool | Entra ID field |
|---|---|
| `timestamp` | `createdDateTime` |
| `username` | `userPrincipalName` |
| `src_ip` | `ipAddress` |
| `country`, `city`, `lat`, `lon` | `location.countryOrRegion`, `location.city`, `location.geoCoordinates` |
| `device_id`, `os` | `deviceDetail.deviceId` (or browser + OS if blank), `deviceDetail.operatingSystem` |
| `app` | `appDisplayName` |
| `result` | `status.errorCode` = 0 → `success`, otherwise `failure` |
| `failure_reason` | `status.failureReason` |

## Windows security events (for example from the Wazuh lab)

Event ID **4624** (successful logon) and **4625** (failed logon) from domain controllers or endpoints give `timestamp`, `username` (TargetUserName), `src_ip` (IpAddress) and `result`. Windows events have no location, so add country and coordinates with a GeoIP lookup, or use a fixed office location for internal IPs. With only local sign-ins, the brute-force, spray and night-time rules still work; impossible travel needs location data.
