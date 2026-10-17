"""Detection rules: known attack patterns, each mapped to MITRE ATT&CK."""
from __future__ import annotations

import pandas as pd

RULES = {
    "R1_BRUTE_FORCE": dict(name="Brute force", mitre="T1110.001 Password Guessing"),
    "R2_PASSWORD_SPRAY": dict(name="Password spraying", mitre="T1110.003 Password Spraying"),
    "R3_IMPOSSIBLE_TRAVEL": dict(name="Impossible travel", mitre="T1078 Valid Accounts"),
    "R4_MFA_FATIGUE": dict(name="MFA fatigue", mitre="T1621 Multi-Factor Authentication Request Generation"),
    "R5_NEW_COUNTRY_DEVICE": dict(name="New country and new device", mitre="T1078 Valid Accounts"),
    "R6_OFFHOURS_NEW_DEVICE": dict(name="Night-time sign-in from a new device", mitre="T1078 Valid Accounts"),
}


def _alert(rule, severity, user, ip, events, detail):
    return dict(rule_id=rule, rule_name=RULES[rule]["name"], mitre=RULES[rule]["mitre"], severity=severity,
                username=user, src_ip=ip, first_seen=events["timestamp"].min(), last_seen=events["timestamp"].max(),
                event_ids=list(events["event_id"]), detail=detail)


def _windows(times: pd.Series, window: pd.Timedelta, minimum: int, key=None):
    """Yield index slices where at least `minimum` items fall inside `window` (distinct `key` values if given)."""
    t = times.to_numpy()
    k = key.to_numpy() if key is not None else None
    i, used_until = 0, -1
    for j in range(len(t)):
        while t[j] - t[i] > window:
            i += 1
        count = len(set(k[i:j + 1])) if k is not None else j - i + 1
        if count >= minimum and j > used_until:
            end = j
            while end + 1 < len(t) and t[end + 1] - t[i] <= window:
                end += 1
            used_until = end
            yield i, end


def run_rules(df: pd.DataFrame, cfg: dict) -> pd.DataFrame:
    det = df[df["period"] == "detection"]
    fails, ok = det[det["result"] == "failure"], det[det["result"] == "success"]
    alerts = []

    # R1 Brute force: many failures for one account from one IP in a short window
    win = pd.Timedelta(minutes=cfg["brute_force_window_min"])
    pw = fails[~fails["failure_reason"].str.contains("MFA", case=False)]
    for (u, ip), g in pw.groupby(["username", "src_ip"]):
        g = g.sort_values("timestamp")
        for a, b in _windows(g["timestamp"], win, cfg["brute_force_failures"]):
            ev = g.iloc[a:b + 1]
            after = ok[(ok["username"] == u) & (ok["src_ip"] == ip) & (ok["timestamp"] > ev["timestamp"].max())
                       & (ok["timestamp"] <= ev["timestamp"].max() + pd.Timedelta(minutes=30))]
            sev, extra = ("Critical", " and then signed in successfully") if len(after) else ("High", "")
            alerts.append(_alert("R1_BRUTE_FORCE", sev, u, ip, pd.concat([ev, after]),
                                 f"{len(ev)} failed passwords in {cfg['brute_force_window_min']} min{extra}"))

    # R2 Password spray: one IP failing against many different accounts
    win = pd.Timedelta(minutes=cfg["spray_window_min"])
    for ip, g in pw.groupby("src_ip"):
        g = g.sort_values("timestamp")
        for a, b in _windows(g["timestamp"], win, cfg["spray_distinct_users"], key=g["username"]):
            ev = g.iloc[a:b + 1]
            t0, t1 = ev["timestamp"].min(), ev["timestamp"].max()
            hits = ok[(ok["src_ip"] == ip) & (ok["timestamp"] >= t0 - pd.Timedelta(hours=1))
                      & (ok["timestamp"] <= t1 + pd.Timedelta(hours=2))]
            users = ", ".join(sorted(hits["username"].unique()))
            sev = "Critical" if len(hits) else "High"
            detail = f"{ev['username'].nunique()} accounts targeted from one IP in {cfg['spray_window_min']} min"
            alerts.append(_alert("R2_PASSWORD_SPRAY", sev, users or "(multiple)", ip, pd.concat([ev, hits]),
                                 detail + (f"; successful sign-in for {users}" if users else "")))

    # R3 Impossible travel: two successful sign-ins too far apart for the time between them
    for u, g in df[df["result"] == "success"].sort_values("timestamp").groupby("username"):
        g = g.reset_index(drop=True)
        for k in range(1, len(g)):
            cur = g.iloc[k]
            if cur["period"] != "detection":
                continue
            if cur["speed_kmh"] > cfg["travel_max_kmh"]:
                prev = g.iloc[k - 1]
                from .features import haversine
                dist = haversine(prev["lat"], prev["lon"], cur["lat"], cur["lon"])
                if dist >= cfg["travel_min_km"]:
                    mins = (cur["timestamp"] - prev["timestamp"]).total_seconds() / 60
                    alerts.append(_alert("R3_IMPOSSIBLE_TRAVEL", "High", u, cur["src_ip"], g.iloc[[k - 1, k]],
                                         f"{prev['city']} -> {cur['city']}: {dist:,.0f} km in {mins:.0f} min "
                                         f"({cur['speed_kmh']:,.0f} km/h)"))

    # R4 MFA fatigue: repeated MFA denials, then an approval
    win = pd.Timedelta(minutes=cfg["mfa_window_min"])
    mfa = fails[fails["failure_reason"].str.contains("MFA", case=False)]
    for u, g in mfa.groupby("username"):
        g = g.sort_values("timestamp")
        for a, b in _windows(g["timestamp"], win, cfg["mfa_denials"]):
            ev = g.iloc[a:b + 1]
            after = ok[(ok["username"] == u) & (ok["timestamp"] > ev["timestamp"].max())
                       & (ok["timestamp"] <= ev["timestamp"].max() + pd.Timedelta(minutes=30))]
            sev = "Critical" if len(after) else "High"
            alerts.append(_alert("R4_MFA_FATIGUE", sev, u, ev["src_ip"].iloc[0], pd.concat([ev, after]),
                                 f"{len(ev)} MFA prompts denied in {cfg['mfa_window_min']} min"
                                 + (", then approved" if len(after) else "")))

    # R5 / R6 on single successful sign-ins
    night = ok["timestamp"].dt.hour.between(cfg["offhours_start"], cfg["offhours_end"] - 1)
    for _, r in ok[(ok["new_country"] == 1) & (ok["new_device"] == 1)].iterrows():
        alerts.append(_alert("R5_NEW_COUNTRY_DEVICE", "Medium", r["username"], r["src_ip"], ok.loc[[r.name]],
                             f"First sign-in from {r['country']} and from device {r['device_id']} ({r['os']})"))
    for _, r in ok[night & (ok["new_device"] == 1) & (ok["new_country"] == 0)].iterrows():
        alerts.append(_alert("R6_OFFHOURS_NEW_DEVICE", "Medium", r["username"], r["src_ip"], ok.loc[[r.name]],
                             f"Sign-in at {r['timestamp']:%H:%M} from a new device {r['device_id']}"))

    cols = ["rule_id", "rule_name", "mitre", "severity", "username", "src_ip", "first_seen", "last_seen",
            "event_ids", "detail"]
    return pd.DataFrame(alerts, columns=cols)
