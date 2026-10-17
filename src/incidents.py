"""Group rule and ML alerts into incidents an analyst can triage."""
from __future__ import annotations

import pandas as pd

SEV_RANK = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}
PLAYBOOK = {
    "R1_BRUTE_FORCE": "Block the source IP. If a sign-in succeeded: reset the password, revoke sessions, "
                      "check mailbox rules and recent activity.",
    "R2_PASSWORD_SPRAY": "Block the source IP. For any account that signed in: reset the password, revoke sessions, "
                         "review activity. Check that targeted accounts have MFA.",
    "R3_IMPOSSIBLE_TRAVEL": "Contact the user to confirm. If it wasn't them: revoke sessions, reset the password, "
                            "review what the session accessed (e.g. cloud console actions).",
    "R4_MFA_FATIGUE": "The attacker knows the password. Revoke sessions, reset the password, turn on MFA "
                      "number matching, and tell the user never to approve prompts they didn't start.",
    "R5_NEW_COUNTRY_DEVICE": "Check with the user (travel? new laptop?). If not confirmed, treat as compromise.",
    "R6_OFFHOURS_NEW_DEVICE": "Check with the user or their manager; review what was accessed.",
    "ML_ANOMALY": "Review the reasons and the user's recent activity; confirm with the user or manager.",
}


def build_incidents(alerts: pd.DataFrame, ml: pd.DataFrame, events: pd.DataFrame,
                    gap: pd.Timedelta = pd.Timedelta(hours=6)) -> pd.DataFrame:
    ev = events.set_index("event_id")
    items = []
    for a in alerts.itertuples():
        key = f"ip:{a.src_ip}" if a.rule_id == "R2_PASSWORD_SPRAY" else a.username
        items.append(dict(key=key, user=a.username, ip=a.src_ip, start=a.first_seen, end=a.last_seen,
                          source="rule", rule_id=a.rule_id, name=a.rule_name, mitre=a.mitre, severity=a.severity,
                          detail=a.detail, event_ids=list(a.event_ids)))
    for m in ml[ml["ml_alert"]].itertuples():
        r = ev.loc[m.event_id]
        items.append(dict(key=r["username"], user=r["username"], ip=r["src_ip"], start=r["timestamp"],
                          end=r["timestamp"], source="ml", rule_id="ML_ANOMALY", name="Behaviour anomaly (ML)",
                          mitre="T1078 Valid Accounts", severity="Medium" if m.anomaly_score >= 0.8 else "Low",
                          detail=f"score {m.anomaly_score:.2f}: {m.ml_reason}", event_ids=[m.event_id]))
    if not items:
        return pd.DataFrame()
    items = pd.DataFrame(items).sort_values("start")

    # A spray incident also absorbs alerts for the accounts it broke into
    spray_users = {u: k for k, u in zip(items["key"], items["user"]) if k.startswith("ip:")}
    for u_list, k in list(spray_users.items()):
        for u in str(u_list).split(", "):
            items.loc[items["key"] == u, "key"] = k

    incidents = []
    for key, g in items.groupby("key"):
        group, last = [], None
        for r in g.itertuples():
            if last is not None and r.start - last > gap:
                incidents.append(group)
                group = []
            group.append(r)
            last = max(last, r.end) if last is not None else r.end
        incidents.append(group)

    rows = []
    for grp in incidents:
        g = pd.DataFrame([x._asdict() for x in grp])
        sev = min(g["severity"], key=SEV_RANK.get)
        top = g.sort_values("severity", key=lambda s: s.map(SEV_RANK)).iloc[0]
        ids = sorted({e for lst in g["event_ids"] for e in lst})
        rows.append(dict(
            severity=sev, title=top["name"], users=", ".join(sorted(set(g["user"]))),
            source_ips=", ".join(sorted(set(g["ip"]))), start=g["start"].min(), end=g["end"].max(),
            detections=", ".join(dict.fromkeys(g["name"])), mitre=", ".join(dict.fromkeys(g["mitre"])),
            detected_by=" + ".join(sorted(set(g["source"]))), events=len(ids),
            summary=" | ".join(dict.fromkeys(g["detail"])), response=PLAYBOOK[top["rule_id"]], event_ids=ids))
    out = pd.DataFrame(rows)
    out["_r"] = out["severity"].map(SEV_RANK)
    out = out.sort_values(["_r", "start"]).drop(columns="_r").reset_index(drop=True)
    out.insert(0, "incident_id", [f"INC-{i + 1:03d}" for i in range(len(out))])
    return out
