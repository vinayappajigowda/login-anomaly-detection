"""Behavioural anomaly detection with an Isolation Forest.

Unsupervised: the model is fitted on all successful sign-ins (no labels) and
isolates the ones that are easy to separate from the rest. The alert threshold
is set so that only a small share of baseline-period sign-ins (0.1% by default)
would have alerted, which keeps the false-positive budget explicit.
"""
from __future__ import annotations

import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest

from .features import FEATURES


def _matrix(df: pd.DataFrame) -> np.ndarray:
    x = df[FEATURES].astype(float).copy()
    # One or two typos, or a colleague's typo on the shared office IP, are normal: only count beyond that
    for c in ["user_fails_1h", "ip_fail_users_1h", "mfa_denied_30m"]:
        x[c] = (x[c] - 2).clip(lower=0)
    for c in ["dist_home_km", "speed_kmh", "user_fails_1h", "ip_fail_users_1h", "mfa_denied_30m"]:
        x[c] = np.log1p(x[c])
    return x.to_numpy()


def explain(r: pd.Series, profile: dict) -> str:
    """Plain-English reasons, from the features that look unusual."""
    why = []
    p = profile.get(r["username"])
    if r["hour_dev"] >= 2 and p:
        fmt = lambda h: f"{int(h):02d}:{int(h % 1 * 60):02d}"  # noqa: E731
        why.append(f"signed in at {r['timestamp']:%H:%M}, usually {fmt(p['hour_from'])}-{fmt(p['hour_to'])}")
    elif r["hour_rarity"] >= 3.5:
        why.append(f"unusual time of day for this person ({r['timestamp']:%H:%M})")
    if r["is_weekend"]:
        why.append("weekend")
    if r["new_device"]:
        why.append(f"new device ({r['os']})")
    if r["new_country"]:
        why.append(f"first time in {r['country']}")
    if r["new_app"]:
        why.append(f"first use of {r['app']}")
    if r["dist_home_km"] >= 500:
        why.append(f"{r['dist_home_km']:,.0f} km from usual location")
    if r["speed_kmh"] >= 900:
        why.append(f"would need {r['speed_kmh']:,.0f} km/h travel")
    if r["user_fails_1h"] >= 3:
        why.append(f"{int(r['user_fails_1h'])} failed attempts in the last hour")
    if r["ip_fail_users_1h"] >= 3:
        why.append(f"IP failed against {int(r['ip_fail_users_1h'])} accounts in the last hour")
    if r["mfa_denied_30m"] >= 2:
        why.append(f"{int(r['mfa_denied_30m'])} MFA denials just before")
    return "; ".join(why) or "unusual combination of behaviour"


def score(df: pd.DataFrame, profile: dict, cfg: dict) -> tuple[pd.DataFrame, float, np.ndarray]:
    ok = df[df["result"] == "success"]
    model = IsolationForest(n_estimators=cfg["n_estimators"], random_state=cfg["random_state"], contamination="auto")
    model.fit(_matrix(ok[ok["period"] != "warmup"]))
    base_scores = -model.score_samples(_matrix(ok[ok["period"] == "baseline"]))
    threshold = float(np.quantile(base_scores, 1 - cfg["baseline_alert_rate"]))

    det = ok[ok["period"] == "detection"].copy()
    det["anomaly_score"] = -model.score_samples(_matrix(det))
    det["ml_alert"] = det["anomaly_score"] > threshold
    det["ml_reason"] = ""
    det.loc[det["ml_alert"], "ml_reason"] = det[det["ml_alert"]].apply(explain, axis=1, profile=profile)
    return det[["event_id", "anomaly_score", "ml_alert", "ml_reason"]], threshold, base_scores
