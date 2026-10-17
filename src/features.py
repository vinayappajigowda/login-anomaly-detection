"""Load sign-in logs and build behaviour features.

Every feature only uses events *before* the one being scored, the same way a
live detector would see the data.
"""
from __future__ import annotations

from collections import defaultdict, deque

import numpy as np
import pandas as pd

REQUIRED = ["timestamp", "username", "src_ip", "country", "lat", "lon", "device_id", "app", "result",
            "failure_reason"]
FEATURES = ["hour_rarity", "is_weekend", "new_device", "new_country", "new_app", "dist_home_km", "speed_kmh",
            "user_fails_1h", "ip_fail_users_1h", "mfa_denied_30m"]


def load_logs(path) -> pd.DataFrame:
    df = pd.read_csv(path, keep_default_na=False)
    missing = [c for c in REQUIRED if c not in df.columns]
    if missing:
        raise ValueError(f"{path} is missing columns: {missing}")
    df["timestamp"] = pd.to_datetime(df["timestamp"])
    df["lat"], df["lon"] = df["lat"].astype(float), df["lon"].astype(float)
    if "event_id" not in df.columns:
        df.insert(0, "event_id", [f"EV{i + 1:06d}" for i in range(len(df))])
    if "mfa_result" not in df.columns:
        df["mfa_result"] = ""
    return df.sort_values("timestamp", kind="stable").reset_index(drop=True)


def haversine(lat1, lon1, lat2, lon2):
    lat1, lon1, lat2, lon2 = map(np.radians, [lat1, lon1, lat2, lon2])
    h = np.sin((lat2 - lat1) / 2) ** 2 + np.cos(lat1) * np.cos(lat2) * np.sin((lon2 - lon1) / 2) ** 2
    return 6371 * 2 * np.arcsin(np.sqrt(h))


def build_features(df: pd.DataFrame, baseline_days: int, warmup_days: int = 5) -> tuple[pd.DataFrame, dict]:
    """Periods: warm-up (learn devices/countries/apps), baseline (train the model), detection."""
    df = df.copy()
    start = df["timestamp"].min().normalize()
    cutoff = start + pd.Timedelta(days=baseline_days)
    warm = start + pd.Timedelta(days=warmup_days)
    df["period"] = np.select([df["timestamp"] < warm, df["timestamp"] < cutoff], ["warmup", "baseline"], "detection")
    df["hour"] = df["timestamp"].dt.hour + df["timestamp"].dt.minute / 60
    df["is_weekend"] = (df["timestamp"].dt.weekday >= 5).astype(int)
    ok = df["result"] == "success"

    # Each user's normal: usual sign-in hour and home location, from baseline successes
    base = df[ok & (df["period"] != "detection")]
    # Usual hours = the person's own window widened to the company's normal day, so a quiet
    # user with only a few sign-ins isn't flagged for logging in at 09:00
    org_from, org_to = np.quantile(base["hour"], 0.02), np.quantile(base["hour"], 0.98)
    profile = {}
    for u, g in base.groupby("username"):
        home = g.groupby(["lat", "lon"]).size().idxmax()
        h = g["hour"].to_numpy()
        profile[u] = dict(hours=h, hour_from=float(min(np.quantile(h, 0.05), org_from)),
                          hour_to=float(max(np.quantile(h, 0.95), org_to)),
                          lat=home[0], lon=home[1])

    n = len(df)
    out = {f: np.zeros(n) for f in FEATURES + ["hour_dev"] if f != "is_weekend"}
    org_hours = base["hour"].to_numpy()

    def near(hours, h):  # share of sign-ins within an hour of h (wrapping round midnight)
        d = np.abs(hours - h)
        return np.minimum(d, 24 - d) <= 1
    seen_dev, seen_cty, seen_app = defaultdict(set), defaultdict(set), defaultdict(set)
    last_ok = {}
    user_fail = defaultdict(deque)        # user -> failure times
    user_mfa = defaultdict(deque)         # user -> MFA denial times
    ip_fail = defaultdict(deque)          # ip -> (time, user)
    hour, minute30 = pd.Timedelta(hours=1), pd.Timedelta(minutes=30)

    for i, r in enumerate(df.itertuples(index=False)):
        t, u, ip = r.timestamp, r.username, r.src_ip
        for q, w in ((user_fail[u], hour), (user_mfa[u], minute30)):
            while q and t - q[0] > w:
                q.popleft()
        q = ip_fail[ip]
        while q and t - q[0][0] > hour:
            q.popleft()
        out["user_fails_1h"][i] = len(user_fail[u])
        out["mfa_denied_30m"][i] = len(user_mfa[u])
        out["ip_fail_users_1h"][i] = len({x[1] for x in q if x[1] != u})  # other accounts failing from this IP

        p = profile.get(u)
        if p:
            # hours outside the person's usual sign-in window
            out["hour_dev"][i] = max(0.0, p["hour_from"] - r.hour, r.hour - p["hour_to"])
            # How unusual this time of day is for this person (smoothed with the company pattern)
            org = near(org_hours, r.hour).mean()
            out["hour_rarity"][i] = -np.log((near(p["hours"], r.hour).sum() + 5 * org + 1e-3) / (len(p["hours"]) + 5))
            out["dist_home_km"][i] = haversine(r.lat, r.lon, p["lat"], p["lon"])
        out["new_device"][i] = r.device_id not in seen_dev[u]
        out["new_country"][i] = r.country not in seen_cty[u]
        out["new_app"][i] = r.app not in seen_app[u]
        if u in last_ok:
            pt, plat, plon = last_ok[u]
            dist = haversine(r.lat, r.lon, plat, plon)
            hrs = max((t - pt).total_seconds() / 3600, 0.05)
            out["speed_kmh"][i] = dist / hrs if dist > 50 else 0

        if r.result == "success":
            seen_dev[u].add(r.device_id)
            seen_cty[u].add(r.country)
            seen_app[u].add(r.app)
            last_ok[u] = (t, r.lat, r.lon)
        else:
            user_fail[u].append(t)
            ip_fail[ip].append((t, u))
            if "mfa" in str(r.failure_reason).lower():
                user_mfa[u].append(t)

    for f, v in out.items():
        df[f] = v
    # Everything is "new" in the warm-up days, so novelty only counts after that
    for f in ["new_device", "new_country", "new_app"]:
        df.loc[df["period"] == "warmup", f] = 0
    return df, profile
