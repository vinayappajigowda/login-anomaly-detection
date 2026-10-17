"""Measure detections against the labelled scenarios (only possible on the synthetic data)."""
from __future__ import annotations

import pandas as pd


def _scenario_table(events, flagged: set, label: str):
    det = events[events["period"] == "detection"]
    rows = []
    for sc, g in det[det["label"] == 1].groupby("scenario"):
        hit = g[g["event_id"].isin(flagged)]
        rows.append(dict(scenario=sc, method=label, detected=len(hit) > 0,
                         minutes_to_detect=round((hit["timestamp"].min() - g["timestamp"].min()).total_seconds() / 60, 1)
                         if len(hit) else None))
    return rows


def evaluate(events: pd.DataFrame, alerts: pd.DataFrame, ml: pd.DataFrame, incidents: pd.DataFrame) -> dict:
    det = events[events["period"] == "detection"]
    rule_ids = {e for lst in alerts["event_ids"] for e in lst} if len(alerts) else set()
    ml_ids = set(ml.loc[ml["ml_alert"], "event_id"])
    attack = set(det.loc[det["label"] == 1, "event_id"])
    benign_odd = set(det.loc[det["scenario"].str.startswith("benign"), "event_id"])
    days = max(det["timestamp"].dt.normalize().nunique(), 1)

    methods = {"Rules": rule_ids, "ML": ml_ids, "Rules + ML": rule_ids | ml_ids}
    scen = []
    summary = {}
    for name, ids in methods.items():
        scen += _scenario_table(events, ids, name)
        fp = ids - attack
        summary[name] = dict(
            scenarios_detected=int(sum(r["detected"] for r in scen if r["method"] == name)),
            scenarios_total=int(det.loc[det["label"] == 1, "scenario"].nunique()),
            attack_events_flagged=len(ids & attack), attack_events=len(attack),
            false_positive_events=len(fp), false_positive_benign_oddities=len(fp & benign_odd),
            false_positives_per_day=round(len(fp) / days, 1))

    inc_fp = 0
    if len(incidents):
        lab = events.set_index("event_id")["label"]
        incidents = incidents.assign(is_attack=[bool(lab[ids].max()) for ids in incidents["event_ids"]])
        inc_fp = int((~incidents["is_attack"]).sum())
        summary["incidents"] = dict(total=len(incidents), true_attack=int(incidents["is_attack"].sum()),
                                    false_positive=inc_fp, false_positive_per_day=round(inc_fp / days, 1))
    return dict(summary=summary, by_scenario=pd.DataFrame(scen), incidents=incidents)


def threshold_tradeoff(events: pd.DataFrame, ml: pd.DataFrame, base_scores, rates=(0.0005, 0.001, 0.002, 0.005, 0.01, 0.02)):
    """How many attacks the ML model catches, and at what false-positive cost, for different thresholds."""
    import numpy as np
    m = ml.merge(events[["event_id", "label", "scenario"]], on="event_id")
    days = max(m.merge(events[["event_id", "timestamp"]], on="event_id")["timestamp"].dt.normalize().nunique(), 1)
    rows = []
    for r in rates:
        thr = float(np.quantile(base_scores, 1 - r))
        hit = m[m["anomaly_score"] > thr]
        rows.append(dict(baseline_alert_rate=r, threshold=round(thr, 3),
                         attacks_detected=int(hit.loc[hit["label"] == 1, "scenario"].nunique()),
                         false_positive_events=int((hit["label"] == 0).sum()),
                         false_positives_per_day=round(float((hit["label"] == 0).sum()) / days, 1)))
    return pd.DataFrame(rows)
