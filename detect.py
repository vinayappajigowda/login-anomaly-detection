"""Detect suspicious sign-ins.

Usage:
    python detect.py                                  # data/signins.csv -> outputs/
    python detect.py --logs path/to/signins.csv --out outputs/other
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

import pandas as pd

from src.evaluate import evaluate, threshold_tradeoff
from src.features import build_features, load_logs
from src.incidents import build_incidents
from src.model import score
from src.rules import run_rules


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--logs", default="data/signins.csv")
    ap.add_argument("--out", default="outputs")
    ap.add_argument("--config", default="config/settings.json")
    args = ap.parse_args()
    cfg = json.loads(Path(args.config).read_text())
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)

    events, profile = build_features(load_logs(args.logs), cfg["baseline_days"])
    det = events[events["period"] == "detection"]
    print(f"Loaded {len(events):,} sign-ins for {events['username'].nunique()} users, "
          f"{events['timestamp'].min():%d %b} to {events['timestamp'].max():%d %b}")
    print(f"Learning normal behaviour from the first {cfg['baseline_days']} days; "
          f"checking the remaining {len(det):,} sign-ins")

    alerts = run_rules(events, cfg["rules"])
    ml, threshold, base_scores = score(events, profile, cfg["model"])
    incidents = build_incidents(alerts, ml, events)
    print(f"\nRule alerts: {len(alerts)}  |  ML alerts: {int(ml['ml_alert'].sum())} "
          f"(threshold {threshold:.3f})  |  Incidents: {len(incidents)}")

    if len(incidents):
        print("\n=== Incidents (highest severity first) ===")
        show = incidents[["incident_id", "severity", "title", "users", "start", "detected_by"]].head(12).copy()
        show["users"] = show["users"].str.slice(0, 30)
        print(show.to_string(index=False))

    labelled = "label" in events.columns and events["label"].astype(str).isin(["0", "1"]).all()
    metrics = {}
    if labelled:
        events["label"] = events["label"].astype(int)
        res = evaluate(events, alerts, ml, incidents)
        metrics = res["summary"]
        incidents = res["incidents"]
        res["by_scenario"].to_csv(out / "detection_by_scenario.csv", index=False)
        print("\n=== Evaluation against labelled scenarios ===")
        rows = [(m, f"{v['scenarios_detected']}/{v['scenarios_total']}", v["false_positive_events"],
                 v["false_positives_per_day"]) for m, v in metrics.items() if m != "incidents"]
        print(pd.DataFrame(rows, columns=["Method", "Attacks detected", "False-positive events", "FP per day"])
              .to_string(index=False))
        piv = res["by_scenario"].pivot(index="scenario", columns="method", values="detected")
        print("\n" + piv[["Rules", "ML", "Rules + ML"]].replace({True: "yes", False: "-"}).to_string())
        trade = threshold_tradeoff(events, ml, base_scores)
        trade.to_csv(out / "ml_threshold_tradeoff.csv", index=False)
        print("\n=== ML threshold trade-off (attacks the model catches vs false alarms) ===")
        print(trade.to_string(index=False))
        if "incidents" in metrics:
            i = metrics["incidents"]
            print(f"\nIncidents: {i['true_attack']} real attacks, {i['false_positive']} false positives "
                  f"({i['false_positive_per_day']} per day)")

    alerts.to_csv(out / "rule_alerts.csv", index=False)
    ml.merge(events[["event_id", "timestamp", "username", "src_ip", "city", "app"]], on="event_id") \
      .sort_values("anomaly_score", ascending=False).to_csv(out / "ml_scores.csv", index=False)
    incidents.to_csv(out / "incidents.csv", index=False)
    events.to_csv(out / "events_scored.csv", index=False)
    (out / "metrics.json").write_text(json.dumps({"threshold": threshold, **metrics}, indent=2, default=str))
    print(f"\nSaved to {out}/: incidents.csv, rule_alerts.csv, ml_scores.csv, events_scored.csv, metrics.json")


if __name__ == "__main__":
    main()
