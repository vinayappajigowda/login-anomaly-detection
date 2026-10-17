"""Tests generate fresh synthetic logs, so they don't depend on files in the repo."""
import json
import sys
from datetime import datetime
from pathlib import Path

import pandas as pd
import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from generate_logs import Builder  # noqa: E402
from src.evaluate import evaluate  # noqa: E402
from src.features import build_features, load_logs  # noqa: E402
from src.incidents import build_incidents  # noqa: E402
from src.model import score  # noqa: E402
from src.rules import run_rules  # noqa: E402

CFG = json.loads((ROOT / "config" / "settings.json").read_text())


def pipeline(tmp_path, seed=42, users=200):
    f = tmp_path / f"logs_{seed}.csv"
    Builder(users, seed, datetime(2026, 10, 15)).build().to_csv(f, index=False)
    events, profile = build_features(load_logs(f), CFG["baseline_days"])
    alerts = run_rules(events, CFG["rules"])
    ml, thr, base = score(events, profile, CFG["model"])
    inc = build_incidents(alerts, ml, events)
    return events, alerts, ml, inc, evaluate(events, alerts, ml, inc)


@pytest.fixture(scope="module")
def run(tmp_path_factory):
    return pipeline(tmp_path_factory.mktemp("logs"))


def detected(res, method):
    t = res["by_scenario"]
    return set(t[(t["method"] == method) & t["detected"]]["scenario"])


def test_rules_catch_known_attack_patterns(run):
    *_, res = run
    assert {"A1_password_spray", "A2_brute_force", "A3_impossible_travel", "A4_mfa_fatigue"} <= detected(res, "Rules")


def test_ml_catches_the_insider_that_rules_miss(run):
    *_, res = run
    assert "A5_offhours_insider" not in detected(res, "Rules")
    assert "A5_offhours_insider" in detected(res, "ML")


def test_combined_beats_either_alone(run):
    *_, res = run
    s = res["summary"]
    assert s["Rules + ML"]["scenarios_detected"] > max(s["Rules"]["scenarios_detected"], s["ML"]["scenarios_detected"])


def test_slow_spray_is_a_known_gap(run):
    *_, res = run
    assert "A6_slow_spray" not in detected(res, "Rules + ML")


def test_business_travel_is_not_impossible_travel(run):
    events, alerts, *_ = run
    travel = alerts[alerts["rule_id"] == "R3_IMPOSSIBLE_TRAVEL"]
    sc = events.set_index("event_id")["scenario"]
    for ids in travel["event_ids"]:
        assert any(sc[i].startswith("A") for i in ids)  # every travel alert involves an attack


def test_false_positives_stay_low(run):
    *_, res = run
    assert res["summary"]["incidents"]["false_positive_per_day"] <= 2.0
    assert res["summary"]["Rules"]["false_positives_per_day"] <= 0.5


def test_spray_incident_is_critical_and_names_the_breached_account(run):
    events, alerts, ml, inc, _ = run
    spray = alerts[alerts["rule_id"] == "R2_PASSWORD_SPRAY"].iloc[0]
    assert spray["severity"] == "Critical"
    victim = events[(events["scenario"] == "A1_password_spray") & (events["result"] == "success")]["username"].iloc[0]
    assert victim in spray["username"]
    assert inc.iloc[0]["severity"] == "Critical"


def test_features_only_look_backwards(run):
    events, *_ = run
    first = events.sort_values("timestamp").groupby("username").head(1)
    assert (first["speed_kmh"] == 0).all() and (first["user_fails_1h"] == 0).all()


@pytest.mark.parametrize("seed", [7, 2024])
def test_other_random_companies(tmp_path, seed):
    *_, res = pipeline(tmp_path, seed=seed, users=250)
    assert res["summary"]["Rules + ML"]["scenarios_detected"] >= 5
