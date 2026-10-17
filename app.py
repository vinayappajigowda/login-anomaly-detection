"""Sign-in threat detection dashboard.  Run:  streamlit run app.py"""
import ast
import json
from pathlib import Path

import altair as alt
import pandas as pd
import streamlit as st

st.set_page_config(page_title="Sign-in Threat Detection", layout="wide")
OUT = Path("outputs")
SEV_COLOURS = {"Critical": "#d03b3b", "High": "#ec835a", "Medium": "#fab219", "Low": "#86b6ef"}
SEV_ICON = {"Critical": "🔴", "High": "🟠", "Medium": "🟡", "Low": "🔵"}


@st.cache_data
def load():
    inc = pd.read_csv(OUT / "incidents.csv", parse_dates=["start", "end"], keep_default_na=False)
    inc["event_ids"] = inc["event_ids"].apply(ast.literal_eval)
    ev = pd.read_csv(OUT / "events_scored.csv", parse_dates=["timestamp"], keep_default_na=False)
    metrics = json.loads((OUT / "metrics.json").read_text())
    by_sc = pd.read_csv(OUT / "detection_by_scenario.csv") if (OUT / "detection_by_scenario.csv").exists() else None
    trade = pd.read_csv(OUT / "ml_threshold_tradeoff.csv") if (OUT / "ml_threshold_tradeoff.csv").exists() else None
    return inc, ev, metrics, by_sc, trade


if not (OUT / "incidents.csv").exists():
    st.error("No results yet. Run `python generate_logs.py` and `python detect.py` first.")
    st.stop()

inc, ev, metrics, by_sc, trade = load()
det = ev[ev["period"] == "detection"]
st.title("Sign-in Threat Detection")
st.caption(f"{len(ev):,} sign-ins · {ev['username'].nunique()} users · "
           f"{ev['timestamp'].min():%d %b} – {ev['timestamp'].max():%d %b %Y} · "
           f"first {ev[ev['period'] != 'detection']['timestamp'].dt.normalize().nunique()} days used as the baseline")

c = st.columns(5)
c[0].metric("Sign-ins checked", f"{len(det):,}")
c[1].metric("Incidents", len(inc))
c[2].metric("Critical", int((inc["severity"] == "Critical").sum()))
c[3].metric("High", int((inc["severity"] == "High").sum()))
c[4].metric("Failed sign-ins", f"{int((det['result'] == 'failure').sum()):,}")

# --- Failed sign-ins over time: spraying and brute force show up as spikes ---
st.subheader("Failed sign-ins per hour")
fails = det[det["result"] == "failure"].set_index("timestamp").resample("1h").size().rename("failed").reset_index()
line = alt.Chart(fails).mark_line(strokeWidth=2, color="#2a78d6").encode(
    x=alt.X("timestamp:T", title=None), y=alt.Y("failed:Q", title="Failed sign-ins"),
    tooltip=[alt.Tooltip("timestamp:T", format="%d %b %H:%M"), "failed:Q"])
marks = alt.Chart(inc[inc["severity"].isin(["Critical", "High"])]).mark_rule(strokeDash=[4, 3], color="#52514e").encode(
    x="start:T", tooltip=["incident_id", "severity", "title", "users"])
st.altair_chart((line + marks).properties(height=220), width="stretch")
st.caption("Dashed lines mark Critical and High incidents.")

# --- Incident queue ---
st.subheader("Incident queue")
sev = st.multiselect("Severity", list(SEV_COLOURS), default=list(SEV_COLOURS))
queue = inc[inc["severity"].isin(sev)].copy()
queue.insert(1, " ", queue["severity"].map(SEV_ICON))
st.dataframe(queue[["incident_id", " ", "severity", "title", "users", "source_ips", "start", "detected_by", "mitre",
                    "summary"]], hide_index=True, width="stretch",
             column_config={"start": st.column_config.DatetimeColumn("Start", format="DD MMM HH:mm")})

if len(queue):
    pick = st.selectbox("Investigate incident", queue["incident_id"] + " · " + queue["title"] + " · " + queue["users"])
    row = queue[queue["incident_id"] == pick.split(" · ")[0]].iloc[0]
    st.markdown(f"### {SEV_ICON[row['severity']]} {row['incident_id']}: {row['title']} ({row['severity']})")
    left, right = st.columns([3, 2])
    with left:
        st.markdown(f"**What happened:** {row['summary']}")
        st.markdown(f"**Detected by:** {row['detected_by']} · **MITRE ATT&CK:** {row['mitre']}")
        st.info(f"**Response:** {row['response']}")
        events = ev[ev["event_id"].isin(row["event_ids"])].sort_values("timestamp")
        st.dataframe(events[["timestamp", "username", "result", "failure_reason", "src_ip", "city", "country",
                             "device_id", "os", "app"]], hide_index=True, width="stretch")
    with right:
        users = row["users"].split(", ")
        hist = ev[ev["username"].isin(users) & (ev["result"] == "success") & ~ev["event_id"].isin(row["event_ids"])]
        st.markdown("**Where these accounts usually sign in, vs this incident**")
        pts = pd.concat([hist.assign(kind="Usual sign-ins"), events.assign(kind="This incident")])
        loc = pts.pivot_table(index=["country", "city"], columns="kind", values="event_id", aggfunc="count",
                              fill_value=0).reset_index()
        st.dataframe(loc, hide_index=True, width="stretch")
        devs = pts.pivot_table(index=["device_id", "os"], columns="kind", values="event_id", aggfunc="count",
                               fill_value=0).reset_index()
        st.markdown("**Devices**")
        st.dataframe(devs, hide_index=True, width="stretch")

# --- Evaluation (synthetic data has labels) ---
if by_sc is not None:
    st.subheader("How well does it work?")
    st.caption("The sample data contains six labelled attack scenarios. Labels are used only for this scoring, "
               "never for training.")
    s = metrics
    tbl = pd.DataFrame([(m, f"{v['scenarios_detected']}/{v['scenarios_total']}", v["false_positive_events"],
                         v["false_positives_per_day"]) for m, v in s.items() if m in ("Rules", "ML", "Rules + ML")],
                       columns=["Method", "Attacks detected", "False-positive events", "False positives per day"])
    a, b = st.columns(2)
    a.dataframe(tbl, hide_index=True, width="stretch")
    piv = by_sc.pivot(index="scenario", columns="method", values="detected")[["Rules", "ML", "Rules + ML"]]
    b.dataframe(piv.replace({True: "✅ detected", False: "— missed"}), width="stretch")
    if trade is not None:
        st.markdown("**ML threshold trade-off.** Lowering the threshold doesn't catch more attacks here, it only adds "
                    "false alarms, so the default keeps the alert rate at 0.1% of normal sign-ins.")
        st.dataframe(trade, hide_index=True, width="stretch")
