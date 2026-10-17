"""Generate 30 days of realistic, made-up sign-in logs for a 200-person company.

Normal behaviour: office and home logins in working hours, the odd typo, some
weekend work. Benign oddities that a good detector should NOT alert on:
business trips, a new phone, people working late. Six labelled attack
scenarios are planted in the second half of the month.

All IP addresses come from reserved documentation ranges (RFC 5737) and the
private 10.0.0.0/8 range, so none belong to real organisations.

Usage:
    python generate_logs.py                      # writes data/signins.csv
    python generate_logs.py --seed 7 --users 300 --out data/other.csv
"""
from __future__ import annotations

import argparse
import random
from datetime import datetime, timedelta
from math import asin, cos, radians, sin, sqrt

import pandas as pd

CITIES = {  # city: (country, lat, lon)
    "Dublin": ("Ireland", 53.35, -6.26), "Cork": ("Ireland", 51.90, -8.47),
    "Galway": ("Ireland", 53.27, -9.05), "Limerick": ("Ireland", 52.66, -8.63),
    "London": ("United Kingdom", 51.51, -0.13), "Paris": ("France", 48.86, 2.35),
    "New York": ("United States", 40.71, -74.01), "Bengaluru": ("India", 12.97, 77.59),
    "Amsterdam": ("Netherlands", 52.37, 4.90), "Sao Paulo": ("Brazil", -23.55, -46.63),
    "Lagos": ("Nigeria", 6.52, 3.38), "Singapore": ("Singapore", 1.35, 103.82),
    "Bucharest": ("Romania", 44.43, 26.10),
}
HOME_SPLIT = [("Dublin", 0.70), ("Cork", 0.12), ("Galway", 0.08), ("Limerick", 0.05), ("London", 0.05)]
OFFICE_IP = {"Dublin": "10.10.1.", "Cork": "10.20.1.", "Galway": "10.30.1.", "Limerick": "10.40.1.", "London": "10.50.1."}
APPS_ALL = ["Microsoft 365"]
APPS_OPT = ["VPN", "Salesforce", "Workday", "ServiceNow", "SAP", "AWS Console"]
OS = ["Windows 11", "Windows 11", "macOS", "iOS", "Android"]
FIRST = ["aoife", "ciaran", "niamh", "sean", "siobhan", "liam", "grace", "conor", "emma", "darragh", "sarah",
         "jack", "orla", "eoin", "ciara", "ryan", "chloe", "adam", "roisin", "mark", "priya", "arjun", "mei",
         "tomasz", "ana", "lucas", "fatima", "omar", "zoe", "daniel"]
LAST = ["murphy", "kelly", "byrne", "ryan", "obrien", "walsh", "osullivan", "doyle", "mccarthy", "gallagher",
        "kennedy", "lynch", "murray", "quinn", "moore", "nolan", "sharma", "kowalski", "silva", "chen", "nair"]


def km(a: str, b: str) -> float:
    _, la1, lo1 = CITIES[a]
    _, la2, lo2 = CITIES[b]
    la1, lo1, la2, lo2 = map(radians, [la1, lo1, la2, lo2])
    h = sin((la2 - la1) / 2) ** 2 + cos(la1) * cos(la2) * sin((lo2 - lo1) / 2) ** 2
    return 6371 * 2 * asin(sqrt(h))


class Builder:
    def __init__(self, n_users: int, seed: int, end: datetime, days: int = 30):
        self.rnd = random.Random(seed)
        self.start = (end - timedelta(days=days)).replace(hour=0, minute=0, second=0, microsecond=0)
        self.days = days
        self.rows = []
        self.users = self._make_users(n_users)

    # ---------- helpers ----------
    def _make_users(self, n):
        rnd, users, seen = self.rnd, [], set()
        while len(users) < n:
            u = f"{rnd.choice(FIRST)}.{rnd.choice(LAST)}"
            if u in seen:
                continue
            seen.add(u)
            city = rnd.choices([c for c, _ in HOME_SPLIT], [w for _, w in HOME_SPLIT])[0]
            devices = [(f"dev-{rnd.randint(10000, 99999)}", rnd.choice(OS)) for _ in range(rnd.choice([1, 1, 2]))]
            users.append(dict(username=u, city=city, start_hour=rnd.gauss(8.5, 0.7), devices=devices,
                              apps=APPS_ALL + rnd.sample(APPS_OPT, rnd.randint(1, 3)),
                              home_ip=f"198.51.100.{rnd.randint(1, 254)}", weekend=rnd.random() < 0.08))
        return users

    def add(self, ts, user, ip, city, device, app, result="success", reason="", mfa="passed",
            label=0, scenario="normal"):
        country, lat, lon = CITIES[city]
        self.rows.append(dict(timestamp=ts.replace(microsecond=0), username=user, src_ip=ip, city=city,
                              country=country, lat=lat, lon=lon, device_id=device[0], os=device[1], app=app,
                              result=result, failure_reason=reason, mfa_result=mfa, label=label, scenario=scenario))

    def normal_day(self, u, day, city=None, ip=None, scenario="normal", late=False):
        rnd = self.rnd
        city = city or u["city"]
        start = day + timedelta(hours=u["start_hour"] + rnd.gauss(0, 0.4))
        n = max(1, int(rnd.expovariate(1 / 3)) + 1)
        times = sorted(start + timedelta(minutes=rnd.uniform(0, 540)) for _ in range(n))
        if late:
            times.append(day + timedelta(hours=rnd.uniform(21.5, 23.5)))
        for t in times:
            at_office = ip is None and rnd.random() < 0.6
            src = ip or (OFFICE_IP[u["city"]] + str(rnd.randint(2, 250)) if at_office else u["home_ip"])
            dev = rnd.choice(u["devices"])
            app = rnd.choice(u["apps"])
            if rnd.random() < 0.04:  # typo first
                self.add(t - timedelta(seconds=rnd.randint(10, 60)), u["username"], src, city, dev, app,
                         "failure", "Invalid password", "", scenario=scenario)
            self.add(t, u["username"], src, city, dev, app, mfa="not required" if at_office else "passed",
                     scenario=scenario)

    def day(self, i):
        return self.start + timedelta(days=i)

    # ---------- build ----------
    def build(self) -> pd.DataFrame:
        rnd, U = self.rnd, self.users
        special = rnd.sample(range(len(U)), 16)
        trav, newphone, late, spray_win, brute, travel_atk, mfa_atk, insider = (
            special[0:4], special[4], special[5:7], special[7], special[8], special[9], special[10], special[11])
        # The impossible-travel victim must use AWS; the insider must NOT normally use SAP
        if "AWS Console" not in U[travel_atk]["apps"]:
            U[travel_atk]["apps"].append("AWS Console")
        U[insider]["apps"] = [a for a in U[insider]["apps"] if a != "SAP"]
        weekdays = [d for d in range(15, self.days) if self.day(d).weekday() < 5]
        phone_day, late_days = weekdays[2], weekdays[1:8:3]
        trips = {}
        for k, i in enumerate(trav):
            dest = ["London", "Paris", "New York", "Bengaluru"][k]
            first = rnd.choice(weekdays[:6])
            trips[i] = (dest, first, first + rnd.randint(2, 4))

        for d in range(self.days):
            day = self.day(d)
            for i, u in enumerate(U):
                if i == newphone and d == phone_day:
                    u["devices"].append((f"dev-{rnd.randint(10000, 99999)}", "iOS"))
                    self.normal_day(u, day, scenario="benign_new_device")
                    continue
                if day.weekday() >= 5:
                    if u["weekend"] and rnd.random() < 0.3:
                        self.normal_day(u, day)
                    continue
                if rnd.random() > 0.92:
                    continue  # day off
                if i in trips and trips[i][1] <= d <= trips[i][2]:
                    dest, first, last = trips[i]
                    if d == first:  # morning at home, then fly, then sign in on arrival
                        t = day + timedelta(hours=7)
                        self.add(t, u["username"], u["home_ip"], u["city"], u["devices"][0], "Microsoft 365",
                                 scenario="benign_travel")
                        arrive = t + timedelta(hours=km(u["city"], dest) / 800 + 3)
                        self.add(arrive, u["username"], f"192.0.2.{10 + i % 200}", dest, u["devices"][0],
                                 "Microsoft 365", scenario="benign_travel")
                    else:
                        self.normal_day(u, day, city=dest, ip=f"192.0.2.{10 + i % 200}", scenario="benign_travel")
                    continue
                self.normal_day(u, day, late=(i in late and d in late_days),
                                scenario="benign_late_work" if (i in late and d in late_days) else "normal")

        self._attacks(U, spray_win, brute, travel_atk, mfa_atk, insider, special[12:16])
        df = pd.DataFrame(self.rows).sort_values("timestamp").reset_index(drop=True)
        df.insert(0, "event_id", [f"EV{i + 1:06d}" for i in range(len(df))])
        return df

    def _attacks(self, U, spray_win, brute, travel_atk, mfa_atk, insider, slow_targets):
        rnd = self.rnd
        atk_dev = lambda: (f"dev-{rnd.randint(10000, 99999)}", rnd.choice(["Windows 10", "Linux"]))  # noqa: E731

        # A1 Password spray: one IP, one password, 60 accounts in 25 minutes at night; one account falls
        t = self.day(19).replace(hour=2, minute=10)
        victims = rnd.sample([u for k, u in enumerate(U) if k != spray_win], 59) + [U[spray_win]]
        rnd.shuffle(victims)
        ip, dev = "203.0.113.50", atk_dev()
        for v in victims:
            t += timedelta(seconds=rnd.randint(15, 35))
            ok = v is U[spray_win]
            self.add(t, v["username"], ip, "Amsterdam", dev, "Microsoft 365", "success" if ok else "failure",
                     "" if ok else "Invalid password", "not required" if ok else "",
                     label=1, scenario="A1_password_spray")
        for m in (4, 9, 15):  # attacker reads the mailbox after getting in
            self.add(t + timedelta(minutes=m), U[spray_win]["username"], ip, "Amsterdam", dev, "Microsoft 365",
                     mfa="not required", label=1, scenario="A1_password_spray")

        # A2 Brute force on one account, then success
        u, ip, dev = U[brute], "203.0.113.77", atk_dev()
        t = self.day(22).replace(hour=13, minute=5)
        for _ in range(35):
            t += timedelta(seconds=rnd.randint(5, 20))
            self.add(t, u["username"], ip, "Sao Paulo", dev, "Microsoft 365", "failure", "Invalid password", "",
                     label=1, scenario="A2_brute_force")
        self.add(t + timedelta(seconds=30), u["username"], ip, "Sao Paulo", dev, "Microsoft 365",
                 label=1, scenario="A2_brute_force")

        # A3 Impossible travel: normal morning in Ireland, then sign-ins from Lagos 45 minutes later
        u = U[travel_atk]
        t = self.day(24).replace(hour=9, minute=12)
        self.add(t, u["username"], u["home_ip"], u["city"], u["devices"][0], "Microsoft 365")
        ip, dev = "203.0.113.120", atk_dev()
        for m, app in [(45, "Microsoft 365"), (52, "AWS Console"), (70, "AWS Console"), (95, "Microsoft 365")]:
            self.add(t + timedelta(minutes=m), u["username"], ip, "Lagos", dev, app,
                     label=1, scenario="A3_impossible_travel")

        # A4 MFA fatigue: correct password, push requests denied again and again, then approved
        u, ip, dev = U[mfa_atk], "203.0.113.200", atk_dev()
        t = self.day(26).replace(hour=23, minute=40)
        for _ in range(8):
            t += timedelta(seconds=rnd.randint(40, 100))
            self.add(t, u["username"], ip, "Singapore", dev, "Microsoft 365", "failure", "MFA denied by user",
                     "denied", label=1, scenario="A4_mfa_fatigue")
        self.add(t + timedelta(minutes=2), u["username"], ip, "Singapore", dev, "Microsoft 365",
                 label=1, scenario="A4_mfa_fatigue")

        # A5 Insider-style misuse: own laptop, home IP, but 3am on a Sunday and an app they never use
        u = U[insider]
        sunday = next(self.day(d) for d in range(20, 30) if self.day(d).weekday() == 6)
        t = sunday.replace(hour=3, minute=40)
        for m, app in [(0, "VPN"), (4, "SAP"), (21, "SAP"), (48, "SAP")]:
            self.add(t + timedelta(minutes=m), u["username"], u["home_ip"], u["city"], u["devices"][0], app,
                     label=1, scenario="A5_offhours_insider")

        # A6 Low-and-slow spray: 15 accounts over 3 days, 5 a day, spaced hours apart (meant to evade rules)
        ip, dev = "203.0.113.90", atk_dev()
        targets = rnd.sample(U, 15)
        for k, v in enumerate(targets):
            t = self.day(15 + k // 5).replace(hour=1 + (k % 5) * 4, minute=rnd.randint(0, 59))
            self.add(t, v["username"], ip, "Bucharest", dev, "Microsoft 365", "failure", "Invalid password", "",
                     label=1, scenario="A6_slow_spray")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default="data/signins.csv")
    ap.add_argument("--users", type=int, default=200)
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--end", default="2026-10-15", help="Last day of the log (YYYY-MM-DD)")
    args = ap.parse_args()
    df = Builder(args.users, args.seed, datetime.fromisoformat(args.end)).build()
    df.to_csv(args.out, index=False)
    att = df[df["label"] == 1]
    print(f"Wrote {args.out}: {len(df):,} sign-in events, {df['username'].nunique()} users, "
          f"{len(att)} attack events in {att['scenario'].nunique()} scenarios")
    print(df["scenario"].value_counts().to_string())


if __name__ == "__main__":
    main()
