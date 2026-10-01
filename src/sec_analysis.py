#!/usr/bin/env python3
"""
Summarize the hand-coded SEC Form 8-K cybersecurity incidents (Dec 18, 2023 - Dec 31, 2025).

  python3 src/sec_analysis.py

Inputs
  data/sec/sec_8k_filings.csv     raw collector output (src/sec_8k_collect.py)
  data/sec/sec_screening.csv      one row per filing: incident, update of an incident, or excluded
  data/sec/sec_incident_codes.csv one row per incident, hand-coded with the VCDB codebook
Outputs
  results/sec/sec_results.json, results/sec/sec_summary.txt

Two counting rules mirror the VCDB analysis:
  incident  one row per disclosing company and incident (68)
  event     the four dealers hit by the June 2024 CDK Global outage merged into one event,
            coded CLOUD / THIRD_PARTY because three of the four filings describe CDK's
            system as hosted or software-as-a-service (65)
"""
import csv, json, os, collections, math
from scipy.stats import fisher_exact

D = "data/sec"
OUT = "results/sec"
ORDER = ["PHYSICAL", "THIRD_PARTY", "INSIDER", "UNPATCHED", "MISCONFIG", "CREDENTIAL", "OTHER"]
CAMPAIGN_CODES = {"CDK": ("CLOUD", "THIRD_PARTY")}

def wilson(k, n, z=1.96):
    if n == 0:
        return (0.0, 0.0)
    p = k / n
    d = 1 + z * z / n
    c = (p + z * z / (2 * n)) / d
    h = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    return (round(c - h, 3), round(c + h, 3))

def summarize(rows, root_key):
    n = len(rows)
    env = collections.Counter(r["infra"] for r in rows)
    det = n - env["UND"]
    root = collections.Counter(r[root_key] for r in rows)
    by_env = {e: dict(collections.Counter(r[root_key] for r in rows if r["infra"] == e))
              for e in ("CLOUD", "ONPREM", "UND")}
    return {
        "n": n, "env": dict(env), "determinable": det,
        "determinable_share": round(det / n, 3), "determinable_ci95": wilson(det, n),
        "root_cause": {k: root.get(k, 0) for k in ORDER},
        "root_cause_stated": n - root.get("OTHER", 0),
        "root_cause_stated_share": round((n - root.get("OTHER", 0)) / n, 3),
        "root_by_env": by_env,
    }

def main():
    os.makedirs(OUT, exist_ok=True)
    filings = list(csv.DictReader(open(f"{D}/sec_8k_filings.csv", encoding="utf-8")))
    screen = list(csv.DictReader(open(f"{D}/sec_screening.csv", encoding="utf-8")))
    codes = list(csv.DictReader(open(f"{D}/sec_incident_codes.csv", encoding="utf-8")))
    assert len(screen) == len(filings), "screening log must cover every filing"

    status = collections.Counter(s["screening_result"].split(":")[0].split(" of")[0] for s in screen)
    flow = {
        "filings": len(filings),
        "companies": len({f["company"] for f in filings}),
        "item_1_05_filings": sum(f["disclosure_type"] == "1.05" for f in filings),
        "item_8_01_filings": sum(f["disclosure_type"] == "8.01" for f in filings),
        "incident_first_filings": status["incident (first filing)"],
        "update_filings": status["update"],
        "excluded_filings": status["excluded"],
        "incidents": len(codes),
        "incidents_ever_item_1_05": sum(c["ever_1_05"] == "Y" for c in codes),
    }

    inc = [{"infra": c["coderA_infra"], "root": c["coderA_root_cause"],
            "alt": c["alt_root_cause"], "campaign": c["coderA_campaign"]} for c in codes]
    ev, seen = [], set()
    for r in inc:
        k = r["campaign"]
        if k in CAMPAIGN_CODES:
            if k in seen:
                continue
            seen.add(k)
            env, root = CAMPAIGN_CODES[k]
            ev.append({"infra": env, "root": root, "alt": root, "campaign": k})
        else:
            ev.append(r)

    res = {"flow": flow,
           "incidents": summarize(inc, "root"),
           "incidents_alt_order": summarize(inc, "alt")["root_cause"],
           "events": summarize(ev, "root"),
           "events_alt_order": summarize(ev, "alt")["root_cause"]}

    # comparison with VCDB under the hand rule (B): 202 events, environment from structured
    # fields plus hand coding of the 163 events the fields left unclassified
    try:
        a = json.load(open("results/analysis_results.json"))
        vn = a["B_hand_events"]
        vt = a["B_hand_table"]
        vcl, vop = sum(vt["CLOUD"].values()), sum(vt["ONPREM"].values())
        # root causes as in Tables IV-V: the coder's codes for hand-coded events,
        # structured-field codes (with campaign codes) for the rest
        hc = {r["incident_id"]: r for r in csv.DictReader(open("data/hand_codes/hand_codes_all.csv", encoding="utf-8"))}
        vroot = collections.Counter(
            hc[r["incident_id"]]["coderA_root_cause"] if r["hand_infra"] == "REVIEW" else r["hand_root_cause"]
            for r in csv.DictReader(open("results/hand/events_hand.csv", encoding="utf-8")))
        s = res["events"]
        sd, sn = s["determinable"], s["n"]
        scl, sop = s["env"].get("CLOUD", 0), s["env"].get("ONPREM", 0)
        smis, sst = s["root_cause"]["MISCONFIG"], s["root_cause_stated"]
        vst = vn - vroot["OTHER"]
        cmp = {
            "vcdb_events": vn,
            "determinable": {"sec": [sd, sn], "vcdb": [vcl + vop, vn],
                             "fisher_p": fisher_exact([[sd, sn - sd], [vcl + vop, vn - vcl - vop]])[1]},
            "cloud_share_of_determinable": {"sec": [scl, scl + sop], "vcdb": [vcl, vcl + vop],
                             "fisher_p": fisher_exact([[scl, sop], [vcl, vop]])[1]},
            "root_cause_stated": {"sec": [sst, sn], "vcdb": [vst, vn],
                             "fisher_p": fisher_exact([[sst, sn - sst], [vst, vn - vst]])[1]},
            "misconfiguration": {"sec": [smis, sn], "vcdb": [vroot["MISCONFIG"], vn],
                             "fisher_p": fisher_exact([[smis, sn - smis], [vroot["MISCONFIG"], vn - vroot["MISCONFIG"]]])[1]},
        }
        for v in cmp.values():
            if isinstance(v, dict):
                v["fisher_p"] = float(f"{v['fisher_p']:.2g}")
                v["sec_ci95"], v["vcdb_ci95"] = wilson(*v["sec"]), wilson(*v["vcdb"])
        res["vs_vcdb_rule_B"] = cmp
    except FileNotFoundError:
        pass

    # disclosed costs
    cost = [c for c in codes if c["disclosed_cost_low_usd"]]
    res["costs"] = {
        "incidents_with_dollar_figure": len(cost),
        "incidents_mentioning_unquantified_expense": sum(
            ("expense" in c["notes"].lower() and not c["disclosed_cost_low_usd"]) for c in codes),
        "items": [{"company": c["company"], "low": int(c["disclosed_cost_low_usd"]),
                   "high": int(c["disclosed_cost_high_usd"]), "what": c["notes"]} for c in cost],
    }

    json.dump(res, open(f"{OUT}/sec_results.json", "w"), indent=2)
    with open(f"{OUT}/sec_summary.txt", "w") as fh:
        f = flow
        fh.write(f"Filings {f['filings']} from {f['companies']} companies "
                 f"({f['item_1_05_filings']} Item 1.05, {f['item_8_01_filings']} Item 8.01)\n")
        fh.write(f"  incidents {f['incidents']}, update filings {f['update_filings']}, "
                 f"excluded {f['excluded_filings']}\n")
        fh.write(f"  incidents ever filed under Item 1.05: {f['incidents_ever_item_1_05']}\n\n")
        for label in ("incidents", "events"):
            s = res[label]
            lo, hi = s["determinable_ci95"]
            fh.write(f"{label}: n={s['n']}  env {s['env']}\n")
            fh.write(f"  environment determinable {s['determinable']}/{s['n']} = "
                     f"{s['determinable_share']:.0%} (95% CI {lo:.0%}-{hi:.0%})\n")
            fh.write(f"  root cause {s['root_cause']}\n")
            fh.write(f"  alternative order {res[label + '_alt_order']}\n")
            fh.write(f"  cause stated {s['root_cause_stated']}/{s['n']} = {s['root_cause_stated_share']:.0%}\n")
            fh.write(f"  root cause by environment {s['root_by_env']}\n\n")
        if "vs_vcdb_rule_B" in res:
            fh.write("SEC events vs VCDB events (hand rule B), Fisher exact test:\n")
            for k, v in res["vs_vcdb_rule_B"].items():
                if isinstance(v, dict):
                    (a1, b1), (a2, b2) = v["sec"], v["vcdb"]
                    fh.write(f"  {k}: SEC {a1}/{b1} = {a1/b1:.0%}  VCDB {a2}/{b2} = {a2/b2:.0%}  p = {v['fisher_p']}\n")
            fh.write("\n")
        fh.write(f"Dollar figures disclosed for {res['costs']['incidents_with_dollar_figure']} incidents:\n")
        for c in res["costs"]["items"]:
            rng = f"${c['low']:,}" + (f"-${c['high']:,}" if c["high"] != c["low"] else "")
            fh.write(f"  {c['company']}: {rng} ({c['what']})\n")
    print(open(f"{OUT}/sec_summary.txt").read())

if __name__ == "__main__":
    main()
