#!/usr/bin/env python3
"""
Robustness checks for the environment x root-cause result (Section IV-F of the paper).

  python3 src/robustness.py     (after analysis.py and sec_analysis.py)

1. Detection: is the environment more often stated for some root causes than others?
2. Bounding: how large is the misconfiguration contrast across all rule-B events if
   the undetermined events were cloud or on-premises in various proportions?
3. Sensitivity: rerun the test (a) treating the two customer-managed campaigns
   (MOVEit, Oracle EBS) as hosting unknown, (b) treating hand codes whose only evidence
   is a mention of the network, servers or internal systems as undetermined, (c) both.
   (b) is also applied to the SEC Form 8-K codes.
4. SEC determinability by disclosure item (1.05 vs 8.01).
5. Sample size: classifiable events needed to detect a 15-point difference in a
   root-cause share, and what that implies at observed determinability rates.
Writes results/robustness.json and results/robustness.txt.
"""
import csv, json, re, math, collections as C
import numpy as np
from scipy import stats

rng = np.random.default_rng(2026)
CAUSES = ["PHYSICAL", "THIRD_PARTY", "INSIDER", "UNPATCHED", "MISCONFIG", "CREDENTIAL", "OTHER"]
# Evidence that places a system on the organization's own premises beyond a bare mention
# of "network", "servers" or "systems".
STRONG = re.compile(r"skimmer|terminal|pump|physical|office computer|equipment|plant|self-hosted|"
                    r"on-prem|data cent|vpn|pos |pos controller|devices", re.I)
CUSTOMER_MANAGED = {"MOVEIT", "EBS"}

hand = list(csv.DictReader(open("results/hand/events_hand.csv")))
codes = {r["incident_id"]: r for r in csv.DictReader(open("data/hand_codes/hand_codes_all.csv"))}

def events(customer_managed_unknown=False, weak_onprem_unknown=False):
    out = []
    for r in hand:
        env, rc, src, basis = r["hand_infra"], r["hand_root_cause"], "structured", ""
        if env == "REVIEW":
            h = codes[r["incident_id"]]
            env, rc, src, basis = h["coderA_infra"], h["coderA_root_cause"], "hand", h["coderA_basis"]
        camp = r["victim"].split(" ")[0] if "campaign" in r["victim"] else ""
        if customer_managed_unknown and camp in CUSTOMER_MANAGED:
            env = "UND"
        if weak_onprem_unknown and src == "hand" and env == "ONPREM" and not STRONG.search(basis):
            env = "UND"
        out.append({"env": "UND" if env == "REVIEW" else env, "rc": rc, "src": src, "camp": camp,
                    "victims": int(r.get("campaign_size") or 1)})
    return out

def perm_test(ev, n=20000):
    ev = [e for e in ev if e["env"] in ("CLOUD", "ONPREM")]
    env = np.array([e["env"] for e in ev]); rc = np.array([e["rc"] for e in ev])
    def chi(env_):
        m = np.array([[np.sum((env_ == e) & (rc == c)) for c in CAUSES] for e in ("CLOUD", "ONPREM")])
        m = m[:, m.sum(0) > 0]
        return stats.chi2_contingency(m, correction=False)[0], m
    obs, m = chi(env)
    cnt = sum(chi(rng.permutation(env))[0] >= obs for _ in range(n))
    v = math.sqrt(obs / (m.sum() * (min(m.shape) - 1)))
    cl = [e for e in ev if e["env"] == "CLOUD"]; op = [e for e in ev if e["env"] == "ONPREM"]
    mc = sum(e["rc"] == "MISCONFIG" for e in cl); mo = sum(e["rc"] == "MISCONFIG" for e in op)
    return {"cloud": len(cl), "onprem": len(op), "chi2": round(obs, 2), "p": round((cnt + 1) / (n + 1), 4),
            "V": round(v, 3), "misconfig_cloud": [mc, len(cl)], "misconfig_onprem": [mo, len(op)]}

res, log = {}, []
def say(s=""):
    log.append(s); print(s)

# 1. detection by root cause
base = events()
det = {}
for c in CAUSES:
    sub = [e for e in base if e["rc"] == c]
    det[c] = [sum(e["env"] != "UND" for e in sub), len(sub)]
mis = det["MISCONFIG"]; rest = [sum(v[0] for k, v in det.items() if k != "MISCONFIG"),
                                 sum(v[1] for k, v in det.items() if k != "MISCONFIG")]
p = stats.fisher_exact([[mis[0], mis[1] - mis[0]], [rest[0], rest[1] - rest[0]]])[1]
res["detection_by_cause"] = det
res["detection_misconfig_vs_rest"] = {"misconfig": mis, "rest": rest, "fisher_p": float(f"{p:.2g}")}
say(f"1. Environment stated, by root cause (rule B, {len(base)} events)")
for c in CAUSES:
    k, n = det[c]; say(f"   {c:12s} {k:3d}/{n:3d} = {k/n:.0%}")
say(f"   misconfiguration {mis[0]}/{mis[1]} vs other causes {rest[0]}/{rest[1]}, Fisher p = {p:.2g}\n")

# 2. bounding
known_c = [e for e in base if e["env"] == "CLOUD"]; known_o = [e for e in base if e["env"] == "ONPREM"]
und = [e for e in base if e["env"] == "UND"]
kc, km_c = len(known_c), sum(e["rc"] == "MISCONFIG" for e in known_c)
ko, km_o = len(known_o), sum(e["rc"] == "MISCONFIG" for e in known_o)
um = sum(e["rc"] == "MISCONFIG" for e in und); uo = len(und) - um
def shares(q_mis, q_other):
    """q = share of undetermined events that are cloud, for misconfiguration and for other causes."""
    cn = kc + q_mis * um + q_other * uo; cm = km_c + q_mis * um
    on = ko + (1 - q_mis) * um + (1 - q_other) * uo; om = km_o + (1 - q_mis) * um
    return cm / cn, om / on
bound = {}
for q in (0.25, 0.5, 0.75):
    c, o = shares(q, q); bound[f"independent_q{q}"] = [round(c, 3), round(o, 3)]
# break-even: other causes split evenly; what share of undetermined misconfig must be cloud
# for the two shares to be equal?
lo, hi = 0.0, 1.0
for _ in range(60):
    mid = (lo + hi) / 2; c, o = shares(mid, 0.5)
    lo, hi = (lo, mid) if c > o else (mid, hi)
bound["break_even_cloud_share_of_undetermined_misconfig"] = round(lo, 3)
res["bounding"] = {"known": {"cloud": [km_c, kc], "onprem": [km_o, ko]},
                   "undetermined": {"misconfig": um, "other": uo}, **bound}
say(f"2. Misconfiguration share over all {len(base)} events if undetermined events were assigned")
say(f"   known only: cloud {km_c}/{kc} = {km_c/kc:.0%}, on-prem {km_o}/{ko} = {km_o/ko:.0%}")
say(f"   undetermined: {um} misconfiguration, {uo} other")
for q in (0.25, 0.5, 0.75):
    c, o = bound[f"independent_q{q}"]
    say(f"   {q:.0%} of undetermined events cloud (independent of cause): cloud {c:.0%}, on-prem {o:.0%}")
say(f"   with other causes split 50/50, the shares are equal if only "
    f"{bound['break_even_cloud_share_of_undetermined_misconfig']:.0%} of undetermined misconfiguration events are cloud\n")

# 3. sensitivity
say("3. Sensitivity of the rule-B test")
sens = {}
for label, kw in (("baseline", {}), ("customer_managed_unknown", {"customer_managed_unknown": True}),
                  ("weak_onprem_unknown", {"weak_onprem_unknown": True}),
                  ("both", {"customer_managed_unknown": True, "weak_onprem_unknown": True})):
    t = perm_test(events(**kw)); sens[label] = t
    say(f"   {label:26s} cloud {t['cloud']:2d} on-prem {t['onprem']:2d}  chi2 {t['chi2']:5.2f}  p {t['p']:.4f}  V {t['V']:.3f}  "
        f"misconfig {t['misconfig_cloud'][0]}/{t['misconfig_cloud'][1]} vs {t['misconfig_onprem'][0]}/{t['misconfig_onprem'][1]}")
weak = [c["coderA_basis"] for c in codes.values() if c["coderA_infra"] == "ONPREM" and not STRONG.search(c["coderA_basis"])]
res["sensitivity"] = sens; res["weak_onprem_vcdb"] = weak
say(f"   weak on-prem hand codes ({len(weak)}): " + "; ".join(weak))

# victim counting without the customer-managed campaigns (rule A, structured fields)
auto = list(csv.DictReader(open("results/automatic/coding_sheet.csv")))
vc = C.Counter(); vc2 = C.Counter()
for r in auto:
    if r["auto_infra"] in ("CLOUD", "ONPREM"):
        n = int(r["campaign_size"] or 1); vc[r["auto_infra"]] += n
        if n < 100: vc2[r["auto_infra"]] += n
res["victims_rule_A"] = dict(vc); res["victims_rule_A_without_moveit"] = dict(vc2)
say(f"   victim records, rule A: {dict(vc)}; without MOVEit: {dict(vc2)}\n")

# SEC with weak on-prem codes treated as undetermined
sec = list(csv.DictReader(open("data/sec/sec_incident_codes.csv", encoding="utf-8")))
sec_ev = [s for s in sec if not (s["coderA_campaign"] == "CDK" and not s["company"].startswith("SONIC"))]
sweak = [s["company"] for s in sec_ev if s["coderA_infra"] == "ONPREM" and not STRONG.search(s["coderA_basis"])]
cl = sum(s["coderA_infra"] == "CLOUD" for s in sec_ev); op = sum(s["coderA_infra"] == "ONPREM" for s in sec_ev)
op2 = op - len(sweak)
res["sec_weak_onprem"] = {"n_events": len(sec_ev), "onprem": op, "weak": len(sweak), "companies": sweak,
                          "stated_after": [cl + op2, len(sec_ev)], "cloud_share_after": [cl, cl + op2]}
say(f"   SEC: {len(sweak)} of {op} on-prem codes rest on network/servers/systems only; "
    f"recoded, environment stated for {cl+op2}/{len(sec_ev)}, cloud {cl}/{cl+op2}\n")

# 4. SEC by item
by = {}
for item in ("Y", "N"):
    sub = [s for s in sec_ev if s["ever_1_05"] == item]
    by["item_1_05" if item == "Y" else "item_8_01_only"] = {
        "n": len(sub), "env_stated": sum(s["coderA_infra"] != "UND" for s in sub),
        "cause_stated": sum(s["coderA_root_cause"] != "OTHER" for s in sub)}
res["sec_by_item"] = by
say("4. SEC events by disclosure item")
for k, v in by.items():
    say(f"   {k:15s} n={v['n']:2d}  environment stated {v['env_stated']} ({v['env_stated']/v['n']:.0%}), "
        f"cause stated {v['cause_stated']} ({v['cause_stated']/v['n']:.0%})")
say()

# 5. sample size for a 15-point difference (25% vs 10%), 80% power, two-sided alpha 0.05
p1, p2, za, zb = 0.25, 0.10, 1.959964, 0.841621
pbar = (p1 + p2) / 2
n_per = math.ceil((za * math.sqrt(2 * pbar * (1 - pbar)) + zb * math.sqrt(p1 * (1 - p1) + p2 * (1 - p2))) ** 2 / (p1 - p2) ** 2)
classifiable = 2 * n_per
vcdb_rate = sum(e["env"] != "UND" for e in base) / len(base); sec_rate = 22 / 65
per_year_vcdb = len(base) / 7; per_year_sec = 65 / 2.04
ss = {"n_per_group": n_per, "classifiable_needed": classifiable,
      "events_needed_vcdb": math.ceil(classifiable / vcdb_rate), "events_needed_sec": math.ceil(classifiable / sec_rate),
      "years_vcdb": round(classifiable / vcdb_rate / per_year_vcdb, 1), "years_sec": round(classifiable / sec_rate / per_year_sec, 1)}
known_on = sum(e["env"] == "ONPREM" for e in base) / len(base)
known_cl = sum(e["env"] == "CLOUD" for e in base) / len(base)
ss["observed_split_events_needed_vcdb"] = math.ceil(n_per / min(known_on, known_cl))
ss["observed_split_years_vcdb"] = round(ss["observed_split_events_needed_vcdb"] / (len(base) / 7), 1)
ss["vcdb_onprem_known_share"] = round(known_on, 3)
res["sample_size"] = ss
say("5. Sample size to detect a root-cause share of 25% vs 10% (80% power, alpha 0.05, equal groups)")
say(f"   {n_per} classifiable events per environment, {classifiable} in all")
say(f"   at VCDB's {vcdb_rate:.0%} determinability: {ss['events_needed_vcdb']} independent events, about {ss['years_vcdb']} years of VCDB at the 2019-2025 rate")
say(f"   with the observed split ({known_on:.0%} of events known on-premises), {ss['observed_split_events_needed_vcdb']} events, "
    f"about {ss['observed_split_years_vcdb']} years of VCDB")
say(f"   at SEC's 34% determinability: {ss['events_needed_sec']} events, about {ss['years_sec']} years of 8-K filings at the 2024-2025 rate")

# 6. SEC recall against an external count: Debevoise & Plimpton, "Lessons learned: one year of
# Form 8-K material cybersecurity incident reporting" (Feb. 2025): 26 companies disclosed under
# Item 1.05 from Dec 18, 2023 to Dec 31, 2024, and 34 under Item 8.01 during 2024.
ext = {"item_1_05": 26, "item_8_01_2024": 34}
upto = [s for s in sec if s["first_file_date"] <= "2024-12-31"]
ours_105 = len({s["company"] for s in upto if s["ever_1_05"] == "Y"})
ours_801 = len({s["company"] for s in upto if s["disclosure_type"] == "8.01" and s["first_file_date"] >= "2024-01-01"
                and s["ever_1_05"] == "N"})
ours_801_any = len({s["company"] for s in upto if s["disclosure_type"] == "8.01" and s["first_file_date"] >= "2024-01-01"})
res["sec_recall"] = {"external": ext, "ours_item_1_05": ours_105, "ours_item_8_01_only": ours_801,
                     "ours_item_8_01_any": ours_801_any}
say()
say("6. SEC recall against Debevoise & Plimpton's count (Dec 18, 2023 - Dec 31, 2024)")
say(f"   Item 1.05 companies: ours {ours_105}, theirs {ext['item_1_05']}")
say(f"   Item 8.01 companies in 2024: ours {ours_801_any} (first filing 8.01; {ours_801} never moved to 1.05), "
    f"theirs {ext['item_8_01_2024']} -> recall about {ours_801_any/ext['item_8_01_2024']:.0%}")

json.dump(res, open("results/robustness.json", "w"), indent=2)
open("results/robustness.txt", "w").write("\n".join(log) + "\n")
