#!/usr/bin/env python3
"""Analyses for Section V: both campaign rules, hand-coded sample, alt ordering, tests."""
import csv, collections as C, numpy as np, json
from scipy import stats
rng = np.random.default_rng(2026)
CAUSES = ["PHYSICAL","THIRD_PARTY","INSIDER","UNPATCHED","MISCONFIG","CREDENTIAL","OTHER"]

auto = list(csv.DictReader(open("results/automatic/coding_sheet.csv")))            # rule A: automatic merge
hand = list(csv.DictReader(open("results/hand/events_hand.csv")))        # rule B: hand merge
samp = {r["incident_id"]: r for r in csv.DictReader(open("data/hand_codes/hand_sample_coded.csv"))}
res = {}

def kappa(a, b):
    cats = sorted(set(a) | set(b)); n = len(a)
    po = sum(x == y for x, y in zip(a, b)) / n
    pe = sum((a.count(c) / n) * (b.count(c) / n) for c in cats)
    return po, (po - pe) / (1 - pe)

# --- 1. automated vs hand root cause on the 60-event sample
s = list(samp.values())
for col in ("auto_root_cause", "auto_root_cause_alt"):
    po, k = kappa([r[col] for r in s], [r["coderA_root_cause"] for r in s])
    res[f"agree_{col}"] = (round(po, 3), round(k, 3))
res["sample_env"] = dict(C.Counter(r["coderA_infra"] for r in s))
det = sum(r["coderA_infra"] != "UND" for r in s)
lo, hi = stats.binomtest(det, len(s)).proportion_ci(method="wilson")
res["sample_determinable"] = (det, len(s), round(lo, 3), round(hi, 3))
res["confusion_auto_vs_hand"] = dict(C.Counter(f"{r['auto_root_cause']}->{r['coderA_root_cause']}" for r in s if r["auto_root_cause"] != r["coderA_root_cause"]))

# --- 2. environment x root cause, both rules, auto-classified + hand-coded sample
def table(events, infra_col, rc_col, weight=False):
    t = C.Counter()
    for r in events:
        sid = r["incident_id"]
        if sid in samp and r[infra_col] == "REVIEW":
            env, rc = samp[sid]["coderA_infra"], samp[sid]["coderA_root_cause"]
        else:
            env, rc = r[infra_col], r[rc_col]
        if env in ("CLOUD", "ONPREM"):
            t[(env, rc)] += int(r.get("campaign_size") or 1) if weight else 1
    return t

def perm_test(t, n=20000):
    labels = [(e, c) for (e, c), k in t.items() for _ in range(k)]
    env = np.array([e for e, _ in labels]); rc = np.array([c for _, c in labels])
    def chi(env_):
        m = np.array([[np.sum((env_ == e) & (rc == c)) for c in CAUSES] for e in ("CLOUD", "ONPREM")])
        m = m[:, m.sum(0) > 0]
        return stats.chi2_contingency(m, correction=False)[0]
    obs = chi(env); cnt = sum(chi(rng.permutation(env)) >= obs for _ in range(n))
    m = np.array([[t[(e, c)] for c in CAUSES] for e in ("CLOUD", "ONPREM")]); m = m[:, m.sum(0) > 0]
    v = np.sqrt(obs / (m.sum() * (min(m.shape) - 1)))
    return round(obs, 2), round((cnt + 1) / (n + 1), 4), round(v, 3)

for name, ev, ic, rcc in [("A_auto", auto, "auto_infra", "auto_root_cause"),
                          ("B_hand", hand, "hand_infra", "hand_root_cause")]:
    t = table(ev, ic, rcc)
    res[f"{name}_events"] = len(ev)
    res[f"{name}_table"] = {e: {c: t[(e, c)] for c in CAUSES if t[(e, c)]} for e in ("CLOUD", "ONPREM")}
    res[f"{name}_test"] = perm_test(t)
    tw = table(ev, ic, rcc, weight=True)
    res[f"{name}_victim_weighted"] = {e: {c: tw[(e, c)] for c in CAUSES if tw[(e, c)]} for e in ("CLOUD", "ONPREM")}

# --- 3. alternative root-cause ordering
for name, ev, rcc in [("A_auto", auto, "auto_root_cause"), ("B_hand", hand, "hand_root_cause")]:
    prim = C.Counter(r[rcc] for r in ev)
    alt = C.Counter((r["auto_root_cause_alt"] if not r.get("campaign") else r[rcc]) for r in ev)
    changed = sum(1 for r in ev if not r.get("campaign") and r["auto_root_cause_alt"] != r[rcc])
    res[f"{name}_order"] = {"primary": {c: prim[c] for c in CAUSES}, "alt": {c: alt[c] for c in CAUSES}, "changed": changed}

# --- 4. impact data availability
for col in ("detection_days", "containment_days", "loss_usd"):
    res[f"n_{col}"] = sum(1 for r in hand if r[col] not in ("", None))
res["n_legal_reg"] = sum(1 for r in hand if r["legal_regulatory_loss"] == "Y")
json.dump(res, open("results/analysis_results.json", "w"), indent=1, default=str)
for k, v in res.items(): print(k, v)
