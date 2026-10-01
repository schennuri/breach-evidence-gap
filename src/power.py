#!/usr/bin/env python3
"""
Confidence intervals and power for the misconfiguration comparison (Section V.E).
Counts come from results/analysis_results.json (hand rule, B_hand_table).
"""
import json
import numpy as np
from scipy import stats

res = json.load(open("results/analysis_results.json"))
t = res["B_hand_table"]
k_c, n_c = t["CLOUD"].get("MISCONFIG", 0), sum(t["CLOUD"].values())
k_o, n_o = t["ONPREM"].get("MISCONFIG", 0), sum(t["ONPREM"].values())
for label, k, n in (("Cloud", k_c, n_c), ("On-prem", k_o, n_o)):
    ci = stats.binomtest(k, n).proportion_ci(method="wilson")
    print(f"{label}: {k}/{n} = {k/n:.1%} misconfiguration (95% CI {ci.low:.1%}-{ci.high:.1%})")

rng = np.random.default_rng(1)
p_c, p_o, sims = k_c / n_c, k_o / n_o, 4000
def power(nc, no):
    hits = [stats.fisher_exact([[a, nc - a], [b, no - b]])[1] < 0.05
            for a, b in zip(rng.binomial(nc, p_c, sims), rng.binomial(no, p_o, sims))]
    return float(np.mean(hits))
print(f"Power at observed sizes ({n_c} vs {n_o}): {power(n_c, n_o):.0%}")
for m in (20, 25, 30, 35, 40):
    print(f"  {m} events per environment: power {power(m, m):.0%}")
