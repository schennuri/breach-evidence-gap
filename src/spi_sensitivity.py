#!/usr/bin/env python3
"""
SPI composite scores and weight-sensitivity analysis (Table I, Table VIII, Fig. 7).

  - composites under assigned and equal weights
  - one-at-a-time scaling of each weight (0x, 0.5x, 1.5x, 2x; others renormalised)
  - break-even weight for cloud to overtake hybrid
  - Dirichlet sampling around the baseline weights and uniform sampling on the simplex
"""
import numpy as np

DIMS = ["Data confidentiality", "Access control / IAM", "Patch management", "Physical security",
        "Incident response", "Compliance auditability", "Insider threat resilience"]
W = np.array([.18, .17, .16, .14, .13, .12, .10])
S = {"Cloud":   np.array([.86, .83, .91, .94, .79, .88, .66]),
     "On-prem": np.array([.71, .67, .58, .72, .63, .65, .74]),
     "Hybrid":  np.array([.89, .86, .84, .91, .82, .90, .79])}
S["Hybrid (bounded)"] = np.maximum(S["Cloud"], S["On-prem"])
rng = np.random.default_rng(42)

print("Composite SPI (assigned weights):", {k: round(float(W @ v), 4) for k, v in S.items()})
print("Composite SPI (equal weights):   ", {k: round(float(v.mean()), 4) for k, v in S.items()})

print("\nOne-at-a-time: hybrid minus cloud lead, min..max over 0x/0.5x/1.5x/2x")
for i, d in enumerate(DIMS):
    leads, ranks_ok = [], True
    for f in (0, 0.5, 1.5, 2):
        w = W.copy(); w[i] *= f; w /= w.sum()
        c, o, h = w @ S["Cloud"], w @ S["On-prem"], w @ S["Hybrid"]
        leads.append(h - c); ranks_ok &= h > c > o
    print(f"  {d:28s} {min(leads):.4f} .. {max(leads):.4f}  ranking unchanged: {ranks_ok}")

print("\nBreak-even weights (cloud overtakes hybrid):")
diff = S["Hybrid"] - S["Cloud"]
for i, d in enumerate(DIMS):
    if diff[i] >= 0:
        continue
    others = [j for j in range(len(W)) if j != i]
    for x in np.linspace(W[i], 1, 4001):
        w = W.copy(); w[i] = x; w[others] = W[others] / W[others].sum() * (1 - x)
        if w @ diff < 0:
            print(f"  {d}: weight >= {x:.2f} (baseline {W[i]:.2f})"); break

names = ["Cloud", "On-prem", "Hybrid"]
def wins(draws):
    sc = np.vstack([draws @ S[n] for n in names])
    best = np.argmax(sc, axis=0)
    return {n: round(100 * float((best == k).mean()), 1) for k, n in enumerate(names)}, sc
print("\nDirichlet sampling around baseline (100,000 draws), % of draws ranked first:")
for label, conc in (("low uncertainty", 100), ("moderate", 20), ("high", 5)):
    print(f"  {label:16s}", wins(rng.dirichlet(W * conc, 100_000))[0])
share, sc = wins(rng.dirichlet(np.ones(len(W)), 100_000))
print("Uniform on simplex (100,000 draws):", share,
      f"| cloud above on-prem in {100 * float((sc[0] > sc[1]).mean()):.1f}%")
