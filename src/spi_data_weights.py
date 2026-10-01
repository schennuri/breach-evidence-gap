#!/usr/bin/env python3
"""Data-informed SPI weights: root-cause frequencies (hand campaign rule) mapped to SPI dimensions."""
import csv, collections as C, numpy as np
dims = ["conf","iam","patch","phys","ir","comp","insider"]
S = {"Cloud":[.86,.83,.91,.94,.79,.88,.66], "On-prem":[.71,.67,.58,.72,.63,.65,.74],
     "Hybrid (as assigned)":[.89,.86,.84,.91,.82,.90,.79]}
S["Hybrid (bounded)"] = list(np.maximum(S["Cloud"], S["On-prem"]))
w_assigned = np.array([.18,.17,.16,.14,.13,.12,.10])
MAP = {"MISCONFIG":"conf","CREDENTIAL":"iam","UNPATCHED":"patch","PHYSICAL":"phys","INSIDER":"insider"}
ev = list(csv.DictReader(open("results/hand/events_hand.csv")))
samp = {r["incident_id"]: r for r in csv.DictReader(open("data/hand_codes/hand_codes_all.csv"))}
def rc(r):
    return samp[r["incident_id"]]["coderA_root_cause"] if r["incident_id"] in samp else r["hand_root_cause"]
def weights(victim):
    f = C.Counter()
    for r in ev:
        d = MAP.get(rc(r))
        if d: f[d] += int(r["campaign_size"]) if victim else 1
    tot = sum(f.values())
    w = np.array([0.75 * f[d] / tot if d in f else 0 for d in dims])
    w[dims.index("ir")], w[dims.index("comp")] = .13, .12
    return w, dict(f)
for name, w, f in [("assigned", w_assigned, None)] + [(n, *weights(v)) for n, v in (("event-weighted", False), ("victim-weighted", True))]:
    print(name, "| root-cause counts:", f, "| weights:", {d: round(float(x), 3) for d, x in zip(dims, w)})
    print("   ", {k: round(float(np.dot(w, v)), 3) for k, v in S.items()})
