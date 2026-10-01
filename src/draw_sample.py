#!/usr/bin/env python3
"""
Reproduce the stratified hand-coding sample (Section IV, "Hand-coding of unclassified events").

Draws 60 of the hand-rule events still needing manual review, stratified by incident
year in proportion to the pool, with random seed 2026. Writes results/sample_ids.json and
checks that the IDs match the coded sheet in data/hand_codes/.
"""
import csv, json, random, sys

EVENTS = "results/hand/events_hand.csv"
CODED = "data/hand_codes/hand_sample_coded.csv"
QUOTA = {"2019": 26, "2020": 25, "2021": 6, "2024": 2, "2025": 1}
SEED = 2026

# Added to the pool after the sample was drawn: a 2019 TransUnion record that an earlier
# version of hand_merge.py wrongly merged into the 2025 Salesforce wave. It is hand-coded
# with the other unsampled events; excluding it here reproduces the original draw.
ADDED_AFTER_DRAW = {"4041a7b0-246a-11eb-b042-01be07ea3379"}
pool = [r for r in csv.DictReader(open(EVENTS, encoding="utf-8"))
        if r["hand_infra"] == "REVIEW" and r["incident_id"] not in ADDED_AFTER_DRAW]
random.seed(SEED)
ids = []
for year, q in QUOTA.items():
    stratum = sorted((r for r in pool if r["year"] == year), key=lambda r: r["incident_id"])
    ids += [r["incident_id"] for r in random.sample(stratum, q)]

json.dump(ids, open("results/sample_ids.json", "w"), indent=1)
coded = [r["incident_id"] for r in csv.DictReader(open(CODED, encoding="utf-8"))]
print(f"pool: {len(pool)} events; sample: {len(ids)}")
if ids == coded:
    print("sample matches data/hand_codes/hand_sample_coded.csv")
else:
    sys.exit("WARNING: sample differs from the coded sheet (different VCDB commit?)")
