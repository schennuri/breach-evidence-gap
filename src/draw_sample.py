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

pool = [r for r in csv.DictReader(open(EVENTS, encoding="utf-8")) if r["hand_infra"] == "REVIEW"]
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
