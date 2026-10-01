#!/usr/bin/env python3
"""
Hand campaign merge + hand environment/root-cause codes for named campaigns.

Reads the victim-level coding sheet (vcdb_extract.py --keep-campaigns) and writes:
  events_hand.csv   one row per independent event under the HAND rule
  campaigns.csv     campaign membership (victim -> campaign) for the appendix

Named campaigns (identified from VCDB narratives + references, 2019-2025):
  MOVEIT  2023 MOVEit Transfer zero-day (Cl0p)            -> ONPREM,  UNPATCHED
  EBS     2025 Oracle E-Business Suite zero-day (Cl0p)    -> ONPREM,  UNPATCHED
  DRIFT   2025 Salesloft Drift OAuth-token theft           -> CLOUD,   THIRD_PARTY
  SFSE    2025 Salesforce CRM social-engineering wave      -> CLOUD,   CREDENTIAL
          (ShinyHunters / Scattered Lapsus$ Hunters)
"""
import csv, collections, sys

SRC = sys.argv[1] if len(sys.argv) > 1 else "results/victims/coding_sheet.csv"
OUT = sys.argv[2] if len(sys.argv) > 2 else "results/hand"

# victims whose VCDB narrative names a third-party customer-service/CRM platform but not
# Salesforce; attributed to the SFSE wave from the cited press coverage (flagged in output)
SFSE_BY_PRESS = {"Farmers Insurance", "Louis Vuitton", "Qantas", "Tiffany", "TransUnion"}

CAMPAIGN_CODES = {
    "MOVEIT": ("ONPREM", "UNPATCHED"),
    "EBS":    ("ONPREM", "UNPATCHED"),
    "DRIFT":  ("CLOUD", "THIRD_PARTY"),
    "SFSE":   ("CLOUD", "CREDENTIAL"),
}

def campaign(r):
    t = (r["summary"] + " " + r["reference"]).lower()
    if "moveit" in t: return "MOVEIT", "narrative"
    if "drift" in t or "salesloft" in t: return "DRIFT", "narrative"
    if "e-business" in t or (("clop" in t or "cl0p" in t) and "oracle" in t): return "EBS", "narrative"
    if "shinyhunters" in t or "lapsus" in t or "salesforce" in t: return "SFSE", "narrative"
    # press attribution covers only the 2025 wave; an earlier record for the same company
    # (TransUnion, 2019 credential stuffing) is a separate incident
    if r["victim"] in SFSE_BY_PRESS and r["year"] == "2025": return "SFSE", "press attribution"
    return "", ""

def main():
    import os
    os.makedirs(OUT, exist_ok=True)
    rows = list(csv.DictReader(open(SRC, encoding="utf-8")))
    members = collections.defaultdict(list)
    events = []
    for r in rows:
        c, how = campaign(r)
        if c:
            members[c].append((r, how))
        else:
            r["campaign"] = ""; r["campaign_size"] = 1
            r["hand_infra"] = r["auto_infra"]; r["hand_root_cause"] = r["auto_root_cause"]
            events.append(r)
    with open(f"{OUT}/campaigns.csv", "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh); w.writerow(["campaign", "victim", "year", "attribution"])
        for c, ms in members.items():
            for r, how in ms:
                w.writerow([c, r["victim"], r["year"], how])
    for c, ms in members.items():
        rep = dict(ms[0][0])
        infra, rc = CAMPAIGN_CODES[c]
        rep.update(campaign=c, campaign_size=len(ms), victim=f"{c} campaign ({len(ms)} victims)",
                   hand_infra=infra, hand_root_cause=rc, auto_infra=rep["auto_infra"])
        events.append(rep)
    keys = list(events[0].keys())
    for e in events:
        for k in ("campaign", "campaign_size", "hand_infra", "hand_root_cause"):
            if k not in keys: keys.append(k)
    with open(f"{OUT}/events_hand.csv", "w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=keys, extrasaction="ignore"); w.writeheader(); w.writerows(events)
    print("victim records:", len(rows))
    print("campaigns:", {c: len(m) for c, m in members.items()})
    print("independent events (hand rule):", len(events))
    print("hand infra:", collections.Counter(e["hand_infra"] for e in events))

if __name__ == "__main__":
    main()
