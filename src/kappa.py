#!/usr/bin/env python3
"""
Inter-coder agreement between the first coder and an independent second coder.

  python3 src/kappa.py data/hand_codes/hand_codes_all.csv second_coder_sheet.csv
  python3 src/kappa.py data/sec/sec_incident_codes.csv sec_second_coder_sheet.csv

Reports percent agreement and Cohen's kappa for environment and root cause, a
confusion table for each, and writes the rows that disagree to disagreements.csv
for adjudication.
"""
import csv, sys, collections

def kappa(a, b):
    n = len(a)
    po = sum(x == y for x, y in zip(a, b)) / n
    cats = set(a) | set(b)
    pe = sum((a.count(c) / n) * (b.count(c) / n) for c in cats)
    return po, (po - pe) / (1 - pe) if pe < 1 else 1.0

def main(first_path, second_path, out="disagreements.csv"):
    A = {(r.get("incident_id") or r.get("accession")): r for r in csv.DictReader(open(first_path, encoding="utf-8"))}
    B = {r["incident_id"]: r for r in csv.DictReader(open(second_path, encoding="utf-8"))}
    ids = [i for i in A if i in B and B[i].get("coderB_infra", "").strip()]
    if not ids:
        sys.exit("No coded rows found in the second coder's sheet.")
    print(f"{len(ids)} events coded by both coders ({len(A)} in first sheet)\n")
    bad = []
    for label, ca, cb in (("Environment", "coderA_infra", "coderB_infra"),
                          ("Root cause", "coderA_root_cause", "coderB_root_cause")):
        a = [A[i][ca].strip().upper() for i in ids]
        b = [B[i][cb].strip().upper() for i in ids]
        po, k = kappa(a, b)
        print(f"{label}: agreement {po:.1%}, Cohen's kappa = {k:.2f}")
        for (x, y), n in sorted(collections.Counter(zip(a, b)).items()):
            if x != y:
                print(f"   coder A {x:12s} vs coder B {y:12s}: {n}")
        bad += [(i, label, x, y) for i, x, y in zip(ids, a, b) if x != y]
        print()
    with open(out, "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(["incident_id", "variable", "coder_A", "coder_B", "victim", "summary", "agreed_code"])
        for i, var, x, y in bad:
            w.writerow([i, var, x, y, A[i].get("victim") or A[i].get("company", ""),
                        (A[i].get("summary") or A[i].get("coderA_basis", ""))[:300], ""])
    print(f"{len(bad)} disagreements written to {out} for adjudication.")

if __name__ == "__main__":
    if len(sys.argv) < 3:
        sys.exit(__doc__)
    main(sys.argv[1], sys.argv[2])
