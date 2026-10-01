#!/usr/bin/env python3
"""
VCDB extraction and auto-coding for the cloud vs on-premises breach study.

Implements the protocol in Section 4.1:
  4.1.2  sampling frame / inclusion-exclusion
  4.1.3  infrastructure classification (Cloud / On-prem / Hybrid / Manual review / Undeterminable)
  4.1.4  root-cause coding with fixed precedence (+ alternative order for robustness)
  4.1.5  impact variables (detection / containment time, loss, legal-regulatory)

Outputs (in --out directory):
  coding_sheet.csv      one row per included incident, auto-codes pre-filled,
                        blank coder1/coder2/final columns for manual review
  screening_flow.csv    counts removed at each step (for the PRISMA-style figure)
  table1_auto.csv       root cause x infrastructure model (auto-coded rows only)
  table2_auto.csv       impact metrics by model with per-cell n
  run_info.txt          VCDB commit hash, run date, parameters

Usage:
  git clone https://github.com/vz-risk/VCDB.git
  python3 vcdb_extract.py --vcdb ./VCDB --out ./out
  python3 vcdb_extract.py --vcdb ./VCDB --out ./out --min-size "101 to 1000"   # relaxed size filter
  python3 vcdb_extract.py --vcdb ./VCDB --out ./out --keep-campaigns         # count every victim
"""
import argparse, csv, glob, json, os, subprocess, datetime, collections

# ---------------------------------------------------------------- parameters
YEAR_MIN, YEAR_MAX = 2019, 2025
CAMPAIGN_MIN = 5   # identical summaries shared by this many victims = one campaign

SIZE_ORDER = ["1 to 10", "11 to 100", "101 to 1000", "1001 to 10000",
              "10001 to 25000", "25001 to 50000", "50001 to 100000", "Over 100000"]

UNIT_TO_DAYS = {"Seconds": 1/86400, "Minutes": 1/1440, "Hours": 1/24, "Days": 1,
                "Weeks": 7, "Months": 30.44, "Years": 365.25}
UNIT_ORDINAL = {u: i for i, u in enumerate(
    ["Seconds", "Minutes", "Hours", "Days", "Weeks", "Months", "Years", "Never"])}

ROOT_CAUSES_PRIMARY = ["PHYSICAL", "THIRD_PARTY", "INSIDER", "UNPATCHED",
                       "MISCONFIG", "CREDENTIAL", "OTHER"]
# robustness ordering (Appendix): technical causes before actor-based causes
ROOT_CAUSES_ALT = ["UNPATCHED", "MISCONFIG", "CREDENTIAL", "PHYSICAL",
                   "INSIDER", "THIRD_PARTY", "OTHER"]

# ---------------------------------------------------------------- helpers
def g(d, *path, default=None):
    for p in path:
        if not isinstance(d, dict) or p not in d:
            return default
        d = d[p]
    return d

def as_list(x):
    if x is None:
        return []
    return x if isinstance(x, list) else [x]

def size_ok(emp, min_band):
    """Enterprise-scale filter. 'Large' = >1000 in VERIS."""
    if emp == "Large":
        return SIZE_ORDER.index(min_band) <= SIZE_ORDER.index("1001 to 10000")
    if emp in SIZE_ORDER:
        return SIZE_ORDER.index(emp) >= SIZE_ORDER.index(min_band)
    return False

def asset_prefixes(r):
    return {str(a.get("variety", ""))[:1] for a in as_list(g(r, "asset", "assets"))}

# ---------------------------------------------------------------- 4.1.3 infrastructure
def classify_infra(r):
    """Returns (code, reason). code in CLOUD / ONPREM / HYBRID / REVIEW / UNDETERMINABLE."""
    vectors = set(as_list(g(r, "action", "hacking", "vector")))
    cloud = set(as_list(g(r, "asset", "cloud")))
    hosting = g(r, "asset", "hosting")
    hosting = set(as_list(hosting.get("variety") if isinstance(hosting, dict) else hosting))

    has_cloud = "External Cloud Asset(s)" in cloud
    has_onprem = "On-Premise Asset(s)" in cloud

    if has_cloud and has_onprem:
        return "HYBRID", "asset.cloud has both values"
    if vectors & {"Hypervisor", "Inter-tenant"}:
        return ("HYBRID" if has_onprem else "CLOUD"), "hypervisor/inter-tenant vector"
    if has_cloud:
        return "CLOUD", "asset.cloud = External Cloud"
    if has_onprem:
        return "ONPREM", "asset.cloud = On-Premise"

    # legacy schema fallback
    if "External - shared environment" in hosting:
        return "CLOUD", "asset.hosting = External shared"
    if "Internal" in hosting:
        return "ONPREM", "asset.hosting = Internal"
    if "External - dedicated environment" in hosting or "External - unknown environment" in hosting:
        return "REVIEW", "asset.hosting = External dedicated/unknown"

    # nothing structured: send to manual review only if a source reference exists
    if g(r, "reference") or g(r, "summary"):
        return "REVIEW", "asset.cloud Unknown/NA - narrative available"
    return "UNDETERMINABLE", "no infrastructure information"

# ---------------------------------------------------------------- 4.1.4 root cause
def root_cause_flags(r):
    hv = set(as_list(g(r, "action", "hacking", "variety")))
    vec = set(as_list(g(r, "action", "hacking", "vector")))
    ev = set(as_list(g(r, "action", "error", "variety")))
    social = g(r, "action", "social")
    conf_vars = {d.get("variety") for d in as_list(g(r, "attribute", "confidentiality", "data"))
                 if isinstance(d, dict)}
    return {
        "PHYSICAL": "physical" in (g(r, "action") or {}) or "Physical access" in vec,
        "THIRD_PARTY": "partner" in (g(r, "actor") or {}) or "Partner" in vec,
        "INSIDER": "internal" in (g(r, "actor") or {}) and "misuse" in (g(r, "action") or {}),
        "UNPATCHED": "Exploit vuln" in hv,
        "MISCONFIG": "Misconfiguration" in ev or "Exploit misconfig" in hv,
        "CREDENTIAL": bool(hv & {"Use of stolen creds", "Brute force", "Pass-the-hash"})
                      or (social is not None and "Credentials" in conf_vars),
    }

def root_cause(flags, order):
    for c in order:
        if c == "OTHER" or flags.get(c):
            return c
    return "OTHER"

# ---------------------------------------------------------------- 4.1.5 impact
def timing(r, phase):
    t = g(r, "timeline", phase) or {}
    unit, val = t.get("unit"), t.get("value")
    if unit in (None, "Unknown", "NA"):
        return "", "", ""
    days = round(val * UNIT_TO_DAYS[unit], 2) if (val is not None and unit in UNIT_TO_DAYS) else ""
    return unit, UNIT_ORDINAL.get(unit, ""), days

def loss_amount(r):
    amt = g(r, "impact", "overall_amount")
    if amt:
        return amt
    items = [l.get("amount") for l in as_list(g(r, "impact", "loss")) if isinstance(l, dict)]
    items = [a for a in items if a]
    return sum(items) if items else ""

def legal_reg(r):
    return "Y" if any(isinstance(l, dict) and l.get("variety") == "Legal and regulatory"
                      for l in as_list(g(r, "impact", "loss"))) else ""

# ---------------------------------------------------------------- main
def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--vcdb", required=True, help="path to cloned VCDB repo")
    ap.add_argument("--out", default="out")
    ap.add_argument("--min-size", default="1001 to 10000", choices=SIZE_ORDER,
                    help="smallest employee_count band to include")
    ap.add_argument("--keep-campaigns", action="store_true",
                    help="do not collapse campaign victims into one row")
    a = ap.parse_args()
    os.makedirs(a.out, exist_ok=True)

    files = glob.glob(os.path.join(a.vcdb, "data", "json", "validated", "*.json"))
    flow = collections.OrderedDict([("records_in_vcdb", len(files))])
    rows, removed = [], collections.Counter()

    for f in files:
        r = json.load(open(f, encoding="utf-8"))
        yr = g(r, "timeline", "incident", "year")
        if not isinstance(yr, int) or not (YEAR_MIN <= yr <= YEAR_MAX):
            removed["outside_2019_2025"] += 1; continue
        if g(r, "attribute", "confidentiality", "data_disclosure") != "Yes":
            removed["not_confirmed_disclosure"] += 1; continue
        if not size_ok(g(r, "victim", "employee_count"), a.min_size):
            removed["below_size_threshold_or_unknown"] += 1; continue
        hv = set(as_list(g(r, "action", "hacking", "variety")))
        acts = set((g(r, "action") or {}).keys())
        if hv == {"DoS"} and acts == {"hacking"}:
            removed["dos_only"] += 1; continue
        if asset_prefixes(r) and asset_prefixes(r) <= {"U", "M"}:
            removed["user_device_or_media_only"] += 1; continue

        infra, why = classify_infra(r)
        if infra == "UNDETERMINABLE":
            removed["infrastructure_undeterminable"] += 1; continue

        flags = root_cause_flags(r)
        det_u, det_o, det_d = timing(r, "discovery")
        con_u, con_o, con_d = timing(r, "containment")
        rows.append({
            "incident_id": r.get("incident_id", os.path.basename(f)[:-5]),
            "_campaign_id": r.get("campaign_id") or "",
            "campaign_size": 1,
            "year": yr,
            "victim": g(r, "victim", "victim_id", default=""),
            "industry_naics2": str(g(r, "victim", "industry", default=""))[:2],
            "employee_count": g(r, "victim", "employee_count"),
            "country": ";".join(as_list(g(r, "victim", "country"))),
            "asset_cloud": ";".join(as_list(g(r, "asset", "cloud"))),
            "auto_infra": infra, "auto_infra_reason": why,
            "needs_manual_review": "Y" if infra == "REVIEW" else "",
            "auto_root_cause": root_cause(flags, ROOT_CAUSES_PRIMARY),
            "auto_root_cause_alt": root_cause(flags, ROOT_CAUSES_ALT),
            "flags": ";".join(k for k, v in flags.items() if v),
            "detection_unit": det_u, "detection_ord": det_o, "detection_days": det_d,
            "containment_unit": con_u, "containment_ord": con_o, "containment_days": con_d,
            "loss_usd": loss_amount(r), "legal_regulatory_loss": legal_reg(r),
            "summary": (g(r, "summary", default="") or "").replace("\n", " ")[:500],
            "reference": (g(r, "reference", default="") or "")[:500],
            # manual-coding columns
            "coder1_infra": "", "coder2_infra": "", "final_infra": "",
            "crossed_environments": "",
            "coder1_root_cause": "", "coder2_root_cause": "", "final_root_cause": "",
            "regulatory_fine": "", "litigation": "", "notes": "",
        })

    flow.update(removed)
    flow["eligible_before_campaign_collapse"] = len(rows)

    # ---- collapse mass-exploitation campaigns (e.g. 2023 MOVEit: hundreds of victims,
    # one root cause). Each campaign counts once; campaign_size records how many victims.
    # Key = VERIS campaign_id if present, else identical summary text shared by >= CAMPAIGN_MIN rows.
    if not a.keep_campaigns:
        summ = collections.Counter(r["summary"].strip().lower() for r in rows)
        def ckey(r):
            if r["_campaign_id"]:
                return "cid:" + r["_campaign_id"]
            s = r["summary"].strip().lower()
            return "sum:" + s if s and summ[s] >= CAMPAIGN_MIN else None
        groups = collections.defaultdict(list)
        for r in rows:
            groups[ckey(r) or "solo:" + r["incident_id"]].append(r)
        rows = []
        for k, grp in groups.items():
            rep = grp[0]
            rep["campaign_size"] = len(grp)
            if len(grp) > 1:
                rep["notes"] = f"Represents {len(grp)} victims of one campaign"
                flow[f"collapsed_campaign: {rep['summary'][:50]}"] = len(grp)
            rows.append(rep)

    flow["included"] = len(rows)
    for k in ("CLOUD", "ONPREM", "HYBRID", "REVIEW"):
        flow[f"included_auto_{k.lower()}"] = sum(r["auto_infra"] == k for r in rows)

    # ---- write coding sheet
    rows.sort(key=lambda x: (x["auto_infra"], x["year"]))
    with open(os.path.join(a.out, "coding_sheet.csv"), "w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=list(rows[0].keys()) if rows else ["empty"])
        w.writeheader(); w.writerows(rows)

    with open(os.path.join(a.out, "screening_flow.csv"), "w", newline="") as fh:
        w = csv.writer(fh); w.writerow(["step", "count"]); w.writerows(flow.items())

    # ---- Table 1 (auto-coded only, REVIEW excluded)
    models = ["CLOUD", "ONPREM", "HYBRID"]
    t1 = collections.Counter((r["auto_root_cause"], r["auto_infra"]) for r in rows
                             if r["auto_infra"] in models)
    tot = collections.Counter(r["auto_infra"] for r in rows if r["auto_infra"] in models)
    with open(os.path.join(a.out, "table1_auto.csv"), "w", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(["root_cause"] + sum([[m + "_n", m + "_pct"] for m in models], []) + ["total"])
        for c in ROOT_CAUSES_PRIMARY:
            line = [c]
            for m in models:
                n = t1[(c, m)]; line += [n, f"{100*n/tot[m]:.1f}" if tot[m] else ""]
            w.writerow(line + [sum(t1[(c, m)] for m in models)])
        w.writerow(["TOTAL"] + sum([[tot[m], "100.0" if tot[m] else ""] for m in models], [])
                   + [sum(tot.values())])

    # ---- Table 2 (impact metrics, with per-cell n)
    def stats(vals):
        vals = sorted(v for v in vals if v != "")
        if not vals: return 0, "", ""
        n = len(vals); mid = n // 2
        med = vals[mid] if n % 2 else (vals[mid-1] + vals[mid]) / 2
        return n, round(sum(vals)/n, 2), round(med, 2)
    with open(os.path.join(a.out, "table2_auto.csv"), "w", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(["metric"] + sum([[m + "_n", m + "_mean", m + "_median"] for m in models], []))
        for metric in ("detection_days", "containment_days", "loss_usd"):
            line = [metric]
            for m in models:
                line += list(stats([r[metric] for r in rows if r["auto_infra"] == m]))
            w.writerow(line)
        line = ["legal_regulatory_loss_pct"]
        for m in models:
            sub = [r for r in rows if r["auto_infra"] == m]
            k = sum(r["legal_regulatory_loss"] == "Y" for r in sub)
            line += [len(sub), f"{100*k/len(sub):.1f}" if sub else "", ""]
        w.writerow(line)

    # ---- run info
    try:
        commit = subprocess.check_output(["git", "-C", a.vcdb, "rev-parse", "HEAD"], text=True).strip()
    except Exception:
        commit = "unknown"
    with open(os.path.join(a.out, "run_info.txt"), "w") as fh:
        fh.write(f"VCDB commit: {commit}\nRun date: {datetime.date.today()}\n"
                 f"Years: {YEAR_MIN}-{YEAR_MAX}\nMin size band: {a.min_size}\n"
                 f"Campaigns collapsed: {not a.keep_campaigns} (min {CAMPAIGN_MIN})\n")
    for k, v in flow.items():
        print(f"{k:40s} {v}")

if __name__ == "__main__":
    main()
