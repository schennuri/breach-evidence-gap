#!/usr/bin/env python3
"""
Collect SEC Form 8-K cybersecurity incident disclosures (Dec 18, 2023 - Dec 31, 2025)
into a coding sheet for the cloud/on-premises study.

Run this on a machine that can reach sec.gov (SEC blocks many cloud/proxy networks).
SEC requires a User-Agent with your name and email; set it with --ua.

  python3 src/sec_8k_collect.py --ua "Your Name your@email.com" --out data/sec/sec_8k_filings.csv

What it does
  1. Queries EDGAR full-text search for 8-K filings that report Item 1.05 (material
     cybersecurity incident), plus 8-K Item 8.01 filings that mention a cybersecurity
     incident (the SEC's May 2024 guidance moved non-material disclosures to 8.01).
  2. De-duplicates by company and keeps the first disclosure of each incident;
     amendments (8-K/A) are linked to their original where possible.
  3. Downloads each filing's main document and extracts the incident text.
  4. Writes a CSV with blank coding columns using the same environment and
     root-cause scheme as the VCDB coding sheet.

It does NOT assign codes. Coding is done by hand, as for VCDB, because 8-K text rarely
states the environment in a fixed form.
"""
import argparse, csv, html, re, sys, time, json, urllib.parse, urllib.request

SEARCH = "https://efts.sec.gov/LATEST/search-index"
ARCHIVE = "https://www.sec.gov/Archives/edgar/data/{cik}/{adsh}/{doc}"
START, END = "2023-12-18", "2025-12-31"   # Item 1.05 effective Dec 18, 2023
QUERIES = [
    # (search phrase, item the filing must report). Filtering on the filing's own item
    # list, not on the phrase, catches 1.05 filings whatever wording they use.
    ('"Item 1.05"', "1.05"),
    ('"cybersecurity incident"', "1.05"),
    ('"cybersecurity incident"', "8.01"),        # voluntary / non-material disclosures
]
PAUSE = 0.15   # SEC fair-access limit is 10 requests per second

def get(url, ua):
    req = urllib.request.Request(url, headers={"User-Agent": ua, "Accept-Encoding": "identity"})
    for attempt in range(4):
        try:
            with urllib.request.urlopen(req, timeout=30) as r:
                return r.read().decode("utf-8", errors="replace")
        except Exception as e:
            if attempt == 3:
                raise
            time.sleep(2 ** attempt)

def search(q, ua):
    hits, start = [], 0
    while True:
        # NOTE: forms must be "8-K" alone. EDGAR returns originals AND amendments for it;
        # a list such as "8-K,8-K/A" silently returns amendments only. Adding
        # dateRange=custom makes the endpoint fail, so dates are also checked below.
        params = {"q": q, "forms": "8-K", "startdt": START, "enddt": END, "from": start}
        data = json.loads(get(SEARCH + "?" + urllib.parse.urlencode(params), ua))
        page = data.get("hits", {}).get("hits", [])
        hits += page
        total = data.get("hits", {}).get("total", {}).get("value", 0)
        start += len(page)
        print(f"  {q}: {start}/{total}", file=sys.stderr)
        if not page or start >= total:
            return hits
        time.sleep(PAUSE)

def text_of(doc_html):
    t = re.sub(r"(?is)<(script|style).*?</\1>", " ", doc_html)
    t = re.sub(r"(?s)<[^>]+>", " ", t)
    return re.sub(r"\s+", " ", html.unescape(t)).strip()

def filing_documents(cik, adsh, ua):
    """Main 8-K document and EX-99 exhibits, from the filing index page."""
    idx = f"https://www.sec.gov/Archives/edgar/data/{cik}/{adsh.replace('-', '')}/{adsh}-index.htm"
    page = get(idx, ua)
    main, exhibits = None, []
    for row in re.findall(r"(?is)<tr.*?</tr>", page):
        link = re.search(r'href="(?:/ix\?doc=)?(/Archives/edgar/data/[^"]+\.htm)"', row)
        cells = [text_of(c) for c in re.findall(r"(?is)<td.*?</td>", row)]
        if not link or len(cells) < 4:
            continue
        doc_type = cells[3].upper()
        url = "https://www.sec.gov" + link.group(1)
        if doc_type in ("8-K", "8-K/A") and main is None:
            main = url
        elif doc_type.startswith("EX-99"):
            exhibits.append(url)
    return main, exhibits

def incident_section(t):
    """Text from 'Item 1.05' (or 'Item 8.01') up to the next Item heading or signature."""
    m = re.search(r"Item\s*1\.05\b.*?(?=Item\s*\d\.\d\d\b|SIGNATURES?\b|$)", t, re.I | re.S) \
        or re.search(r"Item\s*8\.01\b.*?(?=Item\s*\d\.\d\d\b|SIGNATURES?\b|$)", t, re.I | re.S)
    return (m.group(0) if m else t)[:6000]

CLUES = {   # surfaced for the coder, never used as codes
    "cloud_terms": r"\b(cloud|SaaS|third[- ]party (?:platform|application|vendor|service)|hosted|AWS|Azure|Snowflake|Salesforce)\b",
    "onprem_terms": r"\b(on[- ]premises?|internal network|corporate network|data cent(?:er|re)|servers?|domain controller|VPN)\b",
    "ransomware": r"\bransomware|encrypt(?:ed|ion) of",
    "credential_terms": r"\b(credential|phishing|social engineering|password|MFA|multi-factor)\b",
    "vuln_terms": r"\b(vulnerabilit|zero[- ]day|CVE-\d{4}-\d+|exploit)",
}

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--ua", required=True, help='"Your Name your@email.com" (SEC requirement)')
    ap.add_argument("--out", default="data/sec/sec_8k_filings.csv")
    ap.add_argument("--no-text", action="store_true", help="skip downloading filing text")
    a = ap.parse_args()
    import os; os.makedirs(os.path.dirname(a.out) or ".", exist_ok=True)

    rows = {}
    for q, item_filter in QUERIES:
        for h in search(q, a.ua):
            s, adsh_doc = h["_source"], h["_id"]
            items = s.get("items") or []
            if item_filter and item_filter not in items:
                continue
            if not item_filter and "1.05" not in items:
                continue
            adsh, doc = adsh_doc.split(":", 1)
            if adsh in rows or not (START <= s.get("file_date", "") <= END):
                continue
            cik = (s.get("ciks") or [""])[0].lstrip("0")
            rows[adsh] = {
                "accession": adsh, "cik": cik,
                "company": re.sub(r"\s*\(CIK.*$", "", (s.get("display_names") or [""])[0]),
                "form": s.get("form", ""), "file_date": s.get("file_date", ""),
                "items": ";".join(items), "disclosure_type": "1.05" if "1.05" in items else "8.01",
                "url": ARCHIVE.format(cik=cik, adsh=adsh.replace("-", ""), doc=doc),
            }

    out = sorted(rows.values(), key=lambda r: (r["company"], r["file_date"]))
    first = {}
    for r in out:   # first disclosure per company = the incident; later ones are updates
        key = r["company"].lower()
        r["is_first_disclosure"] = "Y" if key not in first else "N"
        r["first_accession"] = first.setdefault(key, r["accession"])

    if not a.no_text:
        for i, r in enumerate(out, 1):
            try:
                main, exhibits = filing_documents(r["cik"], r["accession"], a.ua)
                r["url"] = main or r["url"]
                sec = incident_section(text_of(get(r["url"], a.ua)))
                # short item text usually means "see the attached press release"
                if len(sec) < 800 and exhibits:
                    time.sleep(PAUSE)
                    sec += " [EX-99] " + text_of(get(exhibits[0], a.ua))[:5000]
                    r["exhibit_url"] = exhibits[0]
            except Exception as e:
                sec = f"[download failed: {e}]"
            r["incident_text"] = sec
            for k, pat in CLUES.items():
                r[k] = ";".join(sorted({m.group(0).lower() for m in re.finditer(pat, sec, re.I)}))
            print(f"  text {i}/{len(out)}", file=sys.stderr)
            time.sleep(PAUSE)

    coding = ["coderA_infra", "coderA_root_cause", "coderA_campaign", "coderA_basis",
              "disclosed_cost_usd", "notes"]
    fields = (["accession", "cik", "company", "form", "file_date", "items", "disclosure_type",
               "url", "exhibit_url", "is_first_disclosure", "first_accession", "incident_text"]
              + list(CLUES) + coding) if out else ["empty"]
    with open(a.out, "w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=fields, extrasaction="ignore")
        w.writeheader()
        for r in out:
            w.writerow({**r, **{c: "" for c in coding}})
    n1 = sum(r["disclosure_type"] == "1.05" for r in out)
    print(f"wrote {len(out)} filings ({n1} Item 1.05, {len(out) - n1} Item 8.01), "
          f"{sum(r['is_first_disclosure'] == 'Y' for r in out)} distinct companies -> {a.out}")

if __name__ == "__main__":
    main()
