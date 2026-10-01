# Codebook for independent second coding

Thank you for helping. You will code 162 public breach records. It takes about 3–4 hours; you can stop and resume at any time.

**Please do this without looking at any other coder's codes.** Work only from `second_coder_sheet.csv`, which contains no codes. Agreement between independent coders is what the paper reports, so it only counts if your judgments are your own.

## What you do for each row

Read the `summary` column. If it is unclear, open the links in `reference`. Then fill three columns:

| Column | What to enter |
|---|---|
| `coderB_infra` | Where the compromised data or system was: `CLOUD`, `ONPREM`, `HYBRID` or `UND` |
| `coderB_root_cause` | The main cause: one of the seven codes below |
| `coderB_basis` | A few words quoting or paraphrasing what in the text led to your decision |

## 1. Environment (`coderB_infra`)

Assign an environment **only when the text states it or directly implies it**. When in doubt, use `UND`. Do not use outside knowledge of the company.

| Code | Use when the text says or directly implies | Examples |
|---|---|---|
| `CLOUD` | Data or system hosted by a cloud or SaaS provider | "cloud database", "S3 bucket", "storage buckets", "hosted by [provider]", "Salesforce instance", "managed services hosted environment" |
| `ONPREM` | Data or system on the organization's own premises or network | "our network", "company servers", "self-hosted environment", "office computers", skimmers on the organization's own terminals, VPN into the internal network |
| `HYBRID` | The attack moved between the two | on-premises compromise used to reach a cloud tenant, or the reverse |
| `UND` | The text does not say where the data lived | "database exposed", "hacked", "ransomware attack", "email accounts accessed" with no hosting detail |

Notes:
- An exposed Elasticsearch or MongoDB database with no hosting stated is `UND`, even though many such databases are cloud-hosted.
- Ransomware alone is `UND`. It becomes `ONPREM` only if the text names the victim's network, servers, or devices.
- Email account compromise is `UND` unless the mail platform is named.

## 2. Root cause (`coderB_root_cause`)

Pick **one**. If several apply, use the **first** in this list that the text supports:

| Order | Code | Use when |
|---|---|---|
| 1 | `PHYSICAL` | Physical access or tampering: skimmers, stolen hardware, on-site equipment |
| 2 | `THIRD_PARTY` | The breach happened at, or through, a vendor, partner or contractor |
| 3 | `INSIDER` | An employee or insider misused legitimate access |
| 4 | `UNPATCHED` | A software vulnerability or application flaw was exploited (including flaws in the organization's own apps) |
| 5 | `MISCONFIG` | A misconfiguration: unsecured or publicly exposed database, server or storage; wrong permissions |
| 6 | `CREDENTIAL` | Stolen, guessed, phished or stuffed credentials, or social engineering that obtained credentials |
| 7 | `OTHER` | None of the above, or the cause is not stated (ransomware with no entry point, errors such as misdirected email, data offered for sale with no method) |

Notes:
- "Email accounts were accessed" with no method stated is `OTHER`. It is `CREDENTIAL` only if phishing, stolen passwords or similar is mentioned.
- Accidental disclosure by staff (wrong email recipient, publishing data by mistake) is `OTHER`, not `INSIDER`. `INSIDER` means deliberate misuse.

## When you finish

Save the file and send it back. The agreement score (Cohen's κ) is computed with:

```bash
python3 src/kappa.py data/hand_codes/hand_codes_all_162.csv second_coder_sheet.csv
```
