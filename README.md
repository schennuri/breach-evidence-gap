# Where Do Enterprise Breaches Happen? — Code and Data

Replication package for the paper *Where Do Enterprise Breaches Happen? Cloud, On-Premises, and the Evidence Gap* (Sidhartha Chennuri, 2026).

The package reproduces every number, table and figure in the paper from a pinned snapshot of the
[VERIS Community Database (VCDB)](https://github.com/vz-risk/VCDB). One command runs everything in under a minute.

## Quick start

```bash
pip install -r requirements.txt     # numpy, scipy
./run_all.sh
```

`run_all.sh` fetches VCDB at commit `f6f98c00f66ab35f5b49977a5852ce94a5bb31d1` into `vcdb/` (only that commit, not the full history), runs the pipeline, and writes all outputs to `results/`. It stops with an error if `vcdb/` is at any other commit. Requires Python 3.9+ and git.

## Pipeline

| Step | Script | What it does | Outputs |
|---|---|---|---|
| 1 | `src/vcdb_extract.py` | Applies the inclusion criteria (Table III), the infrastructure rules (Table IV) and root-cause precedence; merges campaigns by the **automatic rule (A)** | `results/automatic/` |
| 2 | `src/vcdb_extract.py --keep-campaigns` | Same, keeping one row per victim | `results/victims/` |
| 3 | `src/hand_merge.py` | Merges the four named campaigns by the **hand rule (B)** and applies their hand codes | `results/hand/events_hand.csv`, `results/hand/campaigns.csv` |
| 4 | `src/draw_sample.py` | Redraws the stratified 60-event sample (seed 2026) and checks it matches the coded sheet | `results/sample_ids.json` |
| 5 | `src/analysis.py` | Permutation χ² tests, Cramér's V, Cohen's κ, Wilson intervals, alternative ordering, impact-data counts | `results/analysis_results.json`, `results/analysis_log.txt` |
| 6 | `src/spi_sensitivity.py` | SPI composites, one-at-a-time, break-even and Dirichlet weight sensitivity | `results/spi_sensitivity.txt` |
| 7 | `src/spi_data_weights.py` | SPI weights derived from observed root-cause frequencies | `results/spi_data_weights.txt` |

## Where each result in the paper comes from

| Paper | Source |
|---|---|
| Screening counts, Fig. 2 | `results/automatic/screening_flow.csv` |
| Records by year, Fig. 3 | `results/automatic/coding_sheet.csv` (`year`) and the VCDB snapshot |
| Event vs victim counting, Fig. 4 | `results/automatic/coding_sheet.csv` (`auto_infra`, `campaign_size`) |
| Root causes, Fig. 5; Table VII | `results/analysis_results.json` (`A_auto_order`, `B_hand_order`) |
| Named campaigns, Table V | `results/hand/campaigns.csv` |
| Hand coding, κ, Wilson CI (Section V.C) | `results/analysis_results.json` (`sample60_*`, `all162_*`) |
| Environment × root cause, Fig. 6; Table VI | `results/analysis_results.json` (`*_table`, `*_test`) |
| Impact data (Section V.G) | `results/analysis_results.json` (`n_*`) |
| Table I, Fig. 1, Fig. 7, Table VIII | `results/spi_sensitivity.txt` |
| Table II | `results/spi_data_weights.txt` |

Confidence intervals and power for the misconfiguration shares (Section V.E) come from `src/power.py`, written to `results/power.txt`.

## Hand-coded data

`data/hand_codes/hand_codes_all_162.csv` holds every hand-rule event that structured fields could not classify (162 events), with the hand-assigned environment (`coderA_infra`), root cause (`coderA_root_cause`) and the text basis for each decision (`coderA_basis`), alongside the automated codes. `in_stratified_sample = Y` marks the 60 events of the original stratified sample, which `src/draw_sample.py` reproduces. The analysis uses all 162. Coding was done by a single coder with language-model assistance in reading the narratives, as stated in the paper.

`data/hand_codes/hand_sample_coded.csv` is the original 60-event sample on its own. `data/hand_codes/hand_sample_blank_for_second_coder.csv` is that sample with the codes removed, for independent re-coding.

Campaign attribution rules are in `src/hand_merge.py`. Five victims of the 2025 Salesforce social-engineering wave are assigned from press attribution rather than their VCDB narrative; they are listed in `SFSE_BY_PRESS` and flagged in `campaigns.csv`.

## SEC 8-K extension (in progress)

`src/sec_8k_collect.py` collects Form 8-K cybersecurity incident disclosures from December 18, 2023 (when Item 1.05 took effect) to December 31, 2025, from SEC EDGAR full-text search. It writes a coding sheet with the incident text and keyword hints but no codes. SEC blocks many cloud and proxy networks, so run it from an ordinary connection:

```bash
python3 src/sec_8k_collect.py --ua "Your Name your@email.com" --out data/sec/sec_8k_filings.csv
```

The SEC data are not yet part of the reported results.

## Notes on reproducibility

- Results depend on the VCDB commit. VCDB is updated continuously; a later commit will give different counts.
- Random elements use fixed seeds: sample draw 2026; permutation tests 2026; SPI sampling 42.
- Permutation p-values use 20,000 permutations and may differ in the third decimal on other platforms.

## Licenses

- Code (`src/`, `run_all.sh`): MIT, see `LICENSE`.
- Data (`data/`, `results/`): derived from VCDB and released under CC BY-SA 4.0, see `data/LICENSE.md`.

## Citation

If you use this package, please cite the paper and VCDB. See `CITATION.cff`.
