# DASHBOARD QA CHECKLIST (manual, browser)

The automated pass covers the HTTP layer only (see `outputs/final/20261101_direct_v14/dashboard_qa.json`).
No controllable browser was available during the review fixes, so **no visual QA is claimed**.
This checklist is what a person must run by hand, and what to record.

## How to start

```cmd
python -B scripts/serve_experimental_ui.py ^
  --config configs\evaluation\integrated_final_direct_v14.json ^
  --pin outputs\final\20261101_direct_v14\runtime_pin.json ^
  --port 8031 --output outputs\demo\qa-manual-v14
```

Open <http://127.0.0.1:8031/>. Offline mode only: `maximum_llm_requests` must read 0, and the
server must refuse `--live` for this profile (it does; verified at HTTP level).

## A. Layout (three columns, names unchanged)

- [ ] Three columns are visible: evidence/source on the left, graph in the middle, analysis on the right.
- [ ] The branch names still read **RAG** and **GraphRAG**; nothing is renamed.
- [ ] The three scenarios are selectable and labelled 3.3.1 / 3.3.2 / 3.3.3.

## B. Three scenarios × two branches

Run each row, then record what the panel shows.

| # | Scenario | Branch | Query to paste |
|---|---|---|---|
| 1 | 3.3.1 PurpleSharp | RAG | `Trong PurpleSharp, các sự kiện đăng nhập thất bại 4625 nhắm những tài khoản nào, nguồn workstation nào và Status/SubStatus nào?` |
| 2 | 3.3.1 PurpleSharp | GraphRAG | same as 1 |
| 3 | 3.3.2 MSHTA | RAG | `Which process chain led to powershell.exe in the reviewed evidence?` |
| 4 | 3.3.2 MSHTA | GraphRAG | same as 3 |
| 5 | 3.3.3 Regsvr32 | RAG | `Regsvr32.exe kết nối đến IP và cổng nào trong Sysmon Event ID 3, từ host và source IP nào?` |
| 6 | 3.3.3 Regsvr32 | GraphRAG | same as 5 |

Expected outcomes at the HTTP layer (already verified):

| # | Expected outcome |
|---|---|
| 1 | `dry_run_no_generation`, gate `proceed` |
| 2 | `dry_run_no_generation`, gate `proceed` |
| 3 | `abstain` |
| 4 | `abstain` |
| 5 | `abstain` |
| 6 | `dry_run_no_generation`, gate `proceed` |

## C. What must be true when switching

- [ ] Sending a **new query** clears the previous evidence, graph and citation panels.
- [ ] Switching **branch RAG → GraphRAG** does not leave a graph from the previous GraphRAG run.
- [ ] Switching **scenario** clears the previous scenario's entities.
- [ ] Every citation/evidence item belongs to the response currently on screen.
- [ ] A **rejected** result is not rendered as an accepted answer.
- [ ] A **provider error** is not rendered as a fallback answer that looks accepted.
- [ ] **Replay** and **live** are labelled differently wherever both can appear.
- [ ] **Export** writes the outcome actually shown, plus its provenance, and does not silently
      re-label a dry run as a live generation.

## D. Loading and error paths

- [ ] Typing a question shows a loading state, then a result (or an explicit abstain).
- [ ] An out-of-scope question (`Thời tiết hôm nay thế nào?`) shows an abstain, not an attack verdict.
- [ ] Stopping the server produces a clear error in the UI rather than a blank panel.

## E. What to record

For each of the six rows: a screenshot named `qa-<row>-<scenario>-<branch>.png`, plus the
`outcome` string shown in the UI. Store them next to this checklist.

If any box is unticked, say so in the delivery report. An unticked box is a finding, not a
formality.
