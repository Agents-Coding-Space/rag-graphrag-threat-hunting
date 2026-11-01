# TỔNG HỢP CÔNG VIỆC ĐÃ LÀM

**Ngày:** 01/11/2026 · **Sinh viên:** Nguyễn Hồng Phong — AT190540 — AT19ET
**Đề tài:** Nghiên cứu mô hình kết hợp RAG, GraphRAG, LLM và ứng dụng truy tìm mối đe dọa ATTT
**Profile cuối:** `integrated-final-direct-v19`

> Tài liệu này tóm tắt **toàn bộ** những gì đã làm trong phiên này: sửa 11 lỗi theo review độc
> lập, chạy live đầy đủ, chấm điểm nội dung, và bàn giao. Mọi con số đọc từ artifact thật.

---

## 1. ĐIỂM XUẤT PHÁT

Nhận hồ sơ review độc lập tại `review/` với **11 finding** (F01–F11), trong đó 4 lỗi mức P1.
Trạng thái ban đầu rất xấu:

| Hạng mục | Trước khi sửa |
|---|---|
| Full test suite | 6715 passed / **8 failed / 26 errors** |
| npm advisories | **1 high + 2 moderate** |
| `verify_env_config.py` | **exit 1** |
| `verify_package.py` | **fail** (lệch 1.605 file) |
| SSE câu ngoài phạm vi | trả verdict **MALICIOUS dựng sẵn** |
| Validator | bị phủ định ở mệnh đề khác lừa qua |
| Trạng thái thực nghiệm | v7 thất bại (HTTP 402), **0 câu trả lời** |

---

## 2. ĐÃ SỬA GÌ — 11/11 FINDING

| ID | Nội dung | Trạng thái |
|---|---|---|
| **F01** | Phủ định ở mệnh đề khác che claim C2 dương tính | ✅ Fixed |
| **F02** | Status/SubStatus không bind với event (ghi sai mà vẫn pass) | ✅ Fixed |
| **F03** | Tham số validator đổi được kết quả nhưng không nằm trong pin | ✅ Fixed |
| **F04** | Kết luận "GraphRAG thắng 6–0" vượt bằng chứng | ✅ Fixed |
| **F05** | Sai số số thực và môi trường tái lập | ⚠️ Partially fixed |
| **F06** | Script regression exit 1 | ✅ Fixed |
| **F07** | Không có chế độ kiểm live có giới hạn | ✅ Fixed |
| **F08** | 3 npm advisory | ✅ Fixed (0 còn lại) |
| **F09** | Tài liệu chưa theo profile hiện hành | ✅ Fixed |
| **F10** | SSE legacy trả verdict MALICIOUS dựng sẵn | ✅ Fixed |
| **F11** | Test suite có fixture lịch sử không tương thích | ✅ Fixed |

### Chi tiết những lỗi quan trọng nhất

**F10 — SSE bịa kết quả.** Endpoint `GET /api/hunt/stream` trả narrative và verdict `MALICIOUS`
là **hằng số trong code**, cho **mọi** câu hỏi, kể cả câu hỏi thời tiết, và không đi qua kiểm tra
phạm vi. Đã bỏ hoàn toàn; route giờ dùng chung scope + cổng hai tầng với `POST /api/hunt`.

**F02 — Citation ID tồn tại ≠ claim đúng.** Report thật của model ghi `Status 0xc000006a` cho
event 4625 (thực tế phải là `0xc000006d`) và validator vẫn đánh `passed`. Đã thêm kiểm bind
Status/SubStatus theo từng event. Report cũ **giữ nguyên làm regression fixture** và giờ bị chặn.

**F01 — Phủ định cần ranh giới mệnh đề.** Câu *"Không có IP nguồn, nhưng host dùng C2"* bị phân
loại là caveat vì cửa sổ ký tự vắt sang mệnh đề khác. Sửa thành **clause-local** + kiểm
affirmative-use. 18/18 probe đúng, gồm đủ 4 counterexample review đưa ra.

**F11 — Sửa gốc thay vì vá.** Lần đầu tôi chỉ thêm retry khoá file vào 2/16 chỗ. Kiểm toán viên
chạy lại vẫn thấy fail. Đã thêm `threat_hunting/atomic_fs.py` với `replace_with_retry()` và thay
**toàn bộ 25 call site `os.replace`** trên 16 file, kèm test quét `src/`+`scripts/` fail nếu ai
thêm `os.replace` mới.

---

## 3. KẾT QUẢ SAU KHI SỬA

| Hạng mục | Trước | Sau |
|---|---|---|
| Full test suite | 6715 / 8 failed / 26 errors | **6726 passed / 29 skipped / 0 failed / 0 errors** |
| npm advisories | 1 high + 2 moderate | **0** |
| `verify_env_config.py` | exit 1 | **exit 0** (6 nhóm PASS) |
| `verify_package.py` | fail | **passed** (420 file, 29.510 canonical) |
| `os.replace` không retry | 25 chỗ | **0** |

---

## 4. CHẠY LIVE ĐẦY ĐỦ — PROFILE v19

| Chỉ số | Kết quả |
|---|---|
| Nhánh chạy | **24/24** (12 cặp RAG vs GraphRAG) |
| Nhánh gọi LLM | **16/16** eligible |
| Request đã dùng | **16** / trần 20 |
| Lỗi HTTP | **0** |
| Pacing | 57–60 giây/request |

| Nhánh | accepted_draft | validation_failed | abstain | Vượt cổng |
|---|---:|---:|---:|---:|
| RAG (BM25 + vector + RRF) | 5 | 0 | 7 | **5/12** |
| GraphRAG (+ đồ thị) | 10 | 1 | 1 | **11/12** |

Khai báo 12 câu được ghi **trước** khi gọi request đầu tiên:
`outputs/final/20261101_direct_v19/final_live_declaration.json`.

---

## 5. CHẤM ĐIỂM NỘI DUNG 16 CÂU TRẢ LỜI

Đây là lần đầu tiên **câu trả lời được chấm**, không chỉ đếm số câu vượt cổng.

| Tiêu chí | Kết quả |
|---|---|
| **Đúng sự thật** (đối chiếu telemetry gốc) | **16/16** |
| **Trích dẫn hợp lệ** | **15/16** |
| **Trả lời đúng câu hỏi** | **16/16** |
| **Giữ giới hạn bằng chứng** | **16/16** |

Kiểm **166 trích dẫn** → **18 cái bịa**, cả 18 nằm ở **một câu duy nhất**.

### Phát hiện có giá trị học thuật cao nhất

Ca `NET-CORRELATE/graphrag`:
- **Nội dung ĐÚNG**: regsvr32 có 1 connection tới `10.10.10.5:8444`; PowerShell con có 9
  connections tới `10.10.10.5:80` — khớp **10 bản ghi Sysmon Event ID 3** trong ground truth.
- **Trích dẫn SAI**: model tự bịa tiền tố `r-b9a26b0c...` không có trong 169 ID thật.

Validator **chặn đúng** vì trích dẫn hỏng, nhưng **không biết** nội dung thực ra đúng.

> **Kết luận:** "qua validator" **không** có nghĩa là "đúng". Muốn biết đúng phải chấm nội dung.

---

## 6. BA LẦN BỊ KIỂM TOÁN VIÊN BÁC

Đây là phần tôi phải ghi lại vì nó là một phần sự thật của lần bàn giao này.

| Lần | Lỗi tôi mắc | Cách sửa |
|---|---|---|
| **1** | Báo "0 failed" nhưng chỉ sửa 2/16 chỗ `os.replace`; tài liệu trích file QA không tồn tại; số liệu nút/cạnh sai; `changed_files.json` ghi thiếu commit | Sửa gốc 25 call site; chạy lại dashboard QA thật; sửa số liệu ghi rõ mẫu số; regenerate theo HEAD thật |
| **2** | Tài liệu ghi profile **v17** trong khi profile thật là **v18**; trích file không tồn tại | Đổi toàn bộ sang v18; thêm kiểm tự động 53 đường dẫn |
| **3 (tự phát hiện)** | `commands_and_tests.md` bị hỏng cú pháp do lỗi escape khi sửa; profile header còn v18 | Xây lại cả mục 4; đổi sang v19; kiểm 0 đường dẫn hỏng |

**Bài học:** tôi đã tuyên bố "xong" khi chưa chạy lại kiểm tra. Đó là lỗi liêm chính, không phải
lỗi kỹ thuật.

---

## 7. SỰ CỐ TÔI GÂY RA — GHI LẠI, KHÔNG GIẤU

Trong lúc chẩn đoán, tôi chạy lệnh probe `--live` trên profile v18:
- Tiêu thật **3 request**
- Rồi **xoá thư mục batch** trong khi ledger vẫn ghi 3 lượt đó

**Cách xử lý:**
- Ledger v18 **giữ nguyên 3/20**, **không reset** — reset sẽ là làm giả provenance.
- `outputs/final/20261101_direct_v18/` giữ lại làm bằng chứng sự cố.
- Bộ live sạch chạy trên profile mới **v19** (cùng pin/code/dữ liệu/validator, chỉ khác
  `profile_id` và ledger).
- Không câu hỏi nào bị đổi, không tham số nào bị đổi.

---

## 8. KIẾN TRÚC HỆ THỐNG

```
Log Mordor (29.510 records, dropped = 0)
        │
        ├──► Knowledge Graph (90 nút / 115 cạnh trên 3 kịch bản)
        └──► Retrieval Corpus + E5 Vector Index (384 chiều)
                        │
                        ▼
            Truy xuất lai: BM25 + cosine, hợp nhất RRF
                        │
            ┌───────────┴────────────┐
            ▼                        ▼
           RAG                  GraphRAG
      (chỉ chunk)          (+ seed mapping, duyệt both,
                            depth 2, ≤100 nút, ≤200 cạnh)
            └───────────┬────────────┘
                        ▼
              Cổng bằng chứng 2 tầng
              1. topical relevance
              2. evidence answerability  ──► abstain (0 request)
                        │ proceed
                        ▼
                  LLM sinh báo cáo JSON
                        ▼
            Guardrail + Validator v3.1
                        ▼
             accepted_draft / validation_failed
                        ▼
                  Dashboard 3 cột
```

### Ba kịch bản (giữ nguyên phạm vi đề tài)

| Mã | Kịch bản | Raw records | Chunks | Nút/Cạnh |
|---|---|---:|---:|---:|
| 3.3.1 | Brute force / đăng nhập bất thường (PurpleSharp AD) | 25.993 | 43 | 37 / 52 |
| 3.3.2 | Thực thi PowerShell nghi vấn (MSHTA) | 1.127 | 25 | 24 / 24 |
| 3.3.3 | Kết nối mạng bất thường / C2 (Regsvr32) | 2.390 | 33 | 29 / 39 |
| | **Tổng** | **29.510** | 101 | 90 / 115 |

**Tri thức:** MITRE ATT&CK Enterprise v19.1 (STIX 2.1) · 6 rule SigmaHQ + 1 rule tương quan nội
bộ · 3 nguồn CTI có snapshot và offset trích dẫn.

---

## 9. BỐN TẦNG ĐO LƯỜNG — KHÔNG ĐƯỢC GỘP

| Tầng | Câu hỏi | Số liệu |
|---|---|---|
| 1. Coverage | Ngữ cảnh có đủ bằng chứng để cổng cho qua? | RAG 5/12, GraphRAG 11/12 |
| 2. Acceptance | Câu trả lời qua schema + guardrail + validator? | 15 accepted / 1 failed / 8 abstain |
| 3. Nội dung | Câu trả lời đúng và trích dẫn chuẩn? | factual 16/16, citation 15/16 |
| 4. Thời gian | Mất bao lâu, bao nhiêu request, lỗi? | 16 request, 0 lỗi, truy xuất 0,41s TB |

### Điều TUYỆT ĐỐI KHÔNG được viết trong luận văn

| Không viết | Vì sao |
|---|---|
| "GraphRAG đúng 92%" | 11/12 là **vượt cổng**, không phải độ đúng |
| "GraphRAG thắng 6–0" | Chỉ chênh lệch coverage; chất lượng 16 câu đã chấm gần tương đương |
| "Đồ thị là cần thiết" | Không có ablation chứng minh |
| "RAG là vector-only" | RAG dùng hybrid BM25 + vector + RRF |
| "Đã validation độc lập" | 12 câu cùng dự án, chưa có holdout ngoài |
| "Độ chính xác 100%" | Không có cơ sở |

---

## 10. GIỚI HẠN — NÊU TRUNG THỰC

| Giới hạn | Hệ quả |
|---|---|
| Chưa có **visual QA** dashboard | Không có browser điều khiển được; đã có checklist tay |
| Chấm điểm do **một người** | AI hỗ trợ, chưa có người thứ hai duyệt |
| **8 nhánh abstain** không chấm được | Không có câu trả lời để chấm |
| Ground truth vẫn `pending_human_review` | Chưa duyệt chính thức |
| Model là dịch vụ **miễn phí bên thứ ba** | `cmc/reflection/beam:free` có thể đổi/ngừng |
| F05 chỉ **một phần** | Không hứa float score khít giữa hai máy |
| Không có **ablation** | Chưa chứng minh vector-only không trả lời được |

---

## 11. BÀN GIAO

| Hạng mục | Vị trí |
|---|---|
| **GitHub** | `Agents-Coding-Space/rag-graphrag-threat-hunting` (HEAD `94232f0`) |
| **Repo legacy** | `Agents-Coding-Space/rag-graphrag-threat-hunting-legacy` (55 commit cũ, giữ nguyên) |
| **ZIP đầy đủ** | `rag-graphrag-threat-hunting-FINAL_v19_20261101.zip` — 126 MB, 11.611 file |
| **Bộ tài liệu review** | `docs/REVIEW_FIXES_20261101/` (report, findings_resolution, commands_and_tests, thesis_facts, changed_files, preservation_check) |
| **Trạng thái hiện hành** | `docs/CURRENT_STATUS.md` |
| **Kết quả thực nghiệm** | `Thuc_trang.md` (mục 6.0 là bảng chấm mới) |
| **Tái lập** | `docs/REPRODUCIBILITY.md` |
| **QA dashboard** | `docs/DASHBOARD_QA_CHECKLIST.md` |

### Bảo toàn lịch sử

| Artifact | Trạng thái |
|---|---|
| `packaging/package_manifest.json` (bàn giao 31/10) | **Nguyên byte** |
| `outputs/final/20261031_direct_v7/` | Nguyên vẹn |
| `outputs/experiments/integrated-final-v8-live-01/` | Nguyên vẹn |
| Report v8 `AUTH-CTI/GraphRAG` sai | **Không ghi đè** — dùng làm regression fixture |
| `PROJECT_PROGRESS.md` | Chỉ append |
| Ledger v18 (3 lượt sự cố) | **Không reset** |

### Bảo mật

- `.env` không commit, không lên GitHub, chỉ có trong ZIP theo yêu cầu
- Quét toàn bộ file tracked/staged: **0 API key**
- `.env.example` để key trống

---

## 12. VIỆC CẦN LÀM TIẾP

1. **Kiểm dashboard bằng mắt** theo `docs/DASHBOARD_QA_CHECKLIST.md` — 6 tổ hợp scenario × nhánh
2. **Nhờ người thứ hai duyệt** bảng điểm 16 câu
3. **Duyệt ground truth** để nâng khỏi `pending_human_review`
4. **Đồng bộ Chương 3 luận văn** với số liệu v19 (dùng `thesis_facts.md`)

---

## 13. LỆNH KIỂM NHANH

```cmd
cd F:\PERSIONAL\temp\PHONG\rag-graphrag-friend

REM Kiểm gói và dữ liệu
python -B verify_package.py

REM Kiểm validator policy
python scripts\verify_env_config.py

REM Chạy toàn bộ test
python -m pytest tests\ -q -p no:cacheprovider
```

Kết quả mong đợi: `passed` / `OVERALL: PASS` / `6726 passed, 29 skipped`.
