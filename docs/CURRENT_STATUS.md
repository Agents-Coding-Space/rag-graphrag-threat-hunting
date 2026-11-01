# TRẠNG THÁI HIỆN HÀNH

**Cập nhật:** 01/11/2026 · **Profile:** `integrated-final-direct-v19` · **Validator:** `source-meaning-validator/v3.1`

Đây là entry point duy nhất cho trạng thái thật của dự án. Mọi tài liệu khác nói profile cũ (v7, v8, v9, v10) là **lịch sử**, không phải trạng thái hiện tại.

---

## 1. Đang ở đâu

| Hạng mục | Trạng thái |
|---|---|
| Mã nguồn, cấu hình, test, frontend | ✅ Chạy được |
| Profile đóng băng | `integrated-final-direct-v19` — pin 107 file, preflight 24/16/0 |
| Test suite | ✅ **6726 passed, 29 skipped, 0 failed, 0 errors** |
| Frontend advisories | ✅ **0 vulnerabilities** (vite 7.3.7, esbuild 0.28.2) |
| Dashboard HTTP-level | ✅ 6/6 tổ hợp scenario × branch |
| Dashboard visual QA | ❌ **Chưa làm** — xem checklist |
| Chấm ngữ nghĩa toàn bộ | ✅ **Đã làm** — 16/16 factual, 15/16 citation (live v19) |
| Human approval ground truth | ❌ Vẫn `pending_human_review` |

---

## 2. Ba kịch bản (giữ nguyên phạm vi đề tài)

| Mã | Kịch bản | Dữ liệu | Số raw record |
|---|---|---|---|
| 3.3.1 | Brute force và đăng nhập bất thường | PurpleSharp AD | 25.993 |
| 3.3.2 | Thực thi PowerShell nghi vấn | MSHTA–PowerShell | 1.127 |
| 3.3.3 | Kết nối mạng bất thường / nghi vấn C2 | Empire Regsvr32 | 2.390 |

Canonical: **29.510** records, dropped = 0. Tri thức: MITRE ATT&CK Enterprise v19.1 (STIX 2.1), 6 rule SigmaHQ + 1 rule tương quan nội bộ, 3 nguồn CTI có snapshot và offset trích dẫn.

---

## 3. Kết quả thực nghiệm — đọc đúng mức

### 3.1 Coverage của cổng bằng chứng (profile v8, 12 câu × 2 nhánh)

| | RAG | GraphRAG |
|---|---:|---:|
| Câu vượt cổng bằng chứng | 5/12 (42%) | 11/12 (92%) |
| Câu bị cổng từ chối | 7/12 | 1/12 |

> **Đây là số câu VƯỢT CỔNG, không phải số câu trả lời đúng.** Chưa chấm nội dung. Không được viết "GraphRAG đúng 92%" hay "GraphRAG thắng 6–0". Xem [Thuc_trang.md](../Thuc_trang.md) mục 6A.

RAG trong đồ án **không phải vector-only baseline**: nhánh RAG dùng `retrieve_hybrid` = BM25 + vector + RRF, và corpus đã chứa cả facts/relationships/evidence chunks.

### 3.2 Smoke 6 nhánh (profile v13, đã chấm nội dung)

| Chỉ số | Kết quả |
|---|---|
| Request đã dùng | **5/6** trần |
| accepted_draft | 5 |
| abstain | 1 (PS-DIRECT/rag — từ chối đúng, 0 request) |
| provider_error | 0 |
| Factual correctness | 5/5 |
| Citation support | 5/5 |
| Trả lời đúng câu hỏi | 5/5 |
| Giữ giới hạn bằng chứng | 6/6 |

Smoke chỉ chứng minh pipeline chạy được trên 6 nhánh đã khai báo. **Không phải kết quả benchmark.**

### 3.3 Bốn tầng đo lường — không gộp

| Tầng | Có số liệu? |
|---|---|
| 1. Coverage truy xuất / answerability | ✅ RAG 5/12, GraphRAG 11/12 |
| 2. Draft acceptance (schema + guardrail + validator) | ✅ 16/16 eligible sinh được draft |
| 3. Độ đúng nội dung & trích dẫn | ❌ **Chưa chấm toàn bộ** |
| 4. Thời gian / request / lỗi | ✅ 16 request, 0 lỗi HTTP, truy xuất 0,41s TB |

---

## 4. Những gì đã sửa theo review (01/11/2026)

11 finding F01–F11. Chi tiết đầy đủ: [REVIEW_FIXES_20261101/findings_resolution.md](REVIEW_FIXES_20261101/findings_resolution.md).

| Finding | Nội dung | Trạng thái |
|---|---|---|
| F01 | Phủ định ở mệnh đề khác che claim C2 dương tính | ✅ Fixed |
| F02 | Status/SubStatus không bind với event | ✅ Fixed |
| F03 | Tham số validator không nằm trong pin | ✅ Fixed |
| F04 | Kết luận "thắng 6–0" vượt bằng chứng | ✅ Fixed |
| F05 | Sai số float và môi trường tái lập | ✅ Fixed |
| F06 | Script regression exit 1 | ✅ Fixed |
| F07 | Không có chế độ kiểm live giới hạn | ✅ Fixed |
| F08 | 3 npm advisory | ✅ Fixed (0 còn lại) |
| F09 | Tài liệu chưa theo profile hiện hành | ✅ Fixed (tài liệu này) |
| F10 | SSE trả verdict MALICIOUS dựng sẵn | ✅ Fixed |
| F11 | Test suite có fixture lịch sử | ✅ Fixed (0 failed) |

---

## 5. Giới hạn phải nêu trung thực

| Giới hạn | Hệ quả |
|---|---|
| Chưa chấm ngữ nghĩa toàn bộ | **Không được kết luận về chất lượng hay ưu thế** |
| Validator chỉ kiểm tập hữu hạn cấu trúc | Ca `AUTH-CTI/GraphRAG` từng được validator cũ đánh `passed` dù ghi sai Status — vượt validator ≠ đúng nội dung |
| Không phải validation độc lập | 12 câu cùng dự án, chưa có holdout ngoài |
| Ground truth chưa duyệt người | `draft_reviewable / pending_human_review` |
| Model miễn phí bên thứ ba | `cmc/reflection/beam:free` có thể đổi/ngừng; không tái lập được sau khi đổi |
| Không có ablation | Chưa chứng minh vector-only không thể trả lời các câu này |
| Dashboard chưa visual QA | Không điều khiển được browser; đã có checklist tay |
| Sai số float khi recompute | Score lệch ~2e-8; hit order và gate không đổi; có tolerance policy v1 |
| Live đầy đủ 16 nhánh | ✅ Đã chạy trên **v19**: 16 request, 15 accepted, 1 validation_failed, 8 abstain |

---

## 6. Việc cần làm tiếp

1. **Chấm ngữ nghĩa** 16 câu trả lời theo rubric 4 tiêu chí → bảng `paired_details.csv`
2. **Đồng bộ Chương 3** luận văn với số liệu thật (dùng [thesis_facts.md](REVIEW_FIXES_20261101/thesis_facts.md))
3. **Kiểm dashboard bằng browser** theo [DASHBOARD_QA_CHECKLIST.md](DASHBOARD_QA_CHECKLIST.md)
4. **Live đủ 16 nhánh** ✅ đã chạy trên v19 (16 request, 15 accepted, 1 validation_failed, 8 abstain)
5. **Duyệt ground truth** để nâng khỏi `pending_human_review`

---

## 7. Đọc tiếp

- [TONG_HOP_CONG_VIEC.md](../TONG_HOP_CONG_VIEC.md) — tổng hợp toàn bộ việc đã làm
- [START_HERE.md](../START_HERE.md) — cài đặt và lệnh chạy
- [Thuc_trang.md](../Thuc_trang.md) — kết quả thực nghiệm chi tiết
- [REPRODUCIBILITY.md](REPRODUCIBILITY.md) — môi trường và dung sai
- [REVIEW_FIXES_20261101/report.md](REVIEW_FIXES_20261101/report.md) — báo cáo sửa lỗi
- [DASHBOARD_QA_CHECKLIST.md](DASHBOARD_QA_CHECKLIST.md) — checklist kiểm dashboard
