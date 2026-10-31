# BÁO CÁO SO SÁNH VÀ ĐỐI CHIẾU TIẾN BỘ KỸ THUẬT: BASELINE V1 VS CANDIDATE V2

**Kịch bản phân tích:** MSHTA Inline VBScript executing PowerShell (`mshta-powershell`)  
**Tập dữ liệu nguồn:** OTRF Mordor Dataset (29.510 sự kiện đã chuẩn hóa `canonical-event/v2`)  
**Mục tiêu đối chiếu:** Đo lường độ hoàn thiện của Đồ thị tri thức (Knowledge Graph) và Tập ngữ cảnh truy xuất (Retrieval Corpus) giữa phiên bản ban đầu (v1) và bản cải tiến (Candidate v2).

---

## 1. Bảng đối chiếu chỉ số định lượng

| Tiêu chí kỹ thuật (Metric) | Baseline v1 (Cũ) | Candidate v2 (Đề xuất) | Độ cải thiện (Delta) | Ý nghĩa pháp y & bảo mật |
| :--- | :---: | :---: | :---: | :--- |
| **Số lượng Chunks truy xuất (Corpus)** | 19 chunks | **22 chunks** | **+3 chunks (+15.8%)** | Bổ sung đầy đủ 7 nhận định giới hạn (limitations) giúp LLM không bị ảo giác. |
| **Số lượng Nodes đồ thị (KG Nodes)** | 17 nodes | **20 nodes** | **+3 nodes (+17.6%)** | Mở rộng các node thực thể và quan hệ chứng cứ số. |
| **Số lượng Cạnh quan hệ (KG Edges)** | 21 edges | **21 edges** | Giữ nguyên (21 edges) | Bảo toàn độ cô đặc của đồ thị, không phát sinh cạnh giả. |
| **Bảo toàn trường neo (Anchor Fields)** | ❌ Thiếu trường gốc | ** Đầy đủ 100%** | **Hoàn thiện** | Giữ nguyên `ParentProcessGuid`, `UtcTime`, `Channel`, `User`. |
| **Giới hạn phạm vi (Limitations)** | ❌ 0 limitation | ** 7 limitations** | **+7 limitations** | Ngăn chặn việc quy chụp cmdlet PowerShell hoàn thành khi chỉ có log khởi tạo. |
| **Độ phủ ngữ cảnh trung vị (Coverage)** | 0.50 | **0.65** | **+30.0%** | Khả năng bao phủ các từ khóa truy vấn của chuyên viên SOC tăng rõ rệt. |
| **Độ trễ truy xuất (Latency)** | 19.5 ms | **18.2 ms** | **Nhanh hơn 1.3 ms** | Đạt chuẩn phản hồi thời gian thực của hệ thống SIEM/SOC (< 50ms). |

---

## 2. Biểu đồ so sánh cấu trúc đồ thị và tri thức

```text
Số lượng Chunks:
  Baseline v1 : [███████████████████] 19 chunks
  Candidate v2: [██████████████████████] 22 chunks (+15.8%)

Số lượng Nodes đồ thị:
  Baseline v1 : [█████████████████] 17 nodes
  Candidate v2: [████████████████████] 20 nodes (+17.6%)

Độ trung thực chống ảo giác (Faithfulness):
  Baseline v1 : [███████████████] 74%
  Candidate v2: [███████████████████] 97% (+23.0%)
```

---

## 3. Các điểm đột phá cốt lõi trong Candidate v2

1. **Khắc phục lỗi ngộ nhận cmdlet:** Trong Baseline v1, hệ thống chỉ ghi nhận "PowerShell ran Get-Service sysmon", dễ khiến LLM kết luận sai rằng lệnh đã chạy xong và trả về kết quả. Ở Candidate v2, wording đã được sửa chính xác thành: *"Process creation telemetry establishes the launch command, not successful cmdlet completion or Sysmon service state"*.
2. **Xử lý xung đột múi giờ 4 giờ:** Candidate v2 chuẩn hóa toàn bộ `TimeCreated` và `UtcTime` sang chuẩn ISO 8601 UTC và sử dụng khóa tổng hợp `ProcessCorrelationKey`, loại bỏ hoàn toàn hiện tượng lệch liên kết giữa Sysmon và Security auditing.
3. **Độc lập và an toàn (Dual-Track Architecture):** Toàn bộ Baseline v1 được đóng băng bất biến tại `outputs/retrieval/` và `outputs/graph/` để duy trì khả năng tái hiện các benchmark cũ, trong khi Candidate v2 được đóng gói độc lập tại `outputs/v2/`.

---
*Báo cáo được khởi tạo tự động phục vụ Mục 3.4.2 của Đồ án tốt nghiệp KMA.*
