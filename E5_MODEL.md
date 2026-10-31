# Chuẩn bị E5 đúng revision

ZIP giữ vector indexes đã tính; query mới vẫn cần embedding model. Không đóng toàn bộ Hugging Face cache hoặc user home.

- Model: `intfloat/multilingual-e5-small`.
- Revision: `614241f622f53c4eeff9890bdc4f31cfecc418b3`.
- Dimension 384, L2 normalization, cosine; prefix `query: ` cho câu hỏi và `passage: ` cho tài liệu.

Sau khi cài Python dependencies, trên máy nhận có mạng, tải đúng snapshot vào Hugging Face cache mặc định:

```powershell
.venv\Scripts\python.exe -c "from huggingface_hub import snapshot_download; snapshot_download(repo_id='intfloat/multilingual-e5-small', revision='614241f622f53c4eeff9890bdc4f31cfecc418b3')"
```

Có thể đặt `HF_HOME` trước khi tải để chọn cache root. Repository hiện dùng cache lookup, nên chỉ chép model vào một thư mục tùy ý chưa chắc đủ. Nếu tải trên máy khác rồi chuyển offline, chuyển đúng snapshot và các blobs/symlink targets mà nó tham chiếu.

Sau khi đã tải đủ, đặt cho phiên PowerShell chạy offline:

```powershell
$env:HF_HUB_OFFLINE='1'
$env:TRANSFORMERS_OFFLINE='1'
```

Hướng dẫn này không được thực thi trong lượt đóng gói. Package verifier không cần model, không tải model hoặc gọi LLM. Nếu thay embedding/revision, rebuild/version corpus-index/pin riêng; không coi index hiện tại tương thích tự động với embedding khác.
