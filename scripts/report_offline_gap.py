"""Build the requirement/status handoff from saved offline evidence; no benchmark."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys
import yaml

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "src"))
from scripts.inventory_offline_inputs import write_json
from threat_hunting.evidence.slice_provenance import digest
from threat_hunting.mordor.format_detection import detect_format
from threat_hunting.mordor.parser import iter_records


def read(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, required=True, help="New offline artifact package")
    args = parser.parse_args()
    base = args.root
    inventory = read(base / "input_inventory.json")
    survey = read(base / "purplesharp_v2/authentication_survey.json")
    correlation = read(base / "purplesharp_v2/authentication_correlation.json")
    spraying = read(base / "purplesharp_v2/password_spraying_candidates.json")
    logons = read(base / "purplesharp_v2/logon_investigation.json")
    rc4 = read(base / "purplesharp_v2/sigma_rc4_evaluation.json")
    cti = read(base / "cti/cti_corpus.json")
    mitre = read(base / "purplesharp_v2/mitre_resolution.json")
    pcap = read(base / "purplesharp_pcap_inventory.json")
    knowledge = []
    for item in inventory["inputs"]:
        if item["filename"].endswith(".yml") and "selected" in Path(item["path"]).parts:
            rule = yaml.safe_load(Path(item["path"]).read_text(encoding="utf-8-sig"))
            knowledge.append({**item, "metadata": {key: str(value) if key in {"date", "modified"} else value for key, value in rule.items()},
                              "provenance_validated": digest(Path(item["path"])) == item["sha256"],
                              "evaluation_this_milestone": "security_offline_reference_subset" if item["filename"] == rc4["rule_filename"] else "metadata_inventory_only"})
    write_json(base / "sigma_inventory.json", {"schema_version": "sigma-knowledge-inventory/v1", "rules": knowledge})
    linked = []
    for link in cti["links"]:
        item = {**link, "citation_base_path": "cti/"}
        if link["target_kind"] == "sigma_rule":
            target = next(rule for rule in knowledge if rule["filename"] == link["target_id"])
            item["target_knowledge_provenance"] = {"path": target["path"], "sha256": target["sha256"], "sigma_id": target["metadata"]["id"]}
        elif link["target_kind"] == "technique":
            target = next(t for t in mitre["techniques"] if t["external_id"] == link["target_id"])
            item["target_knowledge_provenance"] = {**target, "bundle_sha256": mitre["source_sha256"], "collection_version": mitre["collection_version"]}
        else:
            item["target_knowledge_provenance"] = {"origin": "project_behavior_concept", "observed_telemetry_assertion": False}
        linked.append(item)
    write_json(base / "cti_knowledge_links.json", {"schema_version": "cti-knowledge-context-links/v1", "links": linked,
                                                 "review_status": "pending_human_review", "evidence_layer": "cti_context"})
    # Fresh raw anchor inspection for the other two scenarios is an inventory,
    # not a new full rule evaluation or a benchmark run.
    anchors = {}
    requests = {"cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json": {4, 30, 36, 275, 398, 422},
                "empire_launcher_sct_regsvr32_2020-07-21232741.json": {97, 219, 224, 1001}}
    keep = ("EventID", "SourceName", "Hostname", "TimeCreated", "@timestamp", "UtcTime", "Image", "NewProcessName",
            "ProcessGuid", "ParentProcessGuid", "ProcessId", "NewProcessId", "ProcessID", "ParentProcessId", "ParentProcessID",
            "ParentImage", "ParentProcessName", "CommandLine", "ParentCommandLine", "SourceIp", "SourcePort", "DestinationIp", "DestinationPort", "Initiated")
    for filename, lines in requests.items():
        item = next(i for i in inventory["inputs"] if i["filename"] == filename)
        path = Path(item["path"])
        rows = []
        for parsed in iter_records(path, detect_format(path).source_format):
            if parsed.raw_record_ref in {f"jsonl:line:{n}" for n in lines}:
                rows.append({"source_file": filename, "source_sha256": item["sha256"], "raw_record_ref": parsed.raw_record_ref,
                             "original_fields": {k: parsed.data[k] for k in keep if k in parsed.data}, "status": "observed"})
        anchors[filename] = rows
    write_json(base / "other_scenario_anchors.json", {"schema_version": "raw-anchor-inventory/v1", "observations": anchors,
                                                     "scope": "Fresh anchor field check only; no new behavior label or whole-scenario completion claim."})
    matrix = [
        {"requirement": "MITRE ATT&CK, Sigma Rule và CTI report", "current": "10 external inputs có đủ ở sibling project; CTI chưa có trong data roots trước task.",
         "added": "Pin/validate ATT&CK v19.1; inventory 6 Sigma; 2 CTI snapshots, 4 context chunks, 11 provenance links.",
         "blocker": "Chưa đưa CTI vào corpus/graph/index version mới và kiểm tra retrieval; không phải thiếu raw input.",
         "evidence": ["input_inventory.json", "sigma_inventory.json", "purplesharp_v2/mitre_resolution.json", "cti/cti_corpus.json"]},
        {"requirement": "3.3.1 Kịch bản brute force và đăng nhập bất thường", "current": "Checkpoint chỉ launch slice; dataset đầy đủ 25.993 raw/canonical records thực sự có.",
         "added": "203 auth/context observations, 7 endpoint/DC pairs -> 7 attempts/7 accounts, 1 suspected spray cluster, 5 RC4 matches; 49 successes and 43 privilege-session context links.",
         "blocker": "Chưa có GT/knowledge consumers mở rộng và evaluation riêng. Không có baseline hành vi dài hạn để kết luận từng success bất thường, không có password để chứng minh dùng cùng mật khẩu hay compromise.",
         "evidence": ["purplesharp_v2/authentication_survey.json", "purplesharp_v2/authentication_correlation.json", "purplesharp_v2/logon_investigation.json", "purplesharp_v2/scenario_ground_truth.json"]},
        {"requirement": "3.3.2 Kịch bản thực thi PowerShell nghi vấn", "current": "MSHTA core hai process creations/four observations, GT và retrieval prototype cùng saved comparison.",
         "added": "Tìm lại raw và Sigma originals; fresh anchor check; CTI context cho process lineage và command monitoring.",
         "blocker": "Cần corpus/graph tích hợp CTI và đánh giá câu hỏi phân tích nghi vấn. Launch Get-Service không chứng minh cmdlet completion/output/service state.",
         "evidence": ["other_scenario_anchors.json", "cti/cti_corpus.json", "../../review/mshta-ground-truth/review_report.md"]},
        {"requirement": "3.3.3 Kịch bản kết nối mạng bất thường hoặc nghi vấn C2", "current": "Regsvr32 scriptlet/process/network selected slice; raw 2.390 records có trên máy.",
         "added": "Tìm lại 3 Sigma originals; raw anchor 97/224/1001; resolve T1218.010 trong ATT&CK source; CTI context scriptlet/correlation.",
         "blocker": "Cần full process/network correlation và review Sigma trên raw rồi ground truth/corpus version mới. Network endpoint không tự chứng minh HTTP content hoặc confirmed C2.",
         "evidence": ["other_scenario_anchors.json", "sigma_inventory.json", "purplesharp_v2/mitre_resolution.json", "cti/cti_corpus.json"]},
        {"requirement": "Giữ checkpoint 15×2 và đề cương/mục lục", "current": "Hai saved runs là regression trên selected slices, không phải hoàn thành ba scenario.",
         "added": "Bảng acceptance riêng theo đúng ba tên người dùng chốt; artifacts mới tách riêng, baseline hash audit.",
         "blocker": "Chưa có kết quả đánh giá scenario mở rộng; không dùng checkpoint cũ để thay thế.",
         "evidence": ["input_inventory.json", "integrity.json", "../../review/rag_graphrag_combined_semantic_20261027/report.md"]},
    ]
    write_json(base / "requirements_matrix.json", {"schema_version": "requirements-gap-matrix/v1", "review_status": "pending_human_review", "rows": matrix})
    text = ["# Bàn giao offline theo yêu cầu — 30/10/2026", "",
            "Giữ nguyên đề cương/mục lục và checkpoint 15×2. Đây là milestone kiểm kê + evidence/correlation xác thực + CTI ingestion, không phải tuyên bố hoàn thành cả ba kịch bản. Artifacts mới đều `pending_human_review`; draft GT là `draft_reviewable`, techniques giữ `candidate`.", "",
            "Yêu cầu hiện tại có ưu tiên so với PROJECT_CONTEXT/AGENTS ngày 14/10 và checklist ngày 27/10: dùng đúng ba tên bên dưới; PurpleSharp và CTI là công việc phải bổ sung, không chuyển thành hướng phát triển để giảm yêu cầu. Không sửa các tài liệu cũ, Word/PDF, mục lục hoặc checkpoint.", "",
            "Đã đọc PROJECT_CONTEXT.md, AGENTS.md, PROJECT_PROGRESS.md, MASTER_PLAN.md, docs/human_approval.md, EXPERIMENTAL_RESULTS.md, EXPERIMENTAL_SUBMISSION_CHECKLIST.md, review_report/review_manifest MSHTA và report tổng hợp 27/10. Hồ sơ 14/10 không phản ánh hết code LLM/UI mới; code hiện có không đồng nghĩa đủ scenario coverage. MSHTA review manifest cũ có human approval đã ghi nhận ngày 15/10; task này giữ nguyên, không chuyển approval đó sang artifacts mới.", "",
            "## Bảng yêu cầu – hiện trạng – bổ sung – blocker", "",
            "| Yêu cầu | Hiện trạng | Phần đã bổ sung | Blocker/công việc còn lại |", "|---|---|---|---|"]
    for row in matrix:
        text.append(f"| {row['requirement']} | {row['current']} | {row['added']} | {row['blocker']} |")
    text += ["", "Machine-readable matrix và đường dẫn bằng chứng: [requirements_matrix.json](requirements_matrix.json).", "",
             "## Inputs thực sự có và phạm vi tìm kiếm", "",
             "Đã kiểm tra data root cấu hình tại bản làm việc và dự án đã biết: `D:/rag-graphrag-friend/data` (không tồn tại) và `D:/rag-graphrag-threat-hunting/data` (tồn tại). Đối chiếu manifest normalization và cấu hình MITRE; không quét các SOC/NIDS/project không liên quan. Sibling `data/processed` rỗng. Canonical đang dùng nằm tại `outputs/canonical/mordor-selected-v2/files/` của bản làm việc.", "",
             "**Không thiếu filename nào trong 10 selected external inputs.** Sáu Sigma có bản trong `selected` và bản mirror SigmaHQ cùng hash (16 path hits cho 10 filenames); evaluator chọn bản `selected`, không thay nguồn. ATT&CK khớp manifest v19.1 và hash bundle. Các build_manifest ngày 25/10 ghi unavailable là trạng thái lần chạy cũ trong repo thiếu data, không còn là kết luận hiện tại; không sửa manifests lịch sử.", "",
             "| Raw input | Bytes | Format/encoding | Records fresh scan |", "|---|---:|---|---:|"]
    for item in inventory["inputs"]:
        if "record_count" in item:
            text.append(f"| `{item['filename']}` | {item['size_bytes']:,} | {item['format']}/{item['encoding']} | {item['record_count']:,} |")
    text += ["", "Đã xác minh SHA-256 raw/canonical với manifest: 29.510 raw → 29.510 canonical lịch sử, dropped=0; raw counts vừa được đọc lại toàn bộ. Riêng PurpleSharp đã re-normalize trong bộ nhớ và so sánh bằng nhau từng canonical event trên toàn file. Không ghi normalization đè lên baseline.", "",
             "| Loại | Đường dẫn thực tế |", "|---|---|"]
    for item in inventory["inputs"]:
        if "sigma-master" not in item["path"]:
            text.append(f"| {'Raw' if 'record_count' in item else 'Sigma' if item['filename'].endswith('.yml') else 'MITRE'} | `{item['path']}` |")
    text += ["", "Đường dẫn canonical, kích thước, hashes, providers và Event ID distribution từng log: [input_inventory.json](input_inventory.json). Toàn bộ metadata sáu Sigma (title/id/status/logsource/detection/tags/level/references) được safe-load tại [sigma_inventory.json](sigma_inventory.json). MSHTA/Regsvr32 chỉ kiểm kê metadata và fresh raw anchors ở task này; không nói đã re-evaluate toàn bộ selected rules của hai log.", "",
             f"Ngoài JSONL PurpleSharp còn có PCAP `.cap` gốc: {pcap['size_bytes']:,} bytes, classic PCAP/Ethernet, {pcap['packet_count']:,} packets. Đọc streaming toàn capture ở mức header, không xuất payload xác thực. Thời gian theo PCAP epoch {pcap['time_window_from_pcap_epoch']['start']} → {pcap['time_window_from_pcap_epoch']['end']}. Packet counts không phải auth attempts; chưa nối identity PCAP với log, không lấy IP capture điền vào IpAddress='-'. [pcap inventory](purplesharp_pcap_inventory.json).", "",
             "Reference JSON `psh_powershell_httplistener_2020-11-0204130683.json` vẫn có trong raw tree, read-only và excluded; không dùng thay dataset MSHTA. Không tìm thấy CTI reports có sẵn trong các data roots đã kiểm tra. Hai reports bên dưới là **new acquired inputs**, không giả là input gốc.", "",
             "## PurpleSharp: phân tích toàn bộ log", "",
             f"Đã đọc {survey['raw_records_read']:,} raw + {survey['canonical_records_read']:,} canonical; khớp {survey['raw_canonical_equal_records']:,} events; dropped=0. Giữ {len(survey['observations'])} observations xác thực/context; {survey['raw_records_read'] - len(survey['observations']):,} records còn lại không thuộc bộ Event IDs xác thực đang khảo sát, không bị xóa. Khung canonical: {survey['time_window']['start']} → {survey['time_window']['end']}.", "",
             "| Event ID | Count | Ý nghĩa trong khảo sát |", "|---|---:|---|"]
    descriptions = {"4624": "Successful logon; không tự coi bất thường", "4625": "Endpoint failed logon", "4776": "DC credential validation failure; view tương ứng", "4769": "Service-ticket requests, 12 AES + 5 RC4", "4672": "Special-privilege session context", "4627": "Group membership context", "4634": "Logoff context"}
    for eid, count in survey["auth_event_ids"].items():
        text.append(f"| {eid} | {count} | {descriptions.get(eid, 'Không có trong file đã đọc')} |")
    text += ["", "Profiles chi tiết theo Event ID gồm tài khoản, host/đích, workstation/IP nguồn, status/substatus, kết quả, logon type, ticket fields, min/max thời gian, missing/multivalued fields: [authentication_survey.json](purplesharp_v2/authentication_survey.json). Không suy Event 4768/4771 tồn tại từ mô tả trong MASTER_PLAN; counts thực tế bằng 0. Các ví dụ entity/IP trong tài liệu thiết kế không được dùng làm evidence.", "",
             "Canonical v2 không có Status/SubStatus/Workstation/ticket fields; module hydrate từ raw đã pin hash và đối chiếu từng record. `TargetUserName` là target account; `SubjectUserName` là actor/context. Đích event lấy `Hostname`, không dùng host của collector `wec.internal.cloudapp.net`. Missing `-` giữ nguyên trong original fields và biểu diễn null ở derived fields; list/dict không ép thành scalar để join.", "",
             "### Correlation và suspected spraying", "",
             "| Target account | Endpoint 4625 | DC 4776 |", "|---|---|---|"]
    for attempt in correlation["attempts"]:
        text.append(f"| {attempt['target_account']} | `{attempt['raw_record_refs'][0]}` | `{attempt['raw_record_refs'][1]}` |")
    text += ["", "7 endpoint failures có host `WORKSTATION5.theshire.local`, WorkstationName=`WORKSTATION5`, caller `PurpleSharp.exe`, PID `0x1d60`, LogonType=`2`, Status=`0xc000006d`, SubStatus=`0xc000006a`; IP nguồn không có. 7 DC views trên `MORDORDC.theshire.local`, Workstation=`WORKSTATION5`, Status=`0xc000006a`, thiếu target domain/IP. Không dựng quan hệ IP → targeted account.", "",
             "Ghép một-một khi account/workstation/failure code phù hợp, timestamp canonical cách ≤1 giây, không có domain/IP xung đột khi cả hai biết. Chỉ nhận cặp mutually unique; ambiguous candidates bị loại khỏi threshold và giữ lại để review. Cặp giữ `inferred` vì không có shared attempt ID và DC thiếu domain. SourceContext gồm workstation/IP, domain, endpoint host, caller process/PID; đây là grouping thận trọng, có thể bỏ sót spraying trải nhiều caller processes.", "",
             "14 observations → **7 inferred attempts**, ambiguous=0; **1 candidate cluster** trên 7 tài khoản trong **0,012 giây**, từ 08:29:55.210 đến 08:29:55.222 theo canonical. Detector dùng sliding **60 giây**, ≥5 distinct accounts, không dùng cửa sổ 300 giây của thiết kế cũ; không đếm 4625 và 4776 thành 14 lần thử. Mỗi account chỉ có một failure attempt trong group: đủ hỗ trợ nghi vấn spraying/multi-account failures; chưa chứng minh cùng password hoặc repeated guessing vào một account.", "",
             "Derived rule mới: `configs/knowledge/derived/win_security_password_spray_correlation.yml`, multi-document value_count trên normalized-auth-attempt/v1. Đây là project-defined input và reference implementation offline; production Sigma evaluator không hỗ trợ custom taxonomy/correlation. Không gọi output này là luật SigmaHQ gốc hoặc backend conversion đã kiểm chứng. [attempt stream](purplesharp_v2/normalized_auth_attempts.jsonl), [correlation](purplesharp_v2/authentication_correlation.json), [findings](purplesharp_v2/password_spraying_candidates.json).", "",
             "### Đăng nhập bất thường và RC4", "",
             "49 Event 4624 đều LogonType=3: 19 pgustavo, 24 MORDORDC$, 3 ANONYMOUS LOGON và 3 machine-account records khác. Đích: 39 MORDORDC, 5 WORKSTATION6, 5 WORKSTATION7. 35/49 thiếu source IP; 46/49 thiếu source workstation. 46 Kerberos và 3 NTLM logons. Đây là phân bố quan sát, không phải 49 attacks.", "",
             f"Với pgustavo có 19 same-name temporal candidates ±60 giây so failure của account đó: 2 trước, 17 sau; giữ candidate và basis='same_account_name_and_time_only'. Có {len(logons['privileged_logon_context_links'])} context links 4624↔4672 dựa cùng host/account/logon ID trong một giây, giữ inferred. Privileged session hoặc success sau lỗi không chứng minh compromise; thiếu nguồn/session/credential chung và baseline dài hạn. [logon investigation](purplesharp_v2/logon_investigation.json).", "",
             "17 Event 4769 đều Status=0x0 (ticket request success, không phải cracking success); 5 RC4 matches tại lines 1125, 1136, 1140, 1144, 1148. Requester `pgustavo@THESHIRE.LOCAL`, source `::ffff:172.18.39.5`, đích DC; services sysmonsvc/nxlogsvc/defensesvc/mordorsvc/otrsvc, TicketOptions=0x40810000, TicketEncryptionType=0x17. Rule condition `selection and not reduction` được đánh giá với ServiceName suffix `$` exclusion; unsupported expression bị từ chối. Không suy cracking, password recovery, SPN privilege hoặc account compromise. [Sigma evaluation](purplesharp_v2/sigma_rc4_evaluation.json).", "",
             "T1110.003/T1558.003 được resolve từ active STIX objects trong bundle v19.1 và liên kết finding/evidence dưới nhãn candidate. T1218.005/.010 cũng được resolve phục vụ inventory CTI, không tự sửa assessments cũ. [ATT&CK resolution](purplesharp_v2/mitre_resolution.json). `/t T1110.003,T1558.003,T1135,T1021.006` chỉ là launch intent; evidence extraction không lấy danh sách này làm đáp án kỹ thuật.", "",
             "Timestamp giữ canonical hiện có; raw EventTime không có timezone, khác @timestamp/canonical khoảng bốn giờ cùng độ trễ thu thập. Không hiệu chỉnh timezone hoặc gọi 12 ms là thời lượng thực chắc chắn của source activity. PCAP epoch và log source không được tự gộp thành clock đã xác minh.", "",
             "Draft reviewable có required scenario/evidence/provenance/Sigma/MITRE/relationship/questions/notes tại [scenario_ground_truth.json](purplesharp_v2/scenario_ground_truth.json). Đây là schema draft độc lập `authentication-ground-truth-draft/v1`, chưa chuyển thành runtime GT v3 hoặc được người dùng phê duyệt. `purplesharp/` là bản trung gian trước khi bổ sung profiles và privileged-session context; **dùng purplesharp_v2/** cho bàn giao này.", "",
             "## CTI reports, chunks và provenance", "",
             "Nguồn trực tiếp từ đơn vị nghiên cứu; chỉ dùng bối cảnh kỹ thuật. Có raw HTTP HTML snapshot (new input), fetch metadata URL/final URL/status/accessed_at/encoding/hash, text view hash, title/publisher/publication metadata, section/line/character offsets và context links. Publication dates lấy từ publisher HTML JSON-LD; report URL có thể cập nhật nội dung, nên hash snapshot là định danh nội dung lần truy cập.", "",
             "| Report | Publisher | Published metadata | Modified metadata | Access UTC | Snapshot SHA-256 |", "|---|---|---|---|---|---|"]
    for source in cti["sources"]:
        text.append(f"| [{source['title']}]({source['url']}) | {source['publisher']} | {source['publication_date']} | {source['publisher_modified_at']} | {source['accessed_at']} | `{source['snapshot_sha256']}` |")
    text += ["", "Red Canary cung cấp bối cảnh điều tra MSHTA sinh PowerShell/cmd và thu thập command/lineage. Uptycs mô tả scriptlet qua regsvr32 và ngữ cảnh correlation parent/child. Không đem các chiến dịch, IOC, download hay malicious verdict của reports gán cho Mordor. Bốn chunks là analyst paraphrases, các anchors ngắn định vị chính xác trong text đã hash.", "",
             "11 links chỉ có `provides_technical_context_for` tới behavior/technique/Sigma filename, không có CTI→observed-event/host-compromised/confirmed-C2 edge. `cti_context`, `observed` telemetry và `candidate` assessment ở các lớp/artifacts riêng. [cti_corpus.json](cti/cti_corpus.json), [knowledge links](cti_knowledge_links.json) bind cả target Sigma ID/hash/path hoặc active ATT&CK STIX object + bundle hash/version. Chưa thêm vào runtime corpus/graph/index; reference answers và expected labels không làm ingestion input.", "",
             "## Câu hỏi, bằng chứng tối thiểu, outputs và tiêu chí đạt", "",
             "| Kịch bản giữ nguyên tên | Câu hỏi điều tra | Bằng chứng tối thiểu | Outputs cần có | Tiêu chí đạt |", "|---|---|---|---|---|"]
    acceptance = [
        ("3.3.1 Kịch bản brute force và đăng nhập bất thường", "Nguồn nào thử những account nào, nhịp/tần suất/kết quả? Views có trùng? Success/privilege/session nào liên quan và quan hệ nào chưa đủ?", "Full auth survey; failed status + account/source context/time; dedup endpoint/DC; success distribution trước/sau, missingness; rule và ATT&CK/CTI context đúng lớp.", "Timeline, attempt groups, source-account graph, suspected spray/abnormal pattern assessment + competing explanations/limits + draft GT.", "Tái lập đủ full-file counts, ≥5 distinct accounts/60s cho hypothesis đã chọn, không double-count/fake IP; phân tích thực chất logon context. Không đòi chứng minh attack success; không gọi mọi success là abnormal. Offline evidence đã có, integrated scenario/evaluation còn thiếu."),
        ("3.3.2 Kịch bản thực thi PowerShell nghi vấn", "Ai sinh MSHTA/PowerShell, command gì làm hành vi đáng ngờ; Sigma/MITRE/CTI hỗ trợ mức nào?", "Hai creation groups 4/275 và 30/398; host/process identity/parent/command; giữ timestamp và completion caveats.", "Actor-bound chain + exact command, detection hypothesis/technique context/citations, trả lời điều tra và giới hạn.", "Giải thích VBScript proxy execution và PowerShell child bằng evidence, không JavaScript/download/C2 promotion; Get-Service chỉ launch. Cần kết hợp knowledge corpus/version và scenario question coverage; không đòi cmdlet thành công."),
        ("3.3.3 Kịch bản kết nối mạng bất thường hoặc nghi vấn C2", "Regsvr32/PowerShell nào kết nối đích nào khi nào, command HTTP scriptlet có quan hệ gì với flow; điều gì chỉ là nghi vấn?", "Raw command/parent/child refs97/224; Sysmon3 ref1001 và các child-network records, nối host+GUID/time; original Sigma metadata + ATT&CK/CTI context.", "Process→URL→network timeline/graph, destination counts/intervals, rule comparisons, suspicious/C2 hypothesis và alternative explanations.", "Chứng minh process-bound connections và lý do đáng ngờ; không cần confirmed C2/payload success. Không UNC/missing-/n anomaly; bytes/content/compromise không biết phải giữ unknown. Full child flow correlation và review còn cần làm."),
    ]
    for row in acceptance:
        text.append("| " + " | ".join(row) + " |")
    write_json(base / "scenario_acceptance.json", {"schema_version": "scenario-requirements/v1", "review_status": "pending_human_review",
                                                "scenarios": [dict(zip(("name", "questions", "minimum_evidence", "outputs", "acceptance"), row)) for row in acceptance]})
    text += ["", "Evidence threshold không lấy tên case ID hay reference answer làm input. Pipeline chung tái sử dụng discovery/parser/normalizer, hash pinning, safe Sigma loading, ATT&CK loader, provenance và new-only output writer; authentication correlator và CTI ingestor là trách nhiệm riêng, không thay runtime gate theo benchmark.", "",
             "## Blockers/input còn thiếu, phân loại đúng mức", "",
             "- **Không có selected raw/Sigma/MITRE filename thiếu** trong phạm vi search đã nêu. Không tải Mordor/Sigma/ATT&CK thay thế. Có originals đủ cho tiếp tục offline cả ba scenario.",
             "- **CTI đã bổ sung** hai nguồn mới, không còn thiếu report input cho MSHTA/Regsvr32 context. Chưa đánh giá độ đầy đủ CTI cho brute force; có thể bổ sung report xác thực riêng cùng provenance khi cần, không coi MITRE/Sigma là CTI report.",
             "- **Không có file lịch sử đăng nhập/baseline được cấu hình hoặc tìm thấy** ngoài capture ngắn này để xác nhận abnormality theo account/device/time. Không có tên file gốc đã chốt cho input này nên không bịa một required filename. Nếu muốn kết luận stronger về abnormal successful logons, cần cung cấp log xác thực dài hạn cùng manifest nguồn/hash/thời gian; phần suspected multi-account failure vẫn phân tích được hiện tại.",
             "- Không có shared failure/success credential/attempt identifier; 19 success temporal links không đủ causal attribution. Password cùng giá trị, cracking thành công, HTTP body và confirmed C2 không được telemetry hiện có xác lập. Đây là giới hạn kết luận mạnh, **không phải điều kiện bắt buộc để hoàn thành kịch bản nghi vấn**.",
             "- Integration/ground-truth review và evaluation coverage mới là công việc còn lại; không phải lý do giảm mục tiêu. Approval của MSHTA cũ không phê duyệt authentication/CTI mới.", "",
             "## Thứ tự triển khai còn lại", "",
             "1. Review evidence/correlation xác thực và draft GT mới, đặc biệt domain thiếu, SourceContext grouping, timestamp và giới hạn success. Hoàn thiện schema adapter sang GT/corpus/graph chung bằng provenance, giữ baseline.",
             "2. Full-file Regsvr32 extraction/correlation: dedup creation, nối GUID/host/time tới mọi child connections, safe evaluate 3 selected rules; draft GT và ATT&CK assessment từ evidence. Raw/Sigma/STIX đã đủ, không cần chờ input thay thế.",
             "3. Tích hợp CTI vào knowledge corpus/graph phiên bản mới cho cả ba kịch bản; giữ CTI context edges riêng, source location/hash/version; bổ sung CTI auth nếu câu hỏi yêu cầu. Rebuild consumers offline sau review, không trộn reference answers.",
             "4. Đặc tả câu hỏi/rubric cho đúng ba đề mục, kiểm tra offline retrieval + evidence completeness + citation; triển khai rule/evidence adapter chung thay câu trả lời theo case ID. Không sửa 15×2 hoặc tune theo các saved outputs.",
             "5. Sau review và khi có yêu cầu riêng, lên đánh giá mới cho scenario coverage và tích hợp phân tích/UI theo mục tiêu đầy đủ; task này chưa gọi LLM hoặc chạy benchmark. Giữ kết quả mới là version khác nếu có thực nghiệm tiếp.", "",
             "## Code, commands và verification", "",
             "Code mới: `src/threat_hunting/evidence/authentication.py`, `pcap_inventory.py`, `sigma/security_offline.py`, `cti/ingestion.py`; các CLI `inventory_offline_inputs.py`, `build_authentication_gap.py`, `fetch_cti_snapshots.py`, `ingest_cti_reports.py`, `report_offline_gap.py`; CTI selection và derived Sigma config; tests fixtures synthetic. Không sửa existing implementation hoặc dependencies.", "",
             "Các lệnh đã chạy (cần dùng output directory **mới** để tái lập, vì writer từ chối overwrite):", "", "```powershell",
             ".venv/Scripts/python.exe scripts/inventory_offline_inputs.py --data-root D:/rag-graphrag-friend/data --data-root D:/rag-graphrag-threat-hunting/data --output outputs/offline/requirements_gap_20261030_v1",
             ".venv/Scripts/python.exe scripts/build_authentication_gap.py --inventory outputs/offline/requirements_gap_20261030_v1/input_inventory.json --output outputs/offline/requirements_gap_20261030_v1/purplesharp_v2",
             ".venv/Scripts/python.exe scripts/fetch_cti_snapshots.py --output outputs/offline/requirements_gap_20261030_v1/cti_sources",
             ".venv/Scripts/python.exe scripts/ingest_cti_reports.py --sources outputs/offline/requirements_gap_20261030_v1/cti_sources --output outputs/offline/requirements_gap_20261030_v1/cti",
             ".venv/Scripts/python.exe scripts/report_offline_gap.py --root outputs/offline/requirements_gap_20261030_v1", "```", "",
             "Fetch CTI là thao tác HTTP công khai; các bước build/extract/ingest/test không gọi LLM. Có lần pytest ban đầu bị WinError5 ở temporary fixture directory; đã chạy lại ngoài sandbox. Một test fixture single-JSON-object ref đã được sửa theo format detector; một invocation có sai tên test file đã được sửa trước lần pass. Chi tiết kiểm tra cuối trong `verification.json`, JUnit XML và `integrity.json`; không gọi đó là full-suite hoặc benchmark mới.", "",
             "`integrity.json` so lại toàn bộ 828 files đã pin trước triển khai: raw inputs, canonical, existing source/tests/configs/docs, `.env`, selected consumers, hai runs 15×2 và review tổng hợp. Đã không sửa .env; không commit/push. Bản làm việc hiện không có .git, nên không báo git diff/status sạch. New artifact manifest có code/config/output hashes; không có auto approval hoặc label promotion."]
    with (base / "report.md").open("x", encoding="utf-8", newline="\n") as stream:
        stream.write("\n".join(text) + "\n")
    print(json.dumps({"requirements": len(matrix), "sigma_rules": len(knowledge), "report": str(base / "report.md")}))


if __name__ == "__main__":
    main()
