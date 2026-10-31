export interface ExperimentalResponse {
  request: { query: string; scenario_id: string; branch: string };
  outcome: string;
  result: Record<string, any>;
  scope: Record<string, any> | null;
  gate: Record<string, any> | null;
  eligibility: Record<string, any> | null;
  validation: Record<string, any> | null;
  report: Record<string, any> | null;
  diagnostic: Record<string, any> | null;
  context: Record<string, any> | null;
  messages: Record<string, any> | null;
  evidence_contract: Record<string, any> | null;
  configuration: Record<string, any>;
  provenance: Record<string, any>;
  human_review_required: boolean;
}

export function acceptedExperimentalDraft(value: ExperimentalResponse): boolean {
  return value.outcome === 'accepted_draft' && value.validation?.status === 'passed' &&
    !!value.report && value.result.fallback_used === false;
}

export function experimentalStatus(value: ExperimentalResponse): string {
  switch (value.outcome) {
    case 'accepted_draft': return acceptedExperimentalDraft(value) ? 'Accepted draft — vẫn cần human review' : 'Trạng thái draft không hợp lệ — xem diagnostic';
    case 'validation_failed': return 'Validation_failed — rejected output, không phải accepted answer';
    case 'abstain': return 'Abstain — không gọi LLM';
    case 'provider_error': return 'Provider error — chưa có câu trả lời LLM; không fallback';
    case 'rate_limited': return 'Rate limited (429) — dừng session, không retry/fallback';
    case 'dry_run_no_generation': return 'Proceed / offline dry-run — chưa gọi LLM, chưa có answer';
    case 'not_run': return 'Not run — chưa gửi request LLM; xem lý do dừng';
    case 'interrupted': return 'Interrupted — lượt bị ngắt; xem attempt count và checkpoint';
    case 'not_run_request_limit': return 'Đã hết request cap — không gọi LLM';
    case 'not_run_after_stop': return 'Session đã dừng sau lỗi authentication/429 — không gọi LLM';
    default: return 'Runtime error — xem diagnostic, không có accepted answer';
  }
}
