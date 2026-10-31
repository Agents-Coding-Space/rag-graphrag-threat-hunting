import { HuntResponse } from './types';

export const isRejected = (response: HuntResponse): boolean =>
  response.status === 'validation_failed' || response.validation?.status === 'validation_failed';

/** Validation accepts a draft structurally; human review is still required. */
export const canExportAcceptedDraft = (response: HuntResponse): boolean =>
  response.status === 'proceed' && !isRejected(response) &&
  response.validation?.status === 'passed' && response.execution?.source === 'llm' &&
  response.execution.generation_succeeded === true && !response.execution.fallback_used && !!response.report;

export const responseMessage = (response: HuntResponse): string => {
  if (response.status === 'abstained') return `Yêu cầu bị từ chối: ${response.reason || 'Không đủ dữ kiện'}`;
  if (isRejected(response)) return 'Báo cáo bị từ chối bởi validation; không hiển thị như câu trả lời được chấp nhận.';
  if (response.status === 'provider_error') return `${response.error_message || 'Lỗi provider.'} ${response.execution?.fallback_used ? 'Đang hiển thị Offline Fallback.' : 'Chưa có câu trả lời LLM.'}`;
  return 'Đã truy xuất context. Nội dung tổng hợp và verdict vẫn cần người dùng duyệt.';
};

export const exportFilename = (response: HuntResponse, extension: string): string => {
  const kind = isRejected(response) ? 'rejected-diagnostic' : canExportAcceptedDraft(response) ? 'accepted-draft' : 'fallback-diagnostic';
  return `${response.replay ? 'replay-' : ''}${kind}-${response.scenario_id}-${Date.now()}.${extension}`;
};
