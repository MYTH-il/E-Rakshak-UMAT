import { api } from "./api.js";

export function queryRecentRuns(filters) {
  const query = new URLSearchParams();
  Object.entries(filters).forEach(([key, value]) => {
    if (value !== "" && value !== null && value !== undefined) query.set(key, String(value));
  });
  return api(`/api/v1/analysis-runs?${query}`);
}

export function updateCaseMetadata(caseId, body) {
  return api(`/api/v1/cases/${caseId}`, { method: "PATCH", body });
}

export function addCaseSubmission(caseId, body) {
  return api(`/api/v1/cases/${caseId}/submissions`, { method: "POST", body });
}

export function retryAnalysisRun(runId, reason) {
  return api(`/api/v1/analysis-runs/${runId}/retry`, { method: "POST", body: { reason } });
}
