import { api } from "./api.js";

export function loadRunReport(caseId, runId) {
  return api(`/api/v1/cases/${caseId}/report?run_id=${runId}`);
}

export function createReportExport(caseId, format) {
  return api(`/api/v1/cases/${caseId}/exports/${format}`, { method: "POST" });
}
