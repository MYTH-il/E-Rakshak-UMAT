import { api } from "./api.js";

export function loadAndroidWorkflow(runId) {
  return api(`/api/v1/analysis-runs/${runId}/android-workflow`);
}

export function submitAndroidCommand(runId, body) {
  return api(`/api/v1/analysis-runs/${runId}/android-commands`, { method: "POST", body });
}

export function loadAndroidCommand(runId, commandId) {
  return api(`/api/v1/analysis-runs/${runId}/android-commands/${commandId}`);
}
