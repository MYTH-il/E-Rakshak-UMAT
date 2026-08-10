import { api } from "./api.js";

export function loadWorkers() {
  return api("/api/v1/admin/workers");
}

export function updateWindowsProfile(profileId, body) {
  return api(`/api/v1/windows/profiles/${profileId}`, { method: "PATCH", body });
}

export function updateAndroidProfile(profileId, body) {
  return api(`/api/v1/android/profiles/${profileId}`, { method: "PATCH", body });
}
