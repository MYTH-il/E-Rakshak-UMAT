import { api } from "./api.js";

export function loadWorkers() {
  return api("/api/v1/admin/workers");
}

export function loadUsers() {
  return api("/api/v1/admin/users");
}

export function createUser(body) {
  return api("/api/v1/admin/users", { method: "POST", body });
}

export function updateUser(userId, body) {
  return api(`/api/v1/admin/users/${userId}`, { method: "PATCH", body });
}

export function deleteUser(userId) {
  return api(`/api/v1/admin/users/${userId}`, { method: "DELETE" });
}

export function revokeUserSessions(userId) {
  return api(`/api/v1/admin/users/${userId}/revoke-sessions`, { method: "POST" });
}

export function updateWindowsProfile(profileId, body) {
  return api(`/api/v1/windows/profiles/${profileId}`, { method: "PATCH", body });
}

export function updateAndroidProfile(profileId, body) {
  return api(`/api/v1/android/profiles/${profileId}`, { method: "PATCH", body });
}
