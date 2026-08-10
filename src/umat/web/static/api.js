let unauthorizedHandler = null;

export function configureApi({ onUnauthorized }) {
  unauthorizedHandler = onUnauthorized;
}

function csrfToken() {
  const pair = document.cookie.split("; ").find((item) => item.startsWith("umat_csrf="));
  return pair ? decodeURIComponent(pair.split("=").slice(1).join("=")) : "";
}

export async function api(path, options = {}) {
  const request = { credentials: "same-origin", ...options };
  request.headers = new Headers(options.headers || {});
  if (request.body && !(request.body instanceof FormData) && typeof request.body !== "string") {
    request.headers.set("Content-Type", "application/json");
    request.body = JSON.stringify(request.body);
  }
  if (request.method && !["GET", "HEAD"].includes(request.method.toUpperCase())) {
    request.headers.set("X-CSRF-Token", csrfToken());
  }
  const response = await fetch(path, request);
  if (response.status === 401 && !path.endsWith("/login")) {
    if (unauthorizedHandler) unauthorizedHandler();
    throw new Error("Your session has expired.");
  }
  if (!response.ok) {
    let message = `Request failed (${response.status})`;
    try { message = (await response.json()).detail || message; } catch (_) { /* response was not JSON */ }
    throw new Error(message);
  }
  if (response.status === 204) return null;
  return response.json();
}
