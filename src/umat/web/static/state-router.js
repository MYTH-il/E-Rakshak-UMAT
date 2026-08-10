export const state = {
  session: null, cases: [], pollTimer: null, activeTab: "overview",
  caseFilter: { query: "", status: "", platform: "", verdict: "" },
  activeRunId: null, androidTab: "static", androidLiveCleanup: null,
  recentRunPage: 1,
};

let routeRenderer = null;

export function configureRouter(renderer) {
  routeRenderer = renderer;
  window.addEventListener("popstate", renderer);
}

export function go(path) {
  if (state.androidLiveCleanup) { state.androidLiveCleanup(); state.androidLiveCleanup = null; }
  history.pushState({}, "", path);
  if (routeRenderer) routeRenderer();
}

export function navigateEvent(event) {
  if (event.metaKey || event.ctrlKey || event.shiftKey || event.altKey) return;
  event.preventDefault();
  go(event.currentTarget.getAttribute("href"));
}
