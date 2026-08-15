function isLogEvent(value) {
  return value && typeof value === "object" && !Array.isArray(value)
    && ["status", "timestamp", "exception"].some((field) => Object.hasOwn(value, field));
}

/** Expand MobSF scan-log wrappers into one chronological display row per event. */
export function androidScanLogRows(value, maximumRows = 5000) {
  const rows = [];

  function expand(stage, item) {
    if (rows.length >= maximumRows || item === null || item === undefined) return;
    if (Array.isArray(item)) {
      item.forEach((child) => expand(stage, child));
      return;
    }
    if (isLogEvent(item)) {
      rows.push({
        stage,
        timestamp: String(item.timestamp || ""),
        status: String(item.status || "Unknown status"),
        exception: item.exception === null || item.exception === undefined
          ? "—"
          : typeof item.exception === "string"
            ? item.exception
            : JSON.stringify(item.exception),
      });
      return;
    }
    if (typeof item === "object") {
      Object.entries(item).forEach(([name, child]) => expand(name, child));
      return;
    }
    rows.push({ stage, timestamp: "", status: String(item), exception: "—" });
  }

  expand("scan", value);
  return rows;
}
