const COLLECTION_WRAPPERS = new Set(["data", "events", "findings", "items", "results"]);
const LABEL_FIELDS = [
  "summary", "title", "name", "description", "rule", "event", "api_call",
  "url", "domain", "host", "path", "file", "filename", "type",
];

function recordLabel(value, fallback) {
  for (const field of LABEL_FIELDS) {
    const candidate = value[field];
    if (["string", "number", "boolean"].includes(typeof candidate) && String(candidate)) {
      return String(candidate);
    }
  }
  if (value.class && value.method) return `${value.class}.${value.method}`;
  return fallback || "Recorded observation";
}

function isObservationRecord(value) {
  return LABEL_FIELDS.some((field) => value[field] !== undefined)
    || (value.class !== undefined && value.method !== undefined);
}

function detailText(value) {
  if (value === null || value === undefined || value === "") return "—";
  if (typeof value === "string") return value;
  if (["number", "boolean"].includes(typeof value)) return String(value);
  return JSON.stringify(value);
}

/** Expand MobSF's heterogeneous dynamic-report collections into display rows. */
export function runtimeObservationRows(report, maximumRows = 5000) {
  const rows = [];

  function push(section, observation, details) {
    if (rows.length >= maximumRows) return;
    rows.push({ section, observation: observation || "Recorded observation", details: detailText(details) });
  }

  function expand(section, value, fallback = null) {
    if (rows.length >= maximumRows || value === null || value === undefined) return;
    if (Array.isArray(value)) {
      value.forEach((item) => expand(section, item, fallback));
      return;
    }
    if (typeof value !== "object") {
      push(section, fallback || String(value), fallback ? value : null);
      return;
    }

    const entries = Object.entries(value);
    const wrapped = entries.filter(([key, child]) => COLLECTION_WRAPPERS.has(key) && Array.isArray(child));
    if (wrapped.length) {
      wrapped.forEach(([, child]) => expand(section, child, fallback));
      const wrapperNames = new Set(wrapped.map(([key]) => key));
      const metadata = Object.fromEntries(entries.filter(([key]) => !wrapperNames.has(key)));
      if (Object.keys(metadata).length) push(section, fallback || "Collection metadata", metadata);
      return;
    }

    if (isObservationRecord(value)) {
      push(section, recordLabel(value, fallback), value);
      return;
    }

    entries.forEach(([key, child]) => {
      if (Array.isArray(child)) {
        child.forEach((item) => expand(section, item, key));
      } else {
        push(section, key, child);
      }
    });
  }

  if (!report || typeof report !== "object" || Array.isArray(report)) return rows;
  Object.entries(report).forEach(([section, value]) => {
    if (Array.isArray(value) || (value && typeof value === "object")) expand(section, value);
  });
  return rows;
}
