function rawComponentNames(value) {
  if (Array.isArray(value)) {
    return value.map((item) => typeof item === "string" ? item : item?.name || item?.value || JSON.stringify(item));
  }
  if (value && typeof value === "object") return Object.keys(value);
  return [];
}

function visibleCodePoints(value) {
  return [...value].map((character) => /[\p{Cc}\p{Cf}]/u.test(character)
    ? `\\u{${character.codePointAt(0).toString(16).toUpperCase()}}`
    : character).join("");
}

function readableAlias(raw, sequence) {
  const prefix = raw.match(/^[A-Za-z_$][A-Za-z0-9_$]*(?:\.[A-Za-z_$][A-Za-z0-9_$]*)*/)?.[0];
  const suffix = raw.match(/([A-Za-z0-9_$]{1,20})$/)?.[1];
  const scope = prefix ? `${prefix}.` : "";
  const tail = suffix && suffix !== prefix?.split(".").at(-1) ? `.${suffix}` : "";
  return `${scope}‹obfuscated component ${sequence}›${tail}`;
}

/** Preserve exact component evidence while making adversarial identifiers readable. */
export function androidComponentItems(value) {
  return rawComponentNames(value).map((rawValue, index) => {
    const raw = String(rawValue ?? "");
    const characters = [...raw];
    const unusual = characters.filter((character) => !/[A-Za-z0-9_$.]/.test(character)).length;
    const obfuscated = characters.length > 120
      || (characters.length > 40 && unusual / characters.length > 0.25);
    return {
      display: obfuscated ? readableAlias(raw, index + 1) : visibleCodePoints(raw),
      raw: visibleCodePoints(raw),
      raw_character_count: characters.length,
      obfuscated,
    };
  });
}

/** Replace only long obfuscated identifiers embedded in prose; retain the raw text separately. */
export function readableAndroidFinding(value) {
  const raw = String(value ?? "");
  let sequence = 0;
  const plain = raw.replace(/<\/?[A-Za-z][^>]{0,100}>/gu, "");
  const display = plain.replace(/\(([^()\r\n]{40,})\)/gu, (matched, candidate) => {
    const [component] = androidComponentItems([candidate]);
    if (!component?.obfuscated) return matched;
    sequence += 1;
    return `(${readableAlias(candidate, sequence)})`;
  });
  return { display: visibleCodePoints(display), raw: visibleCodePoints(raw), changed: display !== raw };
}
