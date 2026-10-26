// The sealed-form check of a frame's mapped fields (task-content profile §2,
// e2ee spec §12.4), driven by the generated field map.
//
// The host never opens a value: it only checks that every mapped text/json
// value present on an encrypted task's frame is a `{e2ee}` object. A value
// that is absent or `null` carries nothing and passes; a non-object where the
// path continues (e.g. `data.output` as a string) holds the mapped value's
// place and must be sealed itself. Blob fields are checked by the byte
// channel, not here. A `keyed_plain` rule is checked as sealed whole: the
// profile's plain-path tables are empty.
import type { FieldMap, FieldRule } from "@gino/e2ee";
import { taskContentFieldMap } from "@gino/e2ee";
import { SealedValue } from "./schemas";

interface Hit {
  path: string;
  value: unknown;
}

function collect(node: unknown, segments: readonly string[], path: string, out: Hit[]): void {
  if (node == null) {
    return;
  }
  if (segments.length === 0) {
    out.push({ path, value: node });
    return;
  }
  if (typeof node !== "object" || Array.isArray(node)) {
    out.push({ path, value: node });
    return;
  }
  const [head = "", ...rest] = segments;
  const array = head.endsWith("[]");
  const key = array ? head.slice(0, -2) : head;
  const child = (node as Record<string, unknown>)[key];
  const childPath = path ? `${path}.${key}` : key;
  if (!array) {
    collect(child, rest, childPath, out);
    return;
  }
  if (child == null) {
    return;
  }
  if (!Array.isArray(child)) {
    out.push({ path: childPath, value: child });
    return;
  }
  child.forEach((element, i) => collect(element, rest, `${childPath}[${i}]`, out));
}

function lookup(frame: unknown, path: string): unknown {
  let node = frame;
  for (const key of path.split(".")) {
    if (node == null || typeof node !== "object") {
      return undefined;
    }
    node = (node as Record<string, unknown>)[key];
  }
  return node;
}

function applies(rule: FieldRule, frame: unknown): boolean {
  if (rule.kind === "blob") {
    return false;
  }
  if (rule.when == null) {
    return true;
  }
  const equal = lookup(frame, rule.when.path) === rule.when.value;
  return rule.when.op === "eq" ? equal : !equal;
}

/**
 * The first mapped path of a `frameType` frame (`{ data, … }`) whose value is
 * not in the sealed form, or `null` when every present mapped value is sealed
 * (or the frame type maps no fields).
 */
export function findPlaintextField(frameType: string, frame: unknown): string | null {
  const rules = taskContentFieldMap.frames[frameType]?.fields ?? [];
  for (const rule of rules) {
    if (!applies(rule, frame)) {
      continue;
    }
    const hits: Hit[] = [];
    collect(frame, rule.path.split("."), "", hits);
    const plain = hits.find(hit => !SealedValue.safeParse(hit.value).success);
    if (plain) {
      return plain.path;
    }
  }
  return null;
}

/**
 * Whether a `host_action` `thread_message` frame (`{ data, … }`) names a method
 * the field map declares: a key of the `keyed_plain` table of the rule at
 * `data.input.params`, read at the rule's key path. A missing map or rule, or a
 * non-string method, declares nothing.
 */
export function isDeclaredHostAction(map: FieldMap | undefined, frame: unknown): boolean {
  const keyed = map?.frames.thread_message?.fields.find(rule => rule.path === "data.input.params")?.keyedPlain;
  if (keyed == null) {
    return false;
  }
  const method = lookup(frame, keyed.key);
  return typeof method === "string" && Object.hasOwn(keyed.table, method);
}
