import type { FieldMap } from "../src/index";
import { describe, expect, it } from "bun:test";
import { findPlaintextField, isDeclaredHostAction } from "../src/ds/index";
import { taskContentFieldMap } from "../src/index";

// The sealed-form check of runner frames and the declared host actions,
// driven by the generated `gino.task-content.v1` field map.

const S = { e2ee: "c2VhbGVk" };

describe("findPlaintextField", () => {
  it("accepts frames whose present mapped values are sealed, absent or null", () => {
    const ok: Array<[string, unknown]> = [
      ["thread_message", { data: { seq: 1, kind: "assistant_text", content: S } }],
      ["thread_message", { data: { seq: 1, kind: "tool_use", tool: "Bash", input: S } }],
      ["thread_message", { data: { seq: 1, kind: "tool_result", output: { is_error: true, content: S } } }],
      ["thread_message", { data: { seq: 1, kind: "tool_result", output: { is_error: false } } }],
      ["thread_message", { data: { seq: 1, kind: "host_action", input: { method: "notify", params: S } } }],
      ["thread_message", { data: { seq: 1, kind: "status", content: null } }],
      ["thread_result", { data: { status: "succeeded", result: S, error: S, attachments: [{ name: S, sha256: "ab" }] } }],
      ["thread_result", { data: { status: "succeeded" } }],
      ["cron_state", { data: { kind: "interval", status: "plain" } }],
    ];
    for (const [type, frame] of ok) {
      expect(findPlaintextField(type, frame)).toBeNull();
    }
  });

  it("names the first plaintext mapped path", () => {
    const plain: Array<[string, unknown, string]> = [
      ["thread_message", { data: { seq: 1, kind: "assistant_text", content: "hi" } }, "data.content"],
      ["thread_message", { data: { seq: 1, kind: "tool_use", input: { command: "ls" } } }, "data.input"],
      ["thread_message", { data: { seq: 1, kind: "tool_result", output: { content: [{ type: "text" }] } } }, "data.output.content"],
      ["thread_message", { data: { seq: 1, kind: "tool_result", output: "raw output" } }, "data.output"],
      ["thread_message", { data: { seq: 1, kind: "host_action", input: { method: "notify", params: { to: "x" } } } }, "data.input.params"],
      ["thread_message", { data: { seq: 1, kind: "host_action", input: "notify" } }, "data.input"],
      ["thread_message", { data: { seq: 1, kind: "assistant_text", content: { e2ee: "not base64url!" } } }, "data.content"],
      ["thread_result", { data: { status: "failed", error: "boom" } }, "data.error"],
      ["thread_result", { data: { status: "succeeded", attachments: [{ name: S }, { name: "b.txt" }] } }, "data.attachments[1].name"],
    ];
    for (const [type, frame, path] of plain) {
      expect(findPlaintextField(type, frame)).toBe(path);
    }
  });
});

describe("isDeclaredHostAction", () => {
  const frame = (method: unknown) => ({ data: { seq: 1, kind: "host_action", input: { method, params: S } } });
  const declaring: FieldMap = {
    ...taskContentFieldMap,
    frames: {
      ...taskContentFieldMap.frames,
      thread_message: {
        ...taskContentFieldMap.frames.thread_message!,
        fields: taskContentFieldMap.frames.thread_message!.fields.map(rule =>
          rule.keyedPlain ? { ...rule, keyedPlain: { ...rule.keyedPlain, table: { "issue.set_status": ["issue_id"] } } } : rule),
      },
    },
  };

  it("accepts a method declared by the map's keyed_plain table", () => {
    expect(isDeclaredHostAction(declaring, frame("issue.set_status"))).toBe(true);
    expect(isDeclaredHostAction(declaring, frame("comment"))).toBe(false);
    expect(isDeclaredHostAction(declaring, frame("constructor"))).toBe(false);
    expect(isDeclaredHostAction(declaring, frame(42))).toBe(false);
  });

  it("declares nothing for the real profile, an unknown profile or a map without the rule", () => {
    expect(isDeclaredHostAction(taskContentFieldMap, frame("issue.set_status"))).toBe(false);
    expect(isDeclaredHostAction(undefined, frame("issue.set_status"))).toBe(false);
    expect(isDeclaredHostAction({ profile: "x", frames: {} }, frame("issue.set_status"))).toBe(false);
  });
});
