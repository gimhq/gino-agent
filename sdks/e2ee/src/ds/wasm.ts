// The wasm module, loaded synchronously once per process so the relay's paths
// stay synchronous.
import { readFileSync } from "node:fs";
import { initSync } from "@gino/e2ee";

/** The wasm module: its bytes or a compiled module. */
export type RelayWasmSource = BufferSource | WebAssembly.Module;

let loaded = false;

/** `wasm/gino_e2ee_bg.wasm` next to the package's resolved entry point (`src/` or `dist/`). */
function defaultWasmBytes(): Uint8Array {
  return readFileSync(new URL("../wasm/gino_e2ee_bg.wasm", import.meta.resolve("@gino/e2ee")));
}

/**
 * Initialise the wasm module unless it already is. Idempotent and synchronous;
 * the first source wins. Without `source` the bytes are read from the package
 * files; a single-file bundle injects them instead.
 */
export function loadRelayWasm(source?: RelayWasmSource): void {
  if (loaded) {
    return;
  }
  initSync(source ?? defaultWasmBytes());
  loaded = true;
}
