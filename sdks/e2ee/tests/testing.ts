// Injected randomness and inline field maps, for test vectors (spec §13).
// Never use these to seal production data.

import type { EpochSecrets, SealedFile } from "../src/index";
import { call } from "../src/errors";
import { FieldMapEngine, fileDigest } from "../src/index";
import * as wasm from "../wasm/gino_e2ee.js";

/** The per-envelope key `k_msg` (spec §4.3). */
export function messageKey(k: Uint8Array, salt: Uint8Array): Uint8Array {
  return call(() => wasm.messageKey(k, salt));
}

/** {@link sealContent} with preset randomness `random`. */
export function sealContentWith(random: Uint8Array, k: Uint8Array, epoch: number, location: string, plaintext: Uint8Array): Uint8Array {
  return call(() => wasm.sealContent(k, BigInt(epoch), location, plaintext, random));
}

/** {@link sealFile} with preset randomness `random`. */
export function sealFileWith(random: Uint8Array, k: Uint8Array, epoch: number, location: string, bytes: Uint8Array): SealedFile {
  return fileDigest(call(() => wasm.sealFile(k, BigInt(epoch), location, bytes, random)));
}

/** {@link sealEpochLink} with preset randomness `random`. */
export function sealEpochLinkWith(random: Uint8Array, scope: string, epoch: number, secrets: EpochSecrets, kNext: Uint8Array): Uint8Array {
  return call(() => wasm.sealEpochLink(scope, BigInt(epoch), secrets.k, secrets.d, kNext, random));
}

/** {@link FieldMapEngine.sealFrame} with preset randomness `random`. */
export function sealFrameWith<T = unknown>(random: Uint8Array, engine: FieldMapEngine, frameType: string, frame: unknown, epoch: number, k: Uint8Array): T {
  return JSON.parse(call(() => engine.inner.sealFrame(frameType, JSON.stringify(frame), BigInt(epoch), k, random))) as T;
}

/** The engine of an inline field map (spec §12.1). Its memory is never freed. */
export function fieldMapFromJson(map: unknown): FieldMapEngine {
  return new FieldMapEngine(call(() => wasm.FieldMap.fromJson(JSON.stringify(map))));
}
