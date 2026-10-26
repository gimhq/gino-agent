// Every canonical vector of docs/e2ee/test-vectors.json (spec §13) through
// the wasm package.

import type { EpochSecrets, FieldMap, HistoryPolicy } from "../src/index";
import { Buffer } from "node:buffer";
import { beforeAll, describe, expect, test } from "bun:test";
import {
  buildLocation,
  decodeB64url,
  decodeHistoryPolicy,
  decodeKeyHistory,
  decodePlaintext,
  deriveDropKeyPair,
  E2eeError,
  encodeB64url,
  encodeHistoryPolicy,
  encodeKeyHistory,
  envelopeHeader,
  FieldMapEngine,
  fingerprint,
  fingerprintDisplay,
  fromSealedValue,
  groupId,
  History,
  init,
  openContent,
  openDrop,
  openEpochLink,
  openFile,
  openKeyHistorySealed,
  sealDrop,
  sealKeyHistoryToLeaf,
  taskContentFieldMap,
  verifyDropPublicKey,
} from "../src/index";
import { fieldMapFromJson, messageKey, sealContentWith, sealEpochLinkWith, sealFileWith, sealFrameWith } from "./testing";

/* eslint-disable ts/no-explicit-any -- vectors are untyped JSON */
type Json = any;

const vectors: Json = await Bun.file(new URL("../../../docs/e2ee/test-vectors.json", import.meta.url)).json();

function unhex(text: string): Uint8Array {
  return Uint8Array.from(Buffer.from(text, "hex"));
}

function hex(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString("hex");
}

function secretsOf(value: Json): EpochSecrets {
  return { k: unhex(value.k), d: unhex(value.d) };
}

/** The `{code, epoch?}` of a failure, or `null` if `run` succeeds. */
function failure(run: () => unknown): unknown {
  try {
    run();
    return null;
  }
  catch (error) {
    if (!(error instanceof E2eeError))
      throw error;
    return error.toJSON();
  }
}

function walkHistory(value: Json): History {
  const history = new History(value.scope, value.current.epoch, secretsOf(value.current));
  for (const [epoch, link] of Object.entries(value.links as Record<string, string>))
    history.addLink(Number(epoch), unhex(link));
  return history;
}

beforeAll(async () => {
  await init();
});

describe("test vectors", () => {
  test("header", () => {
    expect(vectors.format).toBe("gino-e2ee/test-vectors/v1");
    expect(vectors.envelope_version).toBe(1);
    expect(vectors.suite).toBe(1);
  });

  test("group_id", () => {
    for (const v of vectors.group_id)
      expect(hex(groupId(v.profile, v.scope))).toBe(v.group_id);
  });

  test("fingerprint", () => {
    for (const v of vectors.fingerprint) {
      expect(fingerprint(unhex(v.public_key))).toBe(v.fingerprint);
      expect(fingerprintDisplay(unhex(v.public_key))).toBe(v.display);
    }
  });

  test("aad", () => {
    for (const v of vectors.aad)
      expect(buildLocation(v.template, v.frame, v.element)).toBe(v.location);
  });

  test("policy", () => {
    for (const v of vectors.policy) {
      expect(hex(encodeHistoryPolicy(v.policy as HistoryPolicy))).toBe(v.extension_data);
      expect(decodeHistoryPolicy(unhex(v.extension_data))).toEqual(v.policy);
    }
  });

  test("content", () => {
    for (const v of vectors.content) {
      const [k, salt, plaintext] = [unhex(v.k_e), unhex(v.salt), unhex(v.plaintext)];
      expect(hex(messageKey(k, salt))).toBe(v.k_msg);
      const envelope = sealContentWith(salt, k, v.epoch, v.location, plaintext);
      expect(hex(envelope)).toBe(v.envelope);
      expect(encodeB64url(envelope)).toBe(v.envelope_b64url);
      expect(hex(decodeB64url(v.envelope_b64url))).toBe(v.envelope);
      expect(hex(openContent(k, envelope, v.location))).toBe(v.plaintext);
    }
  });

  test("file", () => {
    for (const v of vectors.file) {
      const k = unhex(v.k_e);
      const sealed = sealFileWith(unhex(v.salt), k, v.epoch, v.location, unhex(v.plaintext));
      expect(hex(sealed.envelope)).toBe(v.envelope);
      expect(sealed.sha256).toBe(v.sha256);
      expect(sealed.size).toBe(v.size);
      expect(hex(openFile(k, sealed.envelope, v.location))).toBe(v.plaintext);
    }
  });

  // The HPKE of the provider takes no injected ephemeral key, so drops are
  // checked by opening and by a fresh round trip (spec §13).
  test("drop", () => {
    for (const v of vectors.drop) {
      const d = unhex(v.d_e);
      const pair = deriveDropKeyPair(d);
      expect(hex(pair.privateKey)).toBe(v.sk);
      expect(hex(pair.publicKey)).toBe(v.pk);
      expect(hex(openDrop(d, unhex(v.envelope), v.location))).toBe(v.plaintext);
      const resealed = sealDrop(pair.publicKey, v.epoch, v.location, unhex(v.plaintext));
      expect(hex(openDrop(d, resealed, v.location))).toBe(v.plaintext);
      verifyDropPublicKey(d, v.epoch, pair.publicKey);
    }
  });

  test("epoch_link", () => {
    for (const v of vectors.epoch_link) {
      const secrets = { k: unhex(v.k_e), d: unhex(v.d_e) };
      const kNext = unhex(v.k_next);
      expect(hex(sealEpochLinkWith(unhex(v.salt), v.scope, v.epoch, secrets, kNext))).toBe(v.envelope);
      expect(openEpochLink(v.scope, v.epoch, kNext, unhex(v.envelope))).toEqual(secrets);
    }
  });

  test("key_history", () => {
    for (const v of vectors.key_history) {
      const history = {
        epoch: v.epoch,
        entries: v.entries.map((e: Json) => ({ epoch: e.epoch, ...secretsOf(e) })),
      };
      expect(hex(encodeKeyHistory(history))).toBe(v.payload);
      expect(decodeKeyHistory(unhex(v.payload))).toEqual(history);
      if (v.sealed) {
        const s = v.sealed;
        expect(openKeyHistorySealed(s.scope, s.leaf_index, unhex(s.leaf_sk), unhex(s.envelope))).toEqual(history);
        const resealed = sealKeyHistoryToLeaf(history, s.scope, s.leaf_index, unhex(s.leaf_pk));
        expect(openKeyHistorySealed(s.scope, s.leaf_index, unhex(s.leaf_sk), resealed)).toEqual(history);
      }
    }
  });

  test("history_walk", () => {
    for (const v of vectors.history_walk) {
      encodeHistoryPolicy(v.policy as HistoryPolicy);
      const history = walkHistory(v);
      for (const item of v.content) {
        const envelope = unhex(item.envelope);
        expect(envelopeHeader(envelope).epoch).toBe(item.epoch);
        if (item.error)
          expect(failure(() => history.open(envelope, item.location))).toEqual(item.error);
        else
          expect(hex(history.open(envelope, item.location))).toBe(item.plaintext);
      }
    }
  });

  // Seal-side errors have `sealed_frame: null`; otherwise opening
  // `sealed_frame` fails with the error (spec §13).
  test("field_map", () => {
    for (const v of vectors.field_map) {
      const map: FieldMap | Json = v.map ?? taskContentFieldMap;
      const engine = v.map ? fieldMapFromJson(v.map) : FieldMapEngine.forProfile(v.profile);
      const frameType: string = v.frame.type;
      const scopePath: string | undefined = map.frames[frameType]?.scope;
      const scope: string = scopePath === undefined ? "t-1" : v.frame[scopePath];
      const epochs = Object.keys(v.secrets).map(Number).sort((a, b) => a - b);
      const current = epochs.at(-1)!;
      const history = new History(scope, current, secretsOf(v.secrets[current]));
      for (const epoch of epochs.slice(0, -1))
        history.cacheSecrets(epoch, secretsOf(v.secrets[epoch]), true);
      const salts = unhex((v.salts as string[]).join(""));
      const k = secretsOf(v.secrets[current]).k;
      const seal = (): unknown => sealFrameWith(salts, engine, frameType, v.frame, current, k);
      const open = (): unknown => history.openFrame(engine, frameType, v.sealed_frame);
      if (!v.error) {
        expect(seal(), v.description).toEqual(v.sealed_frame);
        expect(open(), v.description).toEqual(v.frame);
      }
      else {
        expect(failure(v.sealed_frame === null ? seal : open), v.description).toEqual(v.error);
      }
    }
  });

  test("negative", () => {
    const runners: Record<string, (input: Json) => unknown> = {
      aad: i => buildLocation(i.template, i.frame, i.element),
      policy: i => decodeHistoryPolicy(unhex(i.extension_data)),
      content: (i) => {
        const plaintext = openContent(unhex(i.k_e), unhex(i.envelope), i.location);
        if (i.kind === "text" || i.kind === "json")
          decodePlaintext(plaintext, i.kind);
      },
      file: i => openFile(unhex(i.k_e), unhex(i.envelope), i.location),
      drop: i => openDrop(unhex(i.d_e), unhex(i.envelope), i.location),
      drop_key: i => verifyDropPublicKey(unhex(i.d_e), i.epoch, unhex(i.public_key)),
      epoch_link: i => openEpochLink(i.scope, i.epoch, unhex(i.k_next), unhex(i.envelope)),
      key_history: i => decodeKeyHistory(unhex(i.payload)),
      key_history_sealed: i => openKeyHistorySealed(i.scope, i.leaf_index, unhex(i.leaf_sk), unhex(i.envelope)),
      history_walk: i => walkHistory(i).open(unhex(i.envelope), i.location),
      base64url: i => decodeB64url(i.text),
      sealed_form: i => fromSealedValue(i.value),
    };
    for (const v of vectors.negative) {
      const run = runners[v.section];
      expect(run, v.section).toBeDefined();
      expect(failure(() => run!(v.input)), `${v.section}: ${v.description}`).toEqual(v.error);
    }
  });
});
