// `@gino/e2ee/ds` — the host side of gino e2ee: the key directory and the MLS
// Delivery Service of encrypted tasks (`E2eeRelay`), the storage port it runs
// on (`E2eeRepo`, with an in-memory adapter), the wire schemas of the e2ee
// frames and the sealed-form check of mapped fields. Framework-free and
// synchronous; a host supplies storage and its agent channel (`RelayDeps`).

export { type AckedFrame, E2EE_LOG_PAGE_LIMIT, logEntryData } from "./delivery";
export * from "./directory";
export * from "./errors";
export * from "./memory";
export * from "./ports";
export * from "./relay";
export * from "./repo";
export * from "./schemas";
export * from "./sealed";
export * from "./wasm";
