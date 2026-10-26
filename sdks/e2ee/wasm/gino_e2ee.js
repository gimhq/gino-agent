/* @ts-self-types="./gino_e2ee.d.ts" */

/**
 * A drop key pair derived from a drop seed `d_e` (spec §4.4).
 */
export class DropKeyPair {
    static __wrap(ptr) {
        const obj = Object.create(DropKeyPair.prototype);
        obj.__wbg_ptr = ptr;
        DropKeyPairFinalization.register(obj, obj.__wbg_ptr, obj);
        return obj;
    }
    __destroy_into_raw() {
        const ptr = this.__wbg_ptr;
        this.__wbg_ptr = 0;
        DropKeyPairFinalization.unregister(this);
        return ptr;
    }
    free() {
        const ptr = this.__destroy_into_raw();
        wasm.__wbg_dropkeypair_free(ptr, 0);
    }
    /**
     * Derives the pair of `d_e`.
     * @param {Uint8Array} d_e
     * @returns {DropKeyPair}
     */
    static derive(d_e) {
        const ptr0 = passArray8ToWasm0(d_e, wasm.__wbindgen_malloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.dropkeypair_derive(ptr0, len0);
        if (ret[2]) {
            throw takeFromExternrefTable0(ret[1]);
        }
        return DropKeyPair.__wrap(ret[0]);
    }
    /**
     * The private key.
     * @returns {Uint8Array}
     */
    get privateKey() {
        const ret = wasm.dropkeypair_privateKey(this.__wbg_ptr);
        var v1 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
        wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
        return v1;
    }
    /**
     * The 32-byte X25519 public key.
     * @returns {Uint8Array}
     */
    get publicKey() {
        const ret = wasm.dropkeypair_publicKey(this.__wbg_ptr);
        var v1 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
        wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
        return v1;
    }
}
if (Symbol.dispose) DropKeyPair.prototype[Symbol.dispose] = DropKeyPair.prototype.free;

/**
 * A field map (spec §12): a generated profile map, or an inline one.
 */
export class FieldMap {
    static __wrap(ptr) {
        const obj = Object.create(FieldMap.prototype);
        obj.__wbg_ptr = ptr;
        FieldMapFinalization.register(obj, obj.__wbg_ptr, obj);
        return obj;
    }
    __destroy_into_raw() {
        const ptr = this.__wbg_ptr;
        this.__wbg_ptr = 0;
        FieldMapFinalization.unregister(this);
        return ptr;
    }
    free() {
        const ptr = this.__destroy_into_raw();
        wasm.__wbg_fieldmap_free(ptr, 0);
    }
    /**
     * The generated map of `profile`, or `undefined`.
     * @param {string} profile
     * @returns {FieldMap | undefined}
     */
    static forProfile(profile) {
        const ptr0 = passStringToWasm0(profile, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.fieldmap_forProfile(ptr0, len0);
        return ret === 0 ? undefined : FieldMap.__wrap(ret);
    }
    /**
     * A map from field-map JSON (spec §12.1), for inline maps of test
     * vectors. The map is never freed.
     * @param {string} json
     * @returns {FieldMap}
     */
    static fromJson(json) {
        const ptr0 = passStringToWasm0(json, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.fieldmap_fromJson(ptr0, len0);
        if (ret[2]) {
            throw takeFromExternrefTable0(ret[1]);
        }
        return FieldMap.__wrap(ret[0]);
    }
    /**
     * The profile id.
     * @returns {string}
     */
    get profile() {
        let deferred1_0;
        let deferred1_1;
        try {
            const ret = wasm.fieldmap_profile(this.__wbg_ptr);
            deferred1_0 = ret[0];
            deferred1_1 = ret[1];
            return getStringFromWasm0(ret[0], ret[1]);
        } finally {
            wasm.__wbindgen_free(deferred1_0, deferred1_1, 1);
        }
    }
    /**
     * Seals every mapped value of a JSON frame under `k_e` of `epoch` and
     * returns the JSON frame with the sealed forms in place.
     * @param {string} frame_type
     * @param {string} frame
     * @param {bigint} epoch
     * @param {Uint8Array} k_e
     * @param {Uint8Array | null} [random]
     * @returns {string}
     */
    sealFrame(frame_type, frame, epoch, k_e, random) {
        let deferred6_0;
        let deferred6_1;
        try {
            const ptr0 = passStringToWasm0(frame_type, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
            const len0 = WASM_VECTOR_LEN;
            const ptr1 = passStringToWasm0(frame, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
            const len1 = WASM_VECTOR_LEN;
            const ptr2 = passArray8ToWasm0(k_e, wasm.__wbindgen_malloc);
            const len2 = WASM_VECTOR_LEN;
            var ptr3 = isLikeNone(random) ? 0 : passArray8ToWasm0(random, wasm.__wbindgen_malloc);
            var len3 = WASM_VECTOR_LEN;
            const ret = wasm.fieldmap_sealFrame(this.__wbg_ptr, ptr0, len0, ptr1, len1, epoch, ptr2, len2, ptr3, len3);
            var ptr5 = ret[0];
            var len5 = ret[1];
            if (ret[3]) {
                ptr5 = 0; len5 = 0;
                throw takeFromExternrefTable0(ret[2]);
            }
            deferred6_0 = ptr5;
            deferred6_1 = len5;
            return getStringFromWasm0(ptr5, len5);
        } finally {
            wasm.__wbindgen_free(deferred6_0, deferred6_1, 1);
        }
    }
}
if (Symbol.dispose) FieldMap.prototype[Symbol.dispose] = FieldMap.prototype.free;

/**
 * The epoch secrets of one scope over an in-memory key cache, with the
 * backward walk over the epoch links added with `addLink` (spec §7.3).
 */
export class History {
    __destroy_into_raw() {
        const ptr = this.__wbg_ptr;
        this.__wbg_ptr = 0;
        HistoryFinalization.unregister(this);
        return ptr;
    }
    free() {
        const ptr = this.__destroy_into_raw();
        wasm.__wbg_history_free(ptr, 0);
    }
    /**
     * Adds the epoch link stored for `epoch`.
     * @param {bigint} epoch
     * @param {Uint8Array} link
     */
    addLink(epoch, link) {
        const ptr0 = passArray8ToWasm0(link, wasm.__wbindgen_malloc);
        const len0 = WASM_VECTOR_LEN;
        wasm.history_addLink(this.__wbg_ptr, epoch, ptr0, len0);
    }
    /**
     * Caches the secrets of an epoch below the current one.
     * @param {bigint} epoch
     * @param {Uint8Array} k_e
     * @param {Uint8Array} d_e
     * @param {boolean} verified
     */
    cacheSecrets(epoch, k_e, d_e, verified) {
        const ptr0 = passArray8ToWasm0(k_e, wasm.__wbindgen_malloc);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passArray8ToWasm0(d_e, wasm.__wbindgen_malloc);
        const len1 = WASM_VECTOR_LEN;
        const ret = wasm.history_cacheSecrets(this.__wbg_ptr, epoch, ptr0, len0, ptr1, len1, verified);
        if (ret[1]) {
            throw takeFromExternrefTable0(ret[0]);
        }
    }
    /**
     * The current epoch.
     * @returns {bigint}
     */
    get currentEpoch() {
        const ret = wasm.history_currentEpoch(this.__wbg_ptr);
        return BigInt.asUintN(64, ret);
    }
    /**
     * The epoch of the next link the walk to `epoch` needs, or `undefined`
     * if the secrets of `epoch` are cached.
     * @param {bigint} epoch
     * @returns {bigint | undefined}
     */
    neededLink(epoch) {
        const ret = wasm.history_neededLink(this.__wbg_ptr, epoch);
        if (ret[3]) {
            throw takeFromExternrefTable0(ret[2]);
        }
        return ret[0] === 0 ? undefined : BigInt.asUintN(64, ret[1]);
    }
    /**
     * A history at the current `epoch` with its secrets.
     * @param {string} scope
     * @param {bigint} epoch
     * @param {Uint8Array} k_e
     * @param {Uint8Array} d_e
     */
    constructor(scope, epoch, k_e, d_e) {
        const ptr0 = passStringToWasm0(scope, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passArray8ToWasm0(k_e, wasm.__wbindgen_malloc);
        const len1 = WASM_VECTOR_LEN;
        const ptr2 = passArray8ToWasm0(d_e, wasm.__wbindgen_malloc);
        const len2 = WASM_VECTOR_LEN;
        const ret = wasm.history_new(ptr0, len0, epoch, ptr1, len1, ptr2, len2);
        if (ret[2]) {
            throw takeFromExternrefTable0(ret[1]);
        }
        this.__wbg_ptr = ret[0];
        HistoryFinalization.register(this, this.__wbg_ptr, this);
        return this;
    }
    /**
     * Opens every mapped value of a JSON frame.
     * @param {FieldMap} map
     * @param {string} frame_type
     * @param {string} frame
     * @returns {string}
     */
    openFrame(map, frame_type, frame) {
        let deferred4_0;
        let deferred4_1;
        try {
            _assertClass(map, FieldMap);
            const ptr0 = passStringToWasm0(frame_type, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
            const len0 = WASM_VECTOR_LEN;
            const ptr1 = passStringToWasm0(frame, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
            const len1 = WASM_VECTOR_LEN;
            const ret = wasm.history_openFrame(this.__wbg_ptr, map.__wbg_ptr, ptr0, len0, ptr1, len1);
            var ptr3 = ret[0];
            var len3 = ret[1];
            if (ret[3]) {
                ptr3 = 0; len3 = 0;
                throw takeFromExternrefTable0(ret[2]);
            }
            deferred4_0 = ptr3;
            deferred4_1 = len3;
            return getStringFromWasm0(ptr3, len3);
        } finally {
            wasm.__wbindgen_free(deferred4_0, deferred4_1, 1);
        }
    }
    /**
     * Opens a content, file or drop envelope at `location`.
     * @param {Uint8Array} envelope
     * @param {string} location_text
     * @returns {Uint8Array}
     */
    open(envelope, location_text) {
        const ptr0 = passArray8ToWasm0(envelope, wasm.__wbindgen_malloc);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passStringToWasm0(location_text, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len1 = WASM_VECTOR_LEN;
        const ret = wasm.history_open(this.__wbg_ptr, ptr0, len0, ptr1, len1);
        if (ret[3]) {
            throw takeFromExternrefTable0(ret[2]);
        }
        var v3 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
        wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
        return v3;
    }
    /**
     * `k_e || d_e` of `epoch`, from the cache or the walk.
     * @param {bigint} epoch
     * @returns {Uint8Array}
     */
    secrets(epoch) {
        const ret = wasm.history_secrets(this.__wbg_ptr, epoch);
        if (ret[3]) {
            throw takeFromExternrefTable0(ret[2]);
        }
        var v1 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
        wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
        return v1;
    }
}
if (Symbol.dispose) History.prototype[Symbol.dispose] = History.prototype.free;

/**
 * A party's Ed25519 identity (spec §2.2).
 */
export class Identity {
    static __wrap(ptr) {
        const obj = Object.create(Identity.prototype);
        obj.__wbg_ptr = ptr;
        IdentityFinalization.register(obj, obj.__wbg_ptr, obj);
        return obj;
    }
    __destroy_into_raw() {
        const ptr = this.__wbg_ptr;
        this.__wbg_ptr = 0;
        IdentityFinalization.unregister(this);
        return ptr;
    }
    free() {
        const ptr = this.__destroy_into_raw();
        wasm.__wbg_identity_free(ptr, 0);
    }
    /**
     * The identity of a 32-byte Ed25519 seed.
     * @param {Uint8Array} seed
     * @returns {Identity}
     */
    static fromSeed(seed) {
        const ptr0 = passArray8ToWasm0(seed, wasm.__wbindgen_malloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.identity_fromSeed(ptr0, len0);
        if (ret[2]) {
            throw takeFromExternrefTable0(ret[1]);
        }
        return Identity.__wrap(ret[0]);
    }
    /**
     * A fresh identity.
     * @returns {Identity}
     */
    static generate() {
        const ret = wasm.identity_generate();
        if (ret[2]) {
            throw takeFromExternrefTable0(ret[1]);
        }
        return Identity.__wrap(ret[0]);
    }
    /**
     * The raw 32-byte Ed25519 public key.
     * @returns {Uint8Array}
     */
    get publicKey() {
        const ret = wasm.identity_publicKey(this.__wbg_ptr);
        var v1 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
        wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
        return v1;
    }
    /**
     * The 32-byte seed.
     * @returns {Uint8Array}
     */
    get seed() {
        const ret = wasm.identity_seed(this.__wbg_ptr);
        var v1 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
        wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
        return v1;
    }
}
if (Symbol.dispose) Identity.prototype[Symbol.dispose] = Identity.prototype.free;

/**
 * A party's KeyPackage private keys (spec §2.7).
 */
export class KeyPackageStore {
    static __wrap(ptr) {
        const obj = Object.create(KeyPackageStore.prototype);
        obj.__wbg_ptr = ptr;
        KeyPackageStoreFinalization.register(obj, obj.__wbg_ptr, obj);
        return obj;
    }
    __destroy_into_raw() {
        const ptr = this.__wbg_ptr;
        this.__wbg_ptr = 0;
        KeyPackageStoreFinalization.unregister(this);
        return ptr;
    }
    free() {
        const ptr = this.__destroy_into_raw();
        wasm.__wbg_keypackagestore_free(ptr, 0);
    }
    /**
     * Generates a KeyPackage (TLS-serialized `MLSMessage`) and keeps its
     * private keys.
     * @param {Identity} identity
     * @param {boolean} last_resort
     * @returns {Uint8Array}
     */
    generate(identity, last_resort) {
        _assertClass(identity, Identity);
        const ret = wasm.keypackagestore_generate(this.__wbg_ptr, identity.__wbg_ptr, last_resort);
        if (ret[3]) {
            throw takeFromExternrefTable0(ret[2]);
        }
        var v1 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
        wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
        return v1;
    }
    /**
     * An empty store.
     */
    constructor() {
        const ret = wasm.keypackagestore_new();
        this.__wbg_ptr = ret;
        KeyPackageStoreFinalization.register(this, this.__wbg_ptr, this);
        return this;
    }
    /**
     * A store from `snapshot` bytes.
     * @param {Uint8Array} snapshot
     * @returns {KeyPackageStore}
     */
    static restore(snapshot) {
        const ptr0 = passArray8ToWasm0(snapshot, wasm.__wbindgen_malloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.keypackagestore_restore(ptr0, len0);
        if (ret[2]) {
            throw takeFromExternrefTable0(ret[1]);
        }
        return KeyPackageStore.__wrap(ret[0]);
    }
    /**
     * The store as opaque bytes.
     * @returns {Uint8Array}
     */
    snapshot() {
        const ret = wasm.keypackagestore_snapshot(this.__wbg_ptr);
        if (ret[3]) {
            throw takeFromExternrefTable0(ret[2]);
        }
        var v1 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
        wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
        return v1;
    }
}
if (Symbol.dispose) KeyPackageStore.prototype[Symbol.dispose] = KeyPackageStore.prototype.free;

/**
 * The MLS group of one scope (spec §2.8, §3, §7) with its key cache and
 * the epoch links added with `addLink`.
 */
export class ScopeGroup {
    static __wrap(ptr) {
        const obj = Object.create(ScopeGroup.prototype);
        obj.__wbg_ptr = ptr;
        ScopeGroupFinalization.register(obj, obj.__wbg_ptr, obj);
        return obj;
    }
    __destroy_into_raw() {
        const ptr = this.__wbg_ptr;
        this.__wbg_ptr = 0;
        ScopeGroupFinalization.unregister(this);
        return ptr;
    }
    free() {
        const ptr = this.__destroy_into_raw();
        wasm.__wbg_scopegroup_free(ptr, 0);
    }
    /**
     * Adds the epoch link stored for `epoch`.
     * @param {bigint} epoch
     * @param {Uint8Array} link
     */
    addLink(epoch, link) {
        const ptr0 = passArray8ToWasm0(link, wasm.__wbindgen_malloc);
        const len0 = WASM_VECTOR_LEN;
        wasm.scopegroup_addLink(this.__wbg_ptr, epoch, ptr0, len0);
    }
    /**
     * Commits the addition of the parties of base64url KeyPackages and
     * returns the JSON commit unit. With `key_history_from`, key history
     * from that epoch is attached for the joiners, sealed to each joiner's
     * leaf if `key_history_sealed`.
     * @param {Identity} identity
     * @param {string[]} key_packages
     * @param {bigint | null | undefined} key_history_from
     * @param {boolean} key_history_sealed
     * @returns {string}
     */
    addMembers(identity, key_packages, key_history_from, key_history_sealed) {
        let deferred3_0;
        let deferred3_1;
        try {
            _assertClass(identity, Identity);
            const ptr0 = passArrayJsValueToWasm0(key_packages, wasm.__wbindgen_malloc);
            const len0 = WASM_VECTOR_LEN;
            const ret = wasm.scopegroup_addMembers(this.__wbg_ptr, identity.__wbg_ptr, ptr0, len0, !isLikeNone(key_history_from), isLikeNone(key_history_from) ? BigInt(0) : key_history_from, key_history_sealed);
            var ptr2 = ret[0];
            var len2 = ret[1];
            if (ret[3]) {
                ptr2 = 0; len2 = 0;
                throw takeFromExternrefTable0(ret[2]);
            }
            deferred3_0 = ptr2;
            deferred3_1 = len2;
            return getStringFromWasm0(ptr2, len2);
        } finally {
            wasm.__wbindgen_free(deferred3_0, deferred3_1, 1);
        }
    }
    /**
     * Applies the next JSON log entry `{"seq", "kind", "epoch", "bytes",
     * "drop_public_key"?}` and returns the JSON effect.
     * @param {string} entry
     * @returns {string}
     */
    apply(entry) {
        let deferred3_0;
        let deferred3_1;
        try {
            const ptr0 = passStringToWasm0(entry, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
            const len0 = WASM_VECTOR_LEN;
            const ret = wasm.scopegroup_apply(this.__wbg_ptr, ptr0, len0);
            var ptr2 = ret[0];
            var len2 = ret[1];
            if (ret[3]) {
                ptr2 = 0; len2 = 0;
                throw takeFromExternrefTable0(ret[2]);
            }
            deferred3_0 = ptr2;
            deferred3_1 = len2;
            return getStringFromWasm0(ptr2, len2);
        } finally {
            wasm.__wbindgen_free(deferred3_0, deferred3_1, 1);
        }
    }
    /**
     * The DS accepted the pending commit at `seq`: merges it.
     * @param {bigint} seq
     */
    commitAccepted(seq) {
        const ret = wasm.scopegroup_commitAccepted(this.__wbg_ptr, seq);
        if (ret[1]) {
            throw takeFromExternrefTable0(ret[0]);
        }
    }
    /**
     * The DS rejected the pending commit: discards it.
     */
    commitRejected() {
        const ret = wasm.scopegroup_commitRejected(this.__wbg_ptr);
        if (ret[1]) {
            throw takeFromExternrefTable0(ret[0]);
        }
    }
    /**
     * Creates the group of `scope` at epoch 0 with `identity` as the only
     * member, under a JSON history policy.
     * @param {Identity} identity
     * @param {string} profile
     * @param {string} scope
     * @param {string} policy
     * @returns {ScopeGroup}
     */
    static create(identity, profile, scope, policy) {
        _assertClass(identity, Identity);
        const ptr0 = passStringToWasm0(profile, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passStringToWasm0(scope, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len1 = WASM_VECTOR_LEN;
        const ptr2 = passStringToWasm0(policy, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len2 = WASM_VECTOR_LEN;
        const ret = wasm.scopegroup_create(identity.__wbg_ptr, ptr0, len0, ptr1, len1, ptr2, len2);
        if (ret[2]) {
            throw takeFromExternrefTable0(ret[1]);
        }
        return ScopeGroup.__wrap(ret[0]);
    }
    /**
     * `k_e || d_e` of the current epoch.
     * @returns {Uint8Array}
     */
    currentSecrets() {
        const ret = wasm.scopegroup_currentSecrets(this.__wbg_ptr);
        if (ret[3]) {
            throw takeFromExternrefTable0(ret[2]);
        }
        var v1 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
        wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
        return v1;
    }
    /**
     * The drop public key of the current epoch.
     * @returns {Uint8Array}
     */
    dropPublicKey() {
        const ret = wasm.scopegroup_dropPublicKey(this.__wbg_ptr);
        if (ret[3]) {
            throw takeFromExternrefTable0(ret[2]);
        }
        var v1 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
        wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
        return v1;
    }
    /**
     * The current epoch.
     * @returns {bigint}
     */
    get epoch() {
        const ret = wasm.scopegroup_epoch(this.__wbg_ptr);
        return BigInt.asUintN(64, ret);
    }
    /**
     * The 32-byte group id.
     * @returns {Uint8Array}
     */
    get groupId() {
        const ret = wasm.scopegroup_groupId(this.__wbg_ptr);
        var v1 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
        wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
        return v1;
    }
    /**
     * Whether a commit awaits the DS answer.
     * @returns {boolean}
     */
    get hasPendingCommit() {
        const ret = wasm.scopegroup_hasPendingCommit(this.__wbg_ptr);
        return ret !== 0;
    }
    /**
     * Whether this party still holds a leaf.
     * @returns {boolean}
     */
    get isMember() {
        const ret = wasm.scopegroup_isMember(this.__wbg_ptr);
        return ret !== 0;
    }
    /**
     * Joins from a Welcome delivered with the `seq` of its commit.
     * @param {KeyPackageStore} key_packages
     * @param {string} profile
     * @param {string} scope
     * @param {Uint8Array} welcome
     * @param {bigint} seq
     * @returns {ScopeGroup}
     */
    static join(key_packages, profile, scope, welcome, seq) {
        _assertClass(key_packages, KeyPackageStore);
        const ptr0 = passStringToWasm0(profile, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passStringToWasm0(scope, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len1 = WASM_VECTOR_LEN;
        const ptr2 = passArray8ToWasm0(welcome, wasm.__wbindgen_malloc);
        const len2 = WASM_VECTOR_LEN;
        const ret = wasm.scopegroup_join(key_packages.__wbg_ptr, ptr0, len0, ptr1, len1, ptr2, len2, seq);
        if (ret[2]) {
            throw takeFromExternrefTable0(ret[1]);
        }
        return ScopeGroup.__wrap(ret[0]);
    }
    /**
     * The members' Ed25519 public keys in leaf order, base64url.
     * @returns {string[]}
     */
    members() {
        const ret = wasm.scopegroup_members(this.__wbg_ptr);
        var v1 = getArrayJsValueFromWasm0(ret[0], ret[1]);
        wasm.__wbindgen_free(ret[0], ret[1] * 4, 4);
        return v1;
    }
    /**
     * The epoch of the next link the walk to `epoch` needs, or `undefined`
     * if the secrets of `epoch` are cached.
     * @param {bigint} epoch
     * @returns {bigint | undefined}
     */
    neededLink(epoch) {
        const ret = wasm.scopegroup_neededLink(this.__wbg_ptr, epoch);
        if (ret[3]) {
            throw takeFromExternrefTable0(ret[2]);
        }
        return ret[0] === 0 ? undefined : BigInt.asUintN(64, ret[1]);
    }
    /**
     * Opens every mapped value of a JSON frame.
     * @param {FieldMap} map
     * @param {string} frame_type
     * @param {string} frame
     * @returns {string}
     */
    openFrame(map, frame_type, frame) {
        let deferred4_0;
        let deferred4_1;
        try {
            _assertClass(map, FieldMap);
            const ptr0 = passStringToWasm0(frame_type, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
            const len0 = WASM_VECTOR_LEN;
            const ptr1 = passStringToWasm0(frame, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
            const len1 = WASM_VECTOR_LEN;
            const ret = wasm.scopegroup_openFrame(this.__wbg_ptr, map.__wbg_ptr, ptr0, len0, ptr1, len1);
            var ptr3 = ret[0];
            var len3 = ret[1];
            if (ret[3]) {
                ptr3 = 0; len3 = 0;
                throw takeFromExternrefTable0(ret[2]);
            }
            deferred4_0 = ptr3;
            deferred4_1 = len3;
            return getStringFromWasm0(ptr3, len3);
        } finally {
            wasm.__wbindgen_free(deferred4_0, deferred4_1, 1);
        }
    }
    /**
     * Opens a content, file or drop envelope at `location`.
     * @param {Uint8Array} envelope
     * @param {string} location_text
     * @returns {Uint8Array}
     */
    open(envelope, location_text) {
        const ptr0 = passArray8ToWasm0(envelope, wasm.__wbindgen_malloc);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passStringToWasm0(location_text, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len1 = WASM_VECTOR_LEN;
        const ret = wasm.scopegroup_open(this.__wbg_ptr, ptr0, len0, ptr1, len1);
        if (ret[3]) {
            throw takeFromExternrefTable0(ret[2]);
        }
        var v3 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
        wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
        return v3;
    }
    /**
     * The JSON history policy of the current epoch.
     * @returns {string}
     */
    policy() {
        let deferred2_0;
        let deferred2_1;
        try {
            const ret = wasm.scopegroup_policy(this.__wbg_ptr);
            var ptr1 = ret[0];
            var len1 = ret[1];
            if (ret[3]) {
                ptr1 = 0; len1 = 0;
                throw takeFromExternrefTable0(ret[2]);
            }
            deferred2_0 = ptr1;
            deferred2_1 = len1;
            return getStringFromWasm0(ptr1, len1);
        } finally {
            wasm.__wbindgen_free(deferred2_0, deferred2_1, 1);
        }
    }
    /**
     * The profile id.
     * @returns {string}
     */
    get profile() {
        let deferred1_0;
        let deferred1_1;
        try {
            const ret = wasm.scopegroup_profile(this.__wbg_ptr);
            deferred1_0 = ret[0];
            deferred1_1 = ret[1];
            return getStringFromWasm0(ret[0], ret[1]);
        } finally {
            wasm.__wbindgen_free(deferred1_0, deferred1_1, 1);
        }
    }
    /**
     * Commits the removal of the members with the given base64url Ed25519
     * public keys and returns the JSON commit unit.
     * @param {Identity} identity
     * @param {string[]} public_keys
     * @returns {string}
     */
    removeMembers(identity, public_keys) {
        let deferred3_0;
        let deferred3_1;
        try {
            _assertClass(identity, Identity);
            const ptr0 = passArrayJsValueToWasm0(public_keys, wasm.__wbindgen_malloc);
            const len0 = WASM_VECTOR_LEN;
            const ret = wasm.scopegroup_removeMembers(this.__wbg_ptr, identity.__wbg_ptr, ptr0, len0);
            var ptr2 = ret[0];
            var len2 = ret[1];
            if (ret[3]) {
                ptr2 = 0; len2 = 0;
                throw takeFromExternrefTable0(ret[2]);
            }
            deferred3_0 = ptr2;
            deferred3_1 = len2;
            return getStringFromWasm0(ptr2, len2);
        } finally {
            wasm.__wbindgen_free(deferred3_0, deferred3_1, 1);
        }
    }
    /**
     * A group from `snapshot` bytes.
     * @param {Uint8Array} snapshot
     * @returns {ScopeGroup}
     */
    static restore(snapshot) {
        const ptr0 = passArray8ToWasm0(snapshot, wasm.__wbindgen_malloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.scopegroup_restore(ptr0, len0);
        if (ret[2]) {
            throw takeFromExternrefTable0(ret[1]);
        }
        return ScopeGroup.__wrap(ret[0]);
    }
    /**
     * The scope id.
     * @returns {string}
     */
    get scope() {
        let deferred1_0;
        let deferred1_1;
        try {
            const ret = wasm.scopegroup_scope(this.__wbg_ptr);
            deferred1_0 = ret[0];
            deferred1_1 = ret[1];
            return getStringFromWasm0(ret[0], ret[1]);
        } finally {
            wasm.__wbindgen_free(deferred1_0, deferred1_1, 1);
        }
    }
    /**
     * Seals every mapped value of a JSON frame under the current epoch.
     * @param {FieldMap} map
     * @param {string} frame_type
     * @param {string} frame
     * @returns {string}
     */
    sealFrame(map, frame_type, frame) {
        let deferred4_0;
        let deferred4_1;
        try {
            _assertClass(map, FieldMap);
            const ptr0 = passStringToWasm0(frame_type, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
            const len0 = WASM_VECTOR_LEN;
            const ptr1 = passStringToWasm0(frame, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
            const len1 = WASM_VECTOR_LEN;
            const ret = wasm.scopegroup_sealFrame(this.__wbg_ptr, map.__wbg_ptr, ptr0, len0, ptr1, len1);
            var ptr3 = ret[0];
            var len3 = ret[1];
            if (ret[3]) {
                ptr3 = 0; len3 = 0;
                throw takeFromExternrefTable0(ret[2]);
            }
            deferred4_0 = ptr3;
            deferred4_1 = len3;
            return getStringFromWasm0(ptr3, len3);
        } finally {
            wasm.__wbindgen_free(deferred4_0, deferred4_1, 1);
        }
    }
    /**
     * `k_e || d_e` of `epoch`, from the cache or the walk.
     * @param {bigint} epoch
     * @returns {Uint8Array}
     */
    secrets(epoch) {
        const ret = wasm.scopegroup_secrets(this.__wbg_ptr, epoch);
        if (ret[3]) {
            throw takeFromExternrefTable0(ret[2]);
        }
        var v1 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
        wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
        return v1;
    }
    /**
     * Commits an Update of this member's own leaf.
     * @param {Identity} identity
     * @returns {string}
     */
    selfUpdate(identity) {
        let deferred2_0;
        let deferred2_1;
        try {
            _assertClass(identity, Identity);
            const ret = wasm.scopegroup_selfUpdate(this.__wbg_ptr, identity.__wbg_ptr);
            var ptr1 = ret[0];
            var len1 = ret[1];
            if (ret[3]) {
                ptr1 = 0; len1 = 0;
                throw takeFromExternrefTable0(ret[2]);
            }
            deferred2_0 = ptr1;
            deferred2_1 = len1;
            return getStringFromWasm0(ptr1, len1);
        } finally {
            wasm.__wbindgen_free(deferred2_0, deferred2_1, 1);
        }
    }
    /**
     * The `seq` of the last applied log entry.
     * @returns {bigint}
     */
    get seq() {
        const ret = wasm.scopegroup_seq(this.__wbg_ptr);
        return BigInt.asUintN(64, ret);
    }
    /**
     * Commits a new JSON history policy.
     * @param {Identity} identity
     * @param {string} policy
     * @returns {string}
     */
    setPolicy(identity, policy) {
        let deferred3_0;
        let deferred3_1;
        try {
            _assertClass(identity, Identity);
            const ptr0 = passStringToWasm0(policy, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
            const len0 = WASM_VECTOR_LEN;
            const ret = wasm.scopegroup_setPolicy(this.__wbg_ptr, identity.__wbg_ptr, ptr0, len0);
            var ptr2 = ret[0];
            var len2 = ret[1];
            if (ret[3]) {
                ptr2 = 0; len2 = 0;
                throw takeFromExternrefTable0(ret[2]);
            }
            deferred3_0 = ptr2;
            deferred3_1 = len2;
            return getStringFromWasm0(ptr2, len2);
        } finally {
            wasm.__wbindgen_free(deferred3_0, deferred3_1, 1);
        }
    }
    /**
     * The group state and its key cache as opaque bytes. They hold epoch
     * secrets: the caller stores them encrypted at rest.
     * @returns {Uint8Array}
     */
    snapshot() {
        const ret = wasm.scopegroup_snapshot(this.__wbg_ptr);
        if (ret[3]) {
            throw takeFromExternrefTable0(ret[2]);
        }
        var v1 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
        wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
        return v1;
    }
}
if (Symbol.dispose) ScopeGroup.prototype[Symbol.dispose] = ScopeGroup.prototype.free;

/**
 * Resolves an AAD template against a JSON frame (spec §12.3).
 * @param {string} template
 * @param {string} frame
 * @param {number | null} [element]
 * @returns {string}
 */
export function buildLocation(template, frame, element) {
    let deferred4_0;
    let deferred4_1;
    try {
        const ptr0 = passStringToWasm0(template, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passStringToWasm0(frame, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len1 = WASM_VECTOR_LEN;
        const ret = wasm.buildLocation(ptr0, len0, ptr1, len1, isLikeNone(element) ? Number.MAX_SAFE_INTEGER : (element) >>> 0);
        var ptr3 = ret[0];
        var len3 = ret[1];
        if (ret[3]) {
            ptr3 = 0; len3 = 0;
            throw takeFromExternrefTable0(ret[2]);
        }
        deferred4_0 = ptr3;
        deferred4_1 = len3;
        return getStringFromWasm0(ptr3, len3);
    } finally {
        wasm.__wbindgen_free(deferred4_0, deferred4_1, 1);
    }
}

/**
 * Strict base64url without padding (spec §5.1).
 * @param {string} text
 * @returns {Uint8Array}
 */
export function decodeB64url(text) {
    const ptr0 = passStringToWasm0(text, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len0 = WASM_VECTOR_LEN;
    const ret = wasm.decodeB64url(ptr0, len0);
    if (ret[3]) {
        throw takeFromExternrefTable0(ret[2]);
    }
    var v2 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
    wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
    return v2;
}

/**
 * The JSON history policy of an `extension_data`.
 * @param {Uint8Array} data
 * @returns {string}
 */
export function decodeHistoryPolicy(data) {
    let deferred3_0;
    let deferred3_1;
    try {
        const ptr0 = passArray8ToWasm0(data, wasm.__wbindgen_malloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.decodeHistoryPolicy(ptr0, len0);
        var ptr2 = ret[0];
        var len2 = ret[1];
        if (ret[3]) {
            ptr2 = 0; len2 = 0;
            throw takeFromExternrefTable0(ret[2]);
        }
        deferred3_0 = ptr2;
        deferred3_1 = len2;
        return getStringFromWasm0(ptr2, len2);
    } finally {
        wasm.__wbindgen_free(deferred3_0, deferred3_1, 1);
    }
}

/**
 * The JSON key-history record of an MLS application data payload.
 * @param {Uint8Array} payload
 * @returns {string}
 */
export function decodeKeyHistory(payload) {
    let deferred3_0;
    let deferred3_1;
    try {
        const ptr0 = passArray8ToWasm0(payload, wasm.__wbindgen_malloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.decodeKeyHistory(ptr0, len0);
        var ptr2 = ret[0];
        var len2 = ret[1];
        if (ret[3]) {
            ptr2 = 0; len2 = 0;
            throw takeFromExternrefTable0(ret[2]);
        }
        deferred3_0 = ptr2;
        deferred3_1 = len2;
        return getStringFromWasm0(ptr2, len2);
    } finally {
        wasm.__wbindgen_free(deferred3_0, deferred3_1, 1);
    }
}

/**
 * Decodes an opened plaintext of kind `text` or `json` (spec §12.4) and
 * returns the value as JSON.
 * @param {Uint8Array} plaintext
 * @param {string} kind
 * @returns {string}
 */
export function decodePlaintext(plaintext, kind) {
    let deferred4_0;
    let deferred4_1;
    try {
        const ptr0 = passArray8ToWasm0(plaintext, wasm.__wbindgen_malloc);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passStringToWasm0(kind, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len1 = WASM_VECTOR_LEN;
        const ret = wasm.decodePlaintext(ptr0, len0, ptr1, len1);
        var ptr3 = ret[0];
        var len3 = ret[1];
        if (ret[3]) {
            ptr3 = 0; len3 = 0;
            throw takeFromExternrefTable0(ret[2]);
        }
        deferred4_0 = ptr3;
        deferred4_1 = len3;
        return getStringFromWasm0(ptr3, len3);
    } finally {
        wasm.__wbindgen_free(deferred4_0, deferred4_1, 1);
    }
}

/**
 * base64url without padding.
 * @param {Uint8Array} bytes
 * @returns {string}
 */
export function encodeB64url(bytes) {
    let deferred2_0;
    let deferred2_1;
    try {
        const ptr0 = passArray8ToWasm0(bytes, wasm.__wbindgen_malloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.encodeB64url(ptr0, len0);
        deferred2_0 = ret[0];
        deferred2_1 = ret[1];
        return getStringFromWasm0(ret[0], ret[1]);
    } finally {
        wasm.__wbindgen_free(deferred2_0, deferred2_1, 1);
    }
}

/**
 * The `extension_data` of a history policy given as JSON (`"full"`,
 * `"from_join"` or `{"from_epoch": N}`).
 * @param {string} policy
 * @returns {Uint8Array}
 */
export function encodeHistoryPolicy(policy) {
    const ptr0 = passStringToWasm0(policy, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len0 = WASM_VECTOR_LEN;
    const ret = wasm.encodeHistoryPolicy(ptr0, len0);
    if (ret[3]) {
        throw takeFromExternrefTable0(ret[2]);
    }
    var v2 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
    wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
    return v2;
}

/**
 * The MLS application data of a key-history record given as JSON
 * `{"epoch", "entries": [{"epoch", "k", "d"}]}` (spec §5.7).
 * @param {string} history
 * @returns {Uint8Array}
 */
export function encodeKeyHistory(history) {
    const ptr0 = passStringToWasm0(history, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len0 = WASM_VECTOR_LEN;
    const ret = wasm.encodeKeyHistory(ptr0, len0);
    if (ret[3]) {
        throw takeFromExternrefTable0(ret[2]);
    }
    var v2 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
    wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
    return v2;
}

/**
 * The header of an envelope as JSON `{"type": <name>, "epoch": <integer>}`.
 * @param {Uint8Array} envelope
 * @returns {string}
 */
export function envelopeHeader(envelope) {
    let deferred3_0;
    let deferred3_1;
    try {
        const ptr0 = passArray8ToWasm0(envelope, wasm.__wbindgen_malloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.envelopeHeader(ptr0, len0);
        var ptr2 = ret[0];
        var len2 = ret[1];
        if (ret[3]) {
            ptr2 = 0; len2 = 0;
            throw takeFromExternrefTable0(ret[2]);
        }
        deferred3_0 = ptr2;
        deferred3_1 = len2;
        return getStringFromWasm0(ptr2, len2);
    } finally {
        wasm.__wbindgen_free(deferred3_0, deferred3_1, 1);
    }
}

/**
 * The lower-case hex SHA-256 of a file envelope (the descriptor `sha256`).
 * @param {Uint8Array} envelope
 * @returns {string}
 */
export function fileSha256(envelope) {
    let deferred2_0;
    let deferred2_1;
    try {
        const ptr0 = passArray8ToWasm0(envelope, wasm.__wbindgen_malloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.fileSha256(ptr0, len0);
        deferred2_0 = ret[0];
        deferred2_1 = ret[1];
        return getStringFromWasm0(ret[0], ret[1]);
    } finally {
        wasm.__wbindgen_free(deferred2_0, deferred2_1, 1);
    }
}

/**
 * The canonical fingerprint of an Ed25519 public key (spec §3.5).
 * @param {Uint8Array} public_key
 * @returns {string}
 */
export function fingerprint(public_key) {
    let deferred3_0;
    let deferred3_1;
    try {
        const ptr0 = passArray8ToWasm0(public_key, wasm.__wbindgen_malloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.fingerprint(ptr0, len0);
        var ptr2 = ret[0];
        var len2 = ret[1];
        if (ret[3]) {
            ptr2 = 0; len2 = 0;
            throw takeFromExternrefTable0(ret[2]);
        }
        deferred3_0 = ptr2;
        deferred3_1 = len2;
        return getStringFromWasm0(ptr2, len2);
    } finally {
        wasm.__wbindgen_free(deferred3_0, deferred3_1, 1);
    }
}

/**
 * The display form of a fingerprint.
 * @param {Uint8Array} public_key
 * @returns {string}
 */
export function fingerprintDisplay(public_key) {
    let deferred3_0;
    let deferred3_1;
    try {
        const ptr0 = passArray8ToWasm0(public_key, wasm.__wbindgen_malloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.fingerprintDisplay(ptr0, len0);
        var ptr2 = ret[0];
        var len2 = ret[1];
        if (ret[3]) {
            ptr2 = 0; len2 = 0;
            throw takeFromExternrefTable0(ret[2]);
        }
        deferred3_0 = ptr2;
        deferred3_1 = len2;
        return getStringFromWasm0(ptr2, len2);
    } finally {
        wasm.__wbindgen_free(deferred3_0, deferred3_1, 1);
    }
}

/**
 * The envelope of a JSON mapped value (spec §12.4).
 * @param {string} value
 * @returns {Uint8Array}
 */
export function fromSealedValue(value) {
    const ptr0 = passStringToWasm0(value, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len0 = WASM_VECTOR_LEN;
    const ret = wasm.fromSealedValue(ptr0, len0);
    if (ret[3]) {
        throw takeFromExternrefTable0(ret[2]);
    }
    var v2 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
    wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
    return v2;
}

/**
 * The 32-byte group id of a profile and scope (spec §2.3).
 * @param {string} profile
 * @param {string} scope
 * @returns {Uint8Array}
 */
export function groupId(profile, scope) {
    const ptr0 = passStringToWasm0(profile, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len0 = WASM_VECTOR_LEN;
    const ptr1 = passStringToWasm0(scope, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len1 = WASM_VECTOR_LEN;
    const ret = wasm.groupId(ptr0, len0, ptr1, len1);
    if (ret[3]) {
        throw takeFromExternrefTable0(ret[2]);
    }
    var v3 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
    wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
    return v3;
}

/**
 * Validates an uploaded KeyPackage at `now` (seconds since the Unix epoch)
 * and returns JSON `{"ref", "public_key", "last_resort", "not_before",
 * "not_after"}`.
 * @param {Uint8Array} bytes
 * @param {bigint} now
 * @returns {string}
 */
export function inspectKeyPackage(bytes, now) {
    let deferred3_0;
    let deferred3_1;
    try {
        const ptr0 = passArray8ToWasm0(bytes, wasm.__wbindgen_malloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.inspectKeyPackage(ptr0, len0, now);
        var ptr2 = ret[0];
        var len2 = ret[1];
        if (ret[3]) {
            ptr2 = 0; len2 = 0;
            throw takeFromExternrefTable0(ret[2]);
        }
        deferred3_0 = ptr2;
        deferred3_1 = len2;
        return getStringFromWasm0(ptr2, len2);
    } finally {
        wasm.__wbindgen_free(deferred3_0, deferred3_1, 1);
    }
}

/**
 * Inspects a PublicMessage and returns JSON `{"group_id", "epoch",
 * "content_type", "sender_leaf", "adds", "removes", "proposal_refs",
 * "updates_path"}`.
 * @param {Uint8Array} bytes
 * @returns {string}
 */
export function inspectMessage(bytes) {
    let deferred3_0;
    let deferred3_1;
    try {
        const ptr0 = passArray8ToWasm0(bytes, wasm.__wbindgen_malloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.inspectMessage(ptr0, len0);
        var ptr2 = ret[0];
        var len2 = ret[1];
        if (ret[3]) {
            ptr2 = 0; len2 = 0;
            throw takeFromExternrefTable0(ret[2]);
        }
        deferred3_0 = ptr2;
        deferred3_1 = len2;
        return getStringFromWasm0(ptr2, len2);
    } finally {
        wasm.__wbindgen_free(deferred3_0, deferred3_1, 1);
    }
}

/**
 * The per-envelope key `k_msg` (spec §4.3).
 * @param {Uint8Array} k_e
 * @param {Uint8Array} salt
 * @returns {Uint8Array}
 */
export function messageKey(k_e, salt) {
    const ptr0 = passArray8ToWasm0(k_e, wasm.__wbindgen_malloc);
    const len0 = WASM_VECTOR_LEN;
    const ptr1 = passArray8ToWasm0(salt, wasm.__wbindgen_malloc);
    const len1 = WASM_VECTOR_LEN;
    const ret = wasm.messageKey(ptr0, len0, ptr1, len1);
    if (ret[3]) {
        throw takeFromExternrefTable0(ret[2]);
    }
    var v3 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
    wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
    return v3;
}

/**
 * Opens a content envelope.
 * @param {Uint8Array} k_e
 * @param {Uint8Array} envelope
 * @param {string} location_text
 * @returns {Uint8Array}
 */
export function openContent(k_e, envelope, location_text) {
    const ptr0 = passArray8ToWasm0(k_e, wasm.__wbindgen_malloc);
    const len0 = WASM_VECTOR_LEN;
    const ptr1 = passArray8ToWasm0(envelope, wasm.__wbindgen_malloc);
    const len1 = WASM_VECTOR_LEN;
    const ptr2 = passStringToWasm0(location_text, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len2 = WASM_VECTOR_LEN;
    const ret = wasm.openContent(ptr0, len0, ptr1, len1, ptr2, len2);
    if (ret[3]) {
        throw takeFromExternrefTable0(ret[2]);
    }
    var v4 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
    wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
    return v4;
}

/**
 * Opens a drop envelope with the drop seed of its epoch.
 * @param {Uint8Array} d_e
 * @param {Uint8Array} envelope
 * @param {string} location_text
 * @returns {Uint8Array}
 */
export function openDrop(d_e, envelope, location_text) {
    const ptr0 = passArray8ToWasm0(d_e, wasm.__wbindgen_malloc);
    const len0 = WASM_VECTOR_LEN;
    const ptr1 = passArray8ToWasm0(envelope, wasm.__wbindgen_malloc);
    const len1 = WASM_VECTOR_LEN;
    const ptr2 = passStringToWasm0(location_text, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len2 = WASM_VECTOR_LEN;
    const ret = wasm.openDrop(ptr0, len0, ptr1, len1, ptr2, len2);
    if (ret[3]) {
        throw takeFromExternrefTable0(ret[2]);
    }
    var v4 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
    wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
    return v4;
}

/**
 * Opens the epoch link stored for `epoch + 1` and returns `k_e || d_e`.
 * @param {string} scope
 * @param {bigint} epoch
 * @param {Uint8Array} k_next
 * @param {Uint8Array} link
 * @returns {Uint8Array}
 */
export function openEpochLink(scope, epoch, k_next, link) {
    const ptr0 = passStringToWasm0(scope, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len0 = WASM_VECTOR_LEN;
    const ptr1 = passArray8ToWasm0(k_next, wasm.__wbindgen_malloc);
    const len1 = WASM_VECTOR_LEN;
    const ptr2 = passArray8ToWasm0(link, wasm.__wbindgen_malloc);
    const len2 = WASM_VECTOR_LEN;
    const ret = wasm.openEpochLink(ptr0, len0, epoch, ptr1, len1, ptr2, len2);
    if (ret[3]) {
        throw takeFromExternrefTable0(ret[2]);
    }
    var v4 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
    wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
    return v4;
}

/**
 * Opens a file envelope.
 * @param {Uint8Array} k_e
 * @param {Uint8Array} envelope
 * @param {string} location_text
 * @returns {Uint8Array}
 */
export function openFile(k_e, envelope, location_text) {
    const ptr0 = passArray8ToWasm0(k_e, wasm.__wbindgen_malloc);
    const len0 = WASM_VECTOR_LEN;
    const ptr1 = passArray8ToWasm0(envelope, wasm.__wbindgen_malloc);
    const len1 = WASM_VECTOR_LEN;
    const ptr2 = passStringToWasm0(location_text, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len2 = WASM_VECTOR_LEN;
    const ret = wasm.openFile(ptr0, len0, ptr1, len1, ptr2, len2);
    if (ret[3]) {
        throw takeFromExternrefTable0(ret[2]);
    }
    var v4 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
    wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
    return v4;
}

/**
 * Opens a key-history envelope sealed to the leaf at `leaf_index` and
 * returns the JSON record.
 * @param {string} scope
 * @param {number} leaf_index
 * @param {Uint8Array} leaf_private_key
 * @param {Uint8Array} envelope
 * @returns {string}
 */
export function openKeyHistorySealed(scope, leaf_index, leaf_private_key, envelope) {
    let deferred5_0;
    let deferred5_1;
    try {
        const ptr0 = passStringToWasm0(scope, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passArray8ToWasm0(leaf_private_key, wasm.__wbindgen_malloc);
        const len1 = WASM_VECTOR_LEN;
        const ptr2 = passArray8ToWasm0(envelope, wasm.__wbindgen_malloc);
        const len2 = WASM_VECTOR_LEN;
        const ret = wasm.openKeyHistorySealed(ptr0, len0, leaf_index, ptr1, len1, ptr2, len2);
        var ptr4 = ret[0];
        var len4 = ret[1];
        if (ret[3]) {
            ptr4 = 0; len4 = 0;
            throw takeFromExternrefTable0(ret[2]);
        }
        deferred5_0 = ptr4;
        deferred5_1 = len4;
        return getStringFromWasm0(ptr4, len4);
    } finally {
        wasm.__wbindgen_free(deferred5_0, deferred5_1, 1);
    }
}

/**
 * Checks a location string (spec §6) and returns it.
 * @param {string} text
 * @returns {string}
 */
export function parseLocation(text) {
    let deferred3_0;
    let deferred3_1;
    try {
        const ptr0 = passStringToWasm0(text, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.parseLocation(ptr0, len0);
        var ptr2 = ret[0];
        var len2 = ret[1];
        if (ret[3]) {
            ptr2 = 0; len2 = 0;
            throw takeFromExternrefTable0(ret[2]);
        }
        deferred3_0 = ptr2;
        deferred3_1 = len2;
        return getStringFromWasm0(ptr2, len2);
    } finally {
        wasm.__wbindgen_free(deferred3_0, deferred3_1, 1);
    }
}

/**
 * Seals a content envelope (spec §5.3).
 * @param {Uint8Array} k_e
 * @param {bigint} epoch
 * @param {string} location_text
 * @param {Uint8Array} plaintext
 * @param {Uint8Array | null} [random]
 * @returns {Uint8Array}
 */
export function sealContent(k_e, epoch, location_text, plaintext, random) {
    const ptr0 = passArray8ToWasm0(k_e, wasm.__wbindgen_malloc);
    const len0 = WASM_VECTOR_LEN;
    const ptr1 = passStringToWasm0(location_text, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len1 = WASM_VECTOR_LEN;
    const ptr2 = passArray8ToWasm0(plaintext, wasm.__wbindgen_malloc);
    const len2 = WASM_VECTOR_LEN;
    var ptr3 = isLikeNone(random) ? 0 : passArray8ToWasm0(random, wasm.__wbindgen_malloc);
    var len3 = WASM_VECTOR_LEN;
    const ret = wasm.sealContent(ptr0, len0, epoch, ptr1, len1, ptr2, len2, ptr3, len3);
    if (ret[3]) {
        throw takeFromExternrefTable0(ret[2]);
    }
    var v5 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
    wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
    return v5;
}

/**
 * Seals a drop envelope to the drop public key of `epoch` (spec §5.5).
 * @param {Uint8Array} public_key
 * @param {bigint} epoch
 * @param {string} location_text
 * @param {Uint8Array} plaintext
 * @returns {Uint8Array}
 */
export function sealDrop(public_key, epoch, location_text, plaintext) {
    const ptr0 = passArray8ToWasm0(public_key, wasm.__wbindgen_malloc);
    const len0 = WASM_VECTOR_LEN;
    const ptr1 = passStringToWasm0(location_text, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len1 = WASM_VECTOR_LEN;
    const ptr2 = passArray8ToWasm0(plaintext, wasm.__wbindgen_malloc);
    const len2 = WASM_VECTOR_LEN;
    const ret = wasm.sealDrop(ptr0, len0, epoch, ptr1, len1, ptr2, len2);
    if (ret[3]) {
        throw takeFromExternrefTable0(ret[2]);
    }
    var v4 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
    wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
    return v4;
}

/**
 * Seals the epoch link carrying `E_epoch` under `k_next` (spec §5.6).
 * @param {string} scope
 * @param {bigint} epoch
 * @param {Uint8Array} k_e
 * @param {Uint8Array} d_e
 * @param {Uint8Array} k_next
 * @param {Uint8Array | null} [random]
 * @returns {Uint8Array}
 */
export function sealEpochLink(scope, epoch, k_e, d_e, k_next, random) {
    const ptr0 = passStringToWasm0(scope, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len0 = WASM_VECTOR_LEN;
    const ptr1 = passArray8ToWasm0(k_e, wasm.__wbindgen_malloc);
    const len1 = WASM_VECTOR_LEN;
    const ptr2 = passArray8ToWasm0(d_e, wasm.__wbindgen_malloc);
    const len2 = WASM_VECTOR_LEN;
    const ptr3 = passArray8ToWasm0(k_next, wasm.__wbindgen_malloc);
    const len3 = WASM_VECTOR_LEN;
    var ptr4 = isLikeNone(random) ? 0 : passArray8ToWasm0(random, wasm.__wbindgen_malloc);
    var len4 = WASM_VECTOR_LEN;
    const ret = wasm.sealEpochLink(ptr0, len0, epoch, ptr1, len1, ptr2, len2, ptr3, len3, ptr4, len4);
    if (ret[3]) {
        throw takeFromExternrefTable0(ret[2]);
    }
    var v6 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
    wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
    return v6;
}

/**
 * Seals a file envelope (spec §5.4).
 * @param {Uint8Array} k_e
 * @param {bigint} epoch
 * @param {string} location_text
 * @param {Uint8Array} bytes
 * @param {Uint8Array | null} [random]
 * @returns {Uint8Array}
 */
export function sealFile(k_e, epoch, location_text, bytes, random) {
    const ptr0 = passArray8ToWasm0(k_e, wasm.__wbindgen_malloc);
    const len0 = WASM_VECTOR_LEN;
    const ptr1 = passStringToWasm0(location_text, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len1 = WASM_VECTOR_LEN;
    const ptr2 = passArray8ToWasm0(bytes, wasm.__wbindgen_malloc);
    const len2 = WASM_VECTOR_LEN;
    var ptr3 = isLikeNone(random) ? 0 : passArray8ToWasm0(random, wasm.__wbindgen_malloc);
    var len3 = WASM_VECTOR_LEN;
    const ret = wasm.sealFile(ptr0, len0, epoch, ptr1, len1, ptr2, len2, ptr3, len3);
    if (ret[3]) {
        throw takeFromExternrefTable0(ret[2]);
    }
    var v5 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
    wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
    return v5;
}

/**
 * Seals a JSON key-history record to the leaf at `leaf_index` with its
 * encryption key.
 * @param {string} history
 * @param {string} scope
 * @param {number} leaf_index
 * @param {Uint8Array} leaf_public_key
 * @returns {Uint8Array}
 */
export function sealKeyHistoryToLeaf(history, scope, leaf_index, leaf_public_key) {
    const ptr0 = passStringToWasm0(history, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len0 = WASM_VECTOR_LEN;
    const ptr1 = passStringToWasm0(scope, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len1 = WASM_VECTOR_LEN;
    const ptr2 = passArray8ToWasm0(leaf_public_key, wasm.__wbindgen_malloc);
    const len2 = WASM_VECTOR_LEN;
    const ret = wasm.sealKeyHistoryToLeaf(ptr0, len0, ptr1, len1, leaf_index, ptr2, len2);
    if (ret[3]) {
        throw takeFromExternrefTable0(ret[2]);
    }
    var v4 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
    wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
    return v4;
}

/**
 * The sealed form `{"e2ee": "<base64url>"}` of an envelope, as JSON.
 * @param {Uint8Array} envelope
 * @returns {string}
 */
export function toSealedValue(envelope) {
    let deferred2_0;
    let deferred2_1;
    try {
        const ptr0 = passArray8ToWasm0(envelope, wasm.__wbindgen_malloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.toSealedValue(ptr0, len0);
        deferred2_0 = ret[0];
        deferred2_1 = ret[1];
        return getStringFromWasm0(ret[0], ret[1]);
    } finally {
        wasm.__wbindgen_free(deferred2_0, deferred2_1, 1);
    }
}

/**
 * Compares a logged drop public key of `epoch` with the one derived from
 * `d_e` (`drop_key_mismatch`).
 * @param {Uint8Array} d_e
 * @param {bigint} epoch
 * @param {Uint8Array} public_key
 */
export function verifyDropPublicKey(d_e, epoch, public_key) {
    const ptr0 = passArray8ToWasm0(d_e, wasm.__wbindgen_malloc);
    const len0 = WASM_VECTOR_LEN;
    const ptr1 = passArray8ToWasm0(public_key, wasm.__wbindgen_malloc);
    const len1 = WASM_VECTOR_LEN;
    const ret = wasm.verifyDropPublicKey(ptr0, len0, epoch, ptr1, len1);
    if (ret[1]) {
        throw takeFromExternrefTable0(ret[0]);
    }
}

/**
 * The base64url `new_member` KeyPackageRefs of a Welcome, in order.
 * @param {Uint8Array} bytes
 * @returns {string[]}
 */
export function welcomeRecipients(bytes) {
    const ptr0 = passArray8ToWasm0(bytes, wasm.__wbindgen_malloc);
    const len0 = WASM_VECTOR_LEN;
    const ret = wasm.welcomeRecipients(ptr0, len0);
    if (ret[3]) {
        throw takeFromExternrefTable0(ret[2]);
    }
    var v2 = getArrayJsValueFromWasm0(ret[0], ret[1]);
    wasm.__wbindgen_free(ret[0], ret[1] * 4, 4);
    return v2;
}
function __wbg_get_imports() {
    const import0 = {
        __proto__: null,
        __wbg_Error_30c8987f7c2ed4e2: function(arg0, arg1) {
            const ret = Error(getStringFromWasm0(arg0, arg1));
            return ret;
        },
        __wbg___wbindgen_is_function_1f9d30630b8b1d3d: function(arg0) {
            const ret = typeof(arg0) === 'function';
            return ret;
        },
        __wbg___wbindgen_is_object_3c45d4f2dde4e749: function(arg0) {
            const val = arg0;
            const ret = typeof(val) === 'object' && val !== null;
            return ret;
        },
        __wbg___wbindgen_is_string_90b56bc79aad6f6c: function(arg0) {
            const ret = typeof(arg0) === 'string';
            return ret;
        },
        __wbg___wbindgen_is_undefined_8865fb403f8fe9d8: function(arg0) {
            const ret = arg0 === undefined;
            return ret;
        },
        __wbg___wbindgen_string_get_0380ccaa2f57f0d9: function(arg0, arg1) {
            const obj = arg1;
            const ret = typeof(obj) === 'string' ? obj : undefined;
            var ptr1 = isLikeNone(ret) ? 0 : passStringToWasm0(ret, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
            var len1 = WASM_VECTOR_LEN;
            getDataViewMemory0().setInt32(arg0 + 4 * 1, len1, true);
            getDataViewMemory0().setInt32(arg0 + 4 * 0, ptr1, true);
        },
        __wbg___wbindgen_throw_41e9ee4f547fc59a: function(arg0, arg1) {
            throw new Error(getStringFromWasm0(arg0, arg1));
        },
        __wbg_call_187d372bd5fdd4aa: function() { return handleError(function (arg0, arg1, arg2) {
            const ret = arg0.call(arg1, arg2);
            return ret;
        }, arguments); },
        __wbg_crypto_38df2bab126b63dc: function(arg0) {
            const ret = arg0.crypto;
            return ret;
        },
        __wbg_getRandomValues_436a51d0629d84e1: function() { return handleError(function (arg0, arg1) {
            globalThis.crypto.getRandomValues(getArrayU8FromWasm0(arg0, arg1));
        }, arguments); },
        __wbg_getRandomValues_c44a50d8cfdaebeb: function() { return handleError(function (arg0, arg1) {
            arg0.getRandomValues(arg1);
        }, arguments); },
        __wbg_length_7f3c00c40364105e: function(arg0) {
            const ret = arg0.length;
            return ret;
        },
        __wbg_msCrypto_bd5a034af96bcba6: function(arg0) {
            const ret = arg0.msCrypto;
            return ret;
        },
        __wbg_new_with_length_3da0ad195f6f63ba: function(arg0) {
            const ret = new Uint8Array(arg0 >>> 0);
            return ret;
        },
        __wbg_node_84ea875411254db1: function(arg0) {
            const ret = arg0.node;
            return ret;
        },
        __wbg_now_aa4ccb83129e9e55: function() {
            const ret = Date.now();
            return ret;
        },
        __wbg_process_44c7a14e11e9f69e: function(arg0) {
            const ret = arg0.process;
            return ret;
        },
        __wbg_prototypesetcall_bc27214492979395: function(arg0, arg1, arg2) {
            Uint8Array.prototype.set.call(getArrayU8FromWasm0(arg0, arg1), arg2);
        },
        __wbg_randomFillSync_6c25eac9869eb53c: function() { return handleError(function (arg0, arg1) {
            arg0.randomFillSync(arg1);
        }, arguments); },
        __wbg_require_b4edbdcf3e2a1ef0: function() { return handleError(function () {
            const ret = module.require;
            return ret;
        }, arguments); },
        __wbg_static_accessor_GLOBAL_266715b9d96ba635: function() {
            const ret = typeof global === 'undefined' ? null : global;
            return isLikeNone(ret) ? 0 : addToExternrefTable0(ret);
        },
        __wbg_static_accessor_GLOBAL_THIS_10fb7dc1ae063179: function() {
            const ret = typeof globalThis === 'undefined' ? null : globalThis;
            return isLikeNone(ret) ? 0 : addToExternrefTable0(ret);
        },
        __wbg_static_accessor_SELF_0b583911f537483a: function() {
            const ret = typeof self === 'undefined' ? null : self;
            return isLikeNone(ret) ? 0 : addToExternrefTable0(ret);
        },
        __wbg_static_accessor_WINDOW_d7f903d1508cbdc4: function() {
            const ret = typeof window === 'undefined' ? null : window;
            return isLikeNone(ret) ? 0 : addToExternrefTable0(ret);
        },
        __wbg_subarray_002b94d5e13d1411: function(arg0, arg1, arg2) {
            const ret = arg0.subarray(arg1 >>> 0, arg2 >>> 0);
            return ret;
        },
        __wbg_versions_276b2795b1c6a219: function(arg0) {
            const ret = arg0.versions;
            return ret;
        },
        __wbindgen_generic_0000000000000001: function(arg0, arg1) {
            // Cast intrinsic for `Ref(Slice(U8)) -> NamedExternref("Uint8Array")`.
            const ret = getArrayU8FromWasm0(arg0, arg1);
            return ret;
        },
        __wbindgen_generic_0000000000000002: function(arg0, arg1) {
            // Cast intrinsic for `Ref(String) -> Externref`.
            const ret = getStringFromWasm0(arg0, arg1);
            return ret;
        },
        __wbindgen_init_externref_table: function() {
            const table = wasm.__wbindgen_externrefs;
            const offset = table.grow(4);
            table.set(0, undefined);
            table.set(offset + 0, undefined);
            table.set(offset + 1, null);
            table.set(offset + 2, true);
            table.set(offset + 3, false);
        },
    };
    return {
        __proto__: null,
        "./gino_e2ee_bg.js": import0,
    };
}

const DropKeyPairFinalization = (typeof FinalizationRegistry === 'undefined')
    ? { register: () => {}, unregister: () => {} }
    : new FinalizationRegistry(ptr => wasm.__wbg_dropkeypair_free(ptr, 1));
const FieldMapFinalization = (typeof FinalizationRegistry === 'undefined')
    ? { register: () => {}, unregister: () => {} }
    : new FinalizationRegistry(ptr => wasm.__wbg_fieldmap_free(ptr, 1));
const HistoryFinalization = (typeof FinalizationRegistry === 'undefined')
    ? { register: () => {}, unregister: () => {} }
    : new FinalizationRegistry(ptr => wasm.__wbg_history_free(ptr, 1));
const IdentityFinalization = (typeof FinalizationRegistry === 'undefined')
    ? { register: () => {}, unregister: () => {} }
    : new FinalizationRegistry(ptr => wasm.__wbg_identity_free(ptr, 1));
const KeyPackageStoreFinalization = (typeof FinalizationRegistry === 'undefined')
    ? { register: () => {}, unregister: () => {} }
    : new FinalizationRegistry(ptr => wasm.__wbg_keypackagestore_free(ptr, 1));
const ScopeGroupFinalization = (typeof FinalizationRegistry === 'undefined')
    ? { register: () => {}, unregister: () => {} }
    : new FinalizationRegistry(ptr => wasm.__wbg_scopegroup_free(ptr, 1));

function addToExternrefTable0(obj) {
    const idx = wasm.__externref_table_alloc();
    wasm.__wbindgen_externrefs.set(idx, obj);
    return idx;
}

function _assertClass(instance, klass) {
    if (!(instance instanceof klass)) {
        throw new Error(`expected instance of ${klass.name}`);
    }
}

function getArrayJsValueFromWasm0(ptr, len) {
    ptr = ptr >>> 0;
    const mem = getDataViewMemory0();
    const result = [];
    for (let i = ptr; i < ptr + 4 * len; i += 4) {
        result.push(wasm.__wbindgen_externrefs.get(mem.getUint32(i, true)));
    }
    wasm.__externref_drop_slice(ptr, len);
    return result;
}

function getArrayU8FromWasm0(ptr, len) {
    ptr = ptr >>> 0;
    return getUint8ArrayMemory0().subarray(ptr / 1, ptr / 1 + len);
}

let cachedDataViewMemory0 = null;
function getDataViewMemory0() {
    if (cachedDataViewMemory0 === null || cachedDataViewMemory0.buffer.detached === true || (cachedDataViewMemory0.buffer.detached === undefined && cachedDataViewMemory0.buffer !== wasm.memory.buffer)) {
        cachedDataViewMemory0 = new DataView(wasm.memory.buffer);
    }
    return cachedDataViewMemory0;
}

function getStringFromWasm0(ptr, len) {
    return decodeText(ptr >>> 0, len);
}

let cachedUint8ArrayMemory0 = null;
function getUint8ArrayMemory0() {
    if (cachedUint8ArrayMemory0 === null || cachedUint8ArrayMemory0.byteLength === 0) {
        cachedUint8ArrayMemory0 = new Uint8Array(wasm.memory.buffer);
    }
    return cachedUint8ArrayMemory0;
}

function handleError(f, args) {
    try {
        return f.apply(this, args);
    } catch (e) {
        const idx = addToExternrefTable0(e);
        wasm.__wbindgen_exn_store(idx);
    }
}

function isLikeNone(x) {
    return x === undefined || x === null;
}

function passArray8ToWasm0(arg, malloc) {
    const ptr = malloc(arg.length * 1, 1) >>> 0;
    getUint8ArrayMemory0().set(arg, ptr / 1);
    WASM_VECTOR_LEN = arg.length;
    return ptr;
}

function passArrayJsValueToWasm0(array, malloc) {
    const ptr = malloc(array.length * 4, 4) >>> 0;
    for (let i = 0; i < array.length; i++) {
        const add = addToExternrefTable0(array[i]);
        getDataViewMemory0().setUint32(ptr + 4 * i, add, true);
    }
    WASM_VECTOR_LEN = array.length;
    return ptr;
}

function passStringToWasm0(arg, malloc, realloc) {
    if (realloc === undefined) {
        const buf = cachedTextEncoder.encode(arg);
        const ptr = malloc(buf.length, 1) >>> 0;
        getUint8ArrayMemory0().subarray(ptr, ptr + buf.length).set(buf);
        WASM_VECTOR_LEN = buf.length;
        return ptr;
    }

    let len = arg.length;
    let ptr = malloc(len, 1) >>> 0;

    const mem = getUint8ArrayMemory0();

    let offset = 0;

    for (; offset < len; offset++) {
        const code = arg.charCodeAt(offset);
        if (code > 0x7F) break;
        mem[ptr + offset] = code;
    }
    if (offset !== len) {
        if (offset !== 0) {
            arg = arg.slice(offset);
        }
        ptr = realloc(ptr, len, len = offset + arg.length * 3, 1) >>> 0;
        const view = getUint8ArrayMemory0().subarray(ptr + offset, ptr + len);
        const ret = cachedTextEncoder.encodeInto(arg, view);

        offset += ret.written;
        ptr = realloc(ptr, len, offset, 1) >>> 0;
    }

    WASM_VECTOR_LEN = offset;
    return ptr;
}

function takeFromExternrefTable0(idx) {
    const value = wasm.__wbindgen_externrefs.get(idx);
    wasm.__externref_table_dealloc(idx);
    return value;
}

let cachedTextDecoder = new TextDecoder('utf-8', { ignoreBOM: true, fatal: true });
cachedTextDecoder.decode();
const MAX_SAFARI_DECODE_BYTES = 2146435072;
let numBytesDecoded = 0;
function decodeText(ptr, len) {
    numBytesDecoded += len;
    if (numBytesDecoded >= MAX_SAFARI_DECODE_BYTES) {
        cachedTextDecoder = new TextDecoder('utf-8', { ignoreBOM: true, fatal: true });
        cachedTextDecoder.decode();
        numBytesDecoded = len;
    }
    return cachedTextDecoder.decode(getUint8ArrayMemory0().subarray(ptr, ptr + len));
}

const cachedTextEncoder = new TextEncoder();

if (!('encodeInto' in cachedTextEncoder)) {
    cachedTextEncoder.encodeInto = function (arg, view) {
        const buf = cachedTextEncoder.encode(arg);
        view.set(buf);
        return {
            read: arg.length,
            written: buf.length
        };
    };
}

let WASM_VECTOR_LEN = 0;

let wasmModule, wasmInstance, wasm;
function __wbg_finalize_init(instance, module) {
    wasmInstance = instance;
    wasm = instance.exports;
    wasmModule = module;
    cachedDataViewMemory0 = null;
    cachedUint8ArrayMemory0 = null;
    wasm.__wbindgen_start();
    return wasm;
}

async function __wbg_load(module, imports) {
    if (typeof Response === 'function' && module instanceof Response) {
        if (!module.ok) {
            throw new Error(`failed to fetch Wasm: ${module.status} ${module.statusText} fetching '${module.url}'`);
        }

        if (typeof WebAssembly.instantiateStreaming === 'function') {
            try {
                return await WebAssembly.instantiateStreaming(module, imports);
            } catch (e) {
                const validResponse = expectedResponseType(module.type);

                if (validResponse && module.headers.get('Content-Type') !== 'application/wasm') {
                    console.warn("`WebAssembly.instantiateStreaming` failed because your server does not serve Wasm with `application/wasm` MIME type. Falling back to `WebAssembly.instantiate` which is slower. Original error:\n", e);

                } else { throw e; }
            }
        }

        const bytes = await module.arrayBuffer();
        return await WebAssembly.instantiate(bytes, imports);
    } else {
        const instance = await WebAssembly.instantiate(module, imports);

        if (instance instanceof WebAssembly.Instance) {
            return { instance, module };
        } else {
            return instance;
        }
    }

    function expectedResponseType(type) {
        switch (type) {
            case 'basic': case 'cors': case 'default': return true;
        }
        return false;
    }
}

function initSync(module) {
    if (wasm !== undefined) return wasm;


    if (module !== undefined) {
        if (Object.getPrototypeOf(module) === Object.prototype) {
            ({module} = module)
        } else {
            console.warn('using deprecated parameters for `initSync()`; pass a single object instead')
        }
    }

    const imports = __wbg_get_imports();
    if (!(module instanceof WebAssembly.Module)) {
        module = new WebAssembly.Module(module);
    }
    const instance = new WebAssembly.Instance(module, imports);
    return __wbg_finalize_init(instance, module);
}

async function __wbg_init(module_or_path) {
    if (wasm !== undefined) return wasm;


    if (module_or_path !== undefined) {
        if (Object.getPrototypeOf(module_or_path) === Object.prototype) {
            ({module_or_path} = module_or_path)
        } else {
            console.warn('using deprecated parameters for the initialization function; pass a single object instead')
        }
    }

    if (module_or_path === undefined) {
        module_or_path = new URL('gino_e2ee_bg.wasm', import.meta.url);
    }
    const imports = __wbg_get_imports();

    if (typeof module_or_path === 'string' || (typeof Request === 'function' && module_or_path instanceof Request) || (typeof URL === 'function' && module_or_path instanceof URL)) {
        module_or_path = fetch(module_or_path);
    }

    const { instance, module } = await __wbg_load(await module_or_path, imports);

    return __wbg_finalize_init(instance, module);
}

export { initSync, __wbg_init as default };
