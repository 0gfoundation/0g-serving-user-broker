"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.Metadata = void 0;
const cache_keys_1 = require("./cache-keys");
class Metadata {
    nodeStorage = {};
    initialized = false;
    isBrowser = typeof window !== 'undefined' &&
        typeof window.localStorage !== 'undefined';
    storagePrefix = '0g_metadata_';
    constructor() { }
    async initialize() {
        if (this.initialized) {
            return;
        }
        if (!this.isBrowser) {
            this.nodeStorage = {};
        }
        this.initialized = true;
    }
    async setItem(key, value) {
        await this.initialize();
        const fullKey = this.storagePrefix + key;
        if (this.isBrowser) {
            try {
                console.log('Setting localStorage item:', fullKey, value);
                window.localStorage.setItem(fullKey, value);
            }
            catch (e) {
                console.warn('Failed to set localStorage item:', e);
                this.nodeStorage[key] = value;
            }
        }
        else {
            this.nodeStorage[key] = value;
        }
    }
    async getItem(key) {
        await this.initialize();
        const fullKey = this.storagePrefix + key;
        if (this.isBrowser) {
            try {
                return window.localStorage.getItem(fullKey);
            }
            catch (e) {
                console.warn('Failed to get localStorage item:', e);
                return this.nodeStorage[key] ?? null;
            }
        }
        else {
            return this.nodeStorage[key] ?? null;
        }
    }
    // storeSettleSignerPrivateKey removed - no longer needed
    async storeSigningKey(key, value) {
        await this.setItem(cache_keys_1.CacheKeyHelpers.getSigningKeyKey(key), value);
    }
    // getSettleSignerPrivateKey removed - no longer needed
    async getSigningKey(key) {
        const value = await this.getItem(cache_keys_1.CacheKeyHelpers.getSigningKeyKey(key));
        return value ?? null;
    }
}
exports.Metadata = Metadata;
//# sourceMappingURL=metadata.js.map