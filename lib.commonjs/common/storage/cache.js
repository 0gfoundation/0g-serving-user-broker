"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.Cache = exports.CacheValueTypeEnum = void 0;
var CacheValueTypeEnum;
(function (CacheValueTypeEnum) {
    CacheValueTypeEnum["Service"] = "service";
    CacheValueTypeEnum["BigInt"] = "bigint";
    CacheValueTypeEnum["Other"] = "other";
    CacheValueTypeEnum["Session"] = "session";
})(CacheValueTypeEnum || (exports.CacheValueTypeEnum = CacheValueTypeEnum = {}));
class Cache {
    nodeStorage = {};
    initialized = false;
    isBrowser = typeof window !== 'undefined' &&
        typeof window.localStorage !== 'undefined';
    storagePrefix = '0g_cache_';
    constructor() { }
    setLock(key, value, ttl, type) {
        this.initialize();
        if (this.getStorageItem(key)) {
            return false;
        }
        this.setItem(key, value, ttl, type);
        return true;
    }
    removeLock(key) {
        this.initialize();
        this.removeStorageItem(key);
    }
    setItem(key, value, ttl, type) {
        this.initialize();
        const now = new Date();
        const item = {
            type,
            value: Cache.encodeValue(value),
            expiry: now.getTime() + ttl,
        };
        this.setStorageItem(key, JSON.stringify(item));
    }
    getItem(key) {
        this.initialize();
        const itemStr = this.getStorageItem(key);
        if (!itemStr) {
            return null;
        }
        const item = JSON.parse(itemStr);
        const now = new Date();
        if (now.getTime() > item.expiry) {
            this.removeStorageItem(key);
            return null;
        }
        return Cache.decodeValue(item.value, item.type);
    }
    initialize() {
        if (this.initialized) {
            return;
        }
        if (!this.isBrowser) {
            this.nodeStorage = {};
        }
        else {
            this.cleanupExpiredItems();
        }
        this.initialized = true;
    }
    setStorageItem(key, value) {
        const fullKey = this.storagePrefix + key;
        if (this.isBrowser) {
            try {
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
    getStorageItem(key) {
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
    removeStorageItem(key) {
        const fullKey = this.storagePrefix + key;
        if (this.isBrowser) {
            try {
                window.localStorage.removeItem(fullKey);
            }
            catch (e) {
                console.warn('Failed to remove localStorage item:', e);
                delete this.nodeStorage[key];
            }
        }
        else {
            delete this.nodeStorage[key];
        }
    }
    cleanupExpiredItems() {
        if (!this.isBrowser)
            return;
        try {
            const keysToRemove = [];
            for (let i = 0; i < window.localStorage.length; i++) {
                const key = window.localStorage.key(i);
                if (key && key.startsWith(this.storagePrefix)) {
                    const itemStr = window.localStorage.getItem(key);
                    if (itemStr) {
                        try {
                            const item = JSON.parse(itemStr);
                            if (new Date().getTime() > item.expiry) {
                                keysToRemove.push(key);
                            }
                        }
                        catch (e) {
                            keysToRemove.push(key);
                        }
                    }
                }
            }
            keysToRemove.forEach((key) => window.localStorage.removeItem(key));
        }
        catch (e) {
            console.warn('Failed to cleanup expired items:', e);
        }
    }
    static encodeValue(value) {
        return JSON.stringify(value, (_, val) => typeof val === 'bigint' ? `${val.toString()}n` : val);
    }
    static decodeValue(encodedValue, type) {
        let ret = JSON.parse(encodedValue, (_, val) => {
            if (typeof val === 'string' && /^\d+n$/.test(val)) {
                return BigInt(val.slice(0, -1));
            }
            return val;
        });
        if (type === CacheValueTypeEnum.Service) {
            return Cache.createServiceStructOutput(ret);
        }
        return ret;
    }
    static createServiceStructOutput(fields) {
        const tuple = fields;
        const object = {
            provider: fields[0],
            serviceType: fields[1],
            url: fields[2],
            inputPrice: fields[3],
            outputPrice: fields[4],
            updatedAt: fields[5],
            model: fields[6],
            verifiability: fields[7],
            additionalInfo: fields[8],
        };
        return Object.assign(tuple, object);
    }
}
exports.Cache = Cache;
//# sourceMappingURL=cache.js.map