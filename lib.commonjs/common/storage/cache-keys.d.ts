/**
 * Centralized cache key management
 * This file contains all cache key constants and helper functions
 * to ensure no key conflicts across different storage objects
 */
export declare const CACHE_KEYS: {
    readonly NONCE: "nonce";
    readonly NONCE_LOCK: "nonce_lock";
    readonly FIRST_ROUND: "firstRound";
};
export declare const CACHE_KEY_PREFIXES: {
    readonly SERVICE: "service_";
    readonly USER_ACK: "_ack";
    readonly CACHED_FEE: "_cachedFee";
    readonly SESSION_TOKEN: "session_";
};
export declare const METADATA_KEY_SUFFIXES: {
    readonly SIGNING_KEY: "_signingKey";
};
export declare const CacheKeyHelpers: {
    getServiceKey(providerAddress: string): string;
    getUserAckKey(userAddress: string, providerAddress: string): string;
    getCachedFeeKey(provider: string): string;
    getSigningKeyKey(key: string): string;
    getContentKey(id: string): string;
    getSessionTokenKey(userAddress: string, providerAddress: string): string;
};
export type CacheKey = (typeof CACHE_KEYS)[keyof typeof CACHE_KEYS];
export type CacheKeyPrefix = (typeof CACHE_KEY_PREFIXES)[keyof typeof CACHE_KEY_PREFIXES];
export type MetadataKeySuffix = (typeof METADATA_KEY_SUFFIXES)[keyof typeof METADATA_KEY_SUFFIXES];
//# sourceMappingURL=cache-keys.d.ts.map