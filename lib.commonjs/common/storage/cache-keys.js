"use strict";
/**
 * Centralized cache key management
 * This file contains all cache key constants and helper functions
 * to ensure no key conflicts across different storage objects
 */
Object.defineProperty(exports, "__esModule", { value: true });
exports.CacheKeyHelpers = exports.METADATA_KEY_SUFFIXES = exports.CACHE_KEY_PREFIXES = exports.CACHE_KEYS = void 0;
// Fixed cache keys
exports.CACHE_KEYS = {
    // Nonce related
    NONCE: 'nonce',
    NONCE_LOCK: 'nonce_lock',
    // First round marker
    FIRST_ROUND: 'firstRound',
};
// Cache key prefix patterns
exports.CACHE_KEY_PREFIXES = {
    // Service cache
    SERVICE: 'service_',
    // User acknowledgment
    USER_ACK: '_ack',
    // Cached fee
    CACHED_FEE: '_cachedFee',
    // Session token cache
    SESSION_TOKEN: 'session_',
};
// Metadata key suffixes
exports.METADATA_KEY_SUFFIXES = {
    // SETTLE_SIGNER_PRIVATE_KEY removed - no longer needed
    SIGNING_KEY: '_signingKey',
};
// Helper functions to generate dynamic cache keys
exports.CacheKeyHelpers = {
    // Service cache key
    getServiceKey(providerAddress) {
        return `${exports.CACHE_KEY_PREFIXES.SERVICE}${providerAddress}`;
    },
    // User acknowledgment key
    getUserAckKey(userAddress, providerAddress) {
        return `${userAddress}_${providerAddress}${exports.CACHE_KEY_PREFIXES.USER_ACK}`;
    },
    // Cached fee key
    getCachedFeeKey(provider) {
        return `${provider}${exports.CACHE_KEY_PREFIXES.CACHED_FEE}`;
    },
    // getSettleSignerPrivateKeyKey removed - no longer needed
    // Metadata: signing key
    getSigningKeyKey(key) {
        return `${key}${exports.METADATA_KEY_SUFFIXES.SIGNING_KEY}`;
    },
    // Dynamic content key (for inference server)
    getContentKey(id) {
        return id; // Keep as is since it's already unique
    },
    // Session token key
    getSessionTokenKey(providerAddress) {
        return `${exports.CACHE_KEY_PREFIXES.SESSION_TOKEN}${providerAddress}`;
    },
};
//# sourceMappingURL=cache-keys.js.map