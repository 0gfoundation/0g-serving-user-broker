/**
 * Centralized cache key management
 * This file contains all cache key constants and helper functions
 * to ensure no key conflicts across different storage objects
 */

// Fixed cache keys
export const CACHE_KEYS = {
    // Nonce related
    NONCE: 'nonce',
    NONCE_LOCK: 'nonce_lock',

    // First round marker
    FIRST_ROUND: 'firstRound',
} as const

// Cache key prefix patterns
export const CACHE_KEY_PREFIXES = {
    // Service cache
    SERVICE: 'service_',

    // User acknowledgment
    USER_ACK: '_ack',

    // Cached fee
    CACHED_FEE: '_cachedFee',

    // Session token cache
    SESSION_TOKEN: 'session_',
} as const

// Metadata key suffixes
export const METADATA_KEY_SUFFIXES = {
    // SETTLE_SIGNER_PRIVATE_KEY removed - no longer needed
    SIGNING_KEY: '_signingKey',
} as const

// Helper functions to generate dynamic cache keys
export const CacheKeyHelpers = {
    // Service cache key
    getServiceKey(providerAddress: string): string {
        return `${CACHE_KEY_PREFIXES.SERVICE}${providerAddress}`
    },

    // User acknowledgment key
    getUserAckKey(userAddress: string, providerAddress: string): string {
        return `${userAddress}_${providerAddress}${CACHE_KEY_PREFIXES.USER_ACK}`
    },

    // Cached fee key
    getCachedFeeKey(provider: string): string {
        return `${provider}${CACHE_KEY_PREFIXES.CACHED_FEE}`
    },

    // getSettleSignerPrivateKeyKey removed - no longer needed

    // Metadata: signing key
    getSigningKeyKey(key: string): string {
        return `${key}${METADATA_KEY_SUFFIXES.SIGNING_KEY}`
    },

    // Dynamic content key (for inference server)
    getContentKey(id: string): string {
        return id // Keep as is since it's already unique
    },

    // Session token key
    getSessionTokenKey(userAddress: string, providerAddress: string): string {
        return `${CACHE_KEY_PREFIXES.SESSION_TOKEN}${userAddress}_${providerAddress}`
    },
}

// Type definitions for better type safety
export type CacheKey = (typeof CACHE_KEYS)[keyof typeof CACHE_KEYS]
export type CacheKeyPrefix =
    (typeof CACHE_KEY_PREFIXES)[keyof typeof CACHE_KEY_PREFIXES]
export type MetadataKeySuffix =
    (typeof METADATA_KEY_SUFFIXES)[keyof typeof METADATA_KEY_SUFFIXES]
