import { CacheKeyHelpers } from './cache-keys'

export class Metadata {
    private nodeStorage: { [key: string]: string } = {}
    private initialized = false
    private isBrowser =
        typeof window !== 'undefined' &&
        typeof window.localStorage !== 'undefined'
    private storagePrefix = '0g_metadata_'

    constructor() {}

    async initialize() {
        if (this.initialized) {
            return
        }
        if (!this.isBrowser) {
            this.nodeStorage = {}
        }
        this.initialized = true
    }

    private async setItem(key: string, value: string) {
        await this.initialize()
        const fullKey = this.storagePrefix + key
        if (this.isBrowser) {
            try {
                console.log('Setting localStorage item:', fullKey, value)
                window.localStorage.setItem(fullKey, value)
            } catch (e) {
                console.warn('Failed to set localStorage item:', e)
                this.nodeStorage[key] = value
            }
        } else {
            this.nodeStorage[key] = value
        }
    }

    private async getItem(key: string): Promise<string | null> {
        await this.initialize()
        const fullKey = this.storagePrefix + key
        if (this.isBrowser) {
            try {
                return window.localStorage.getItem(fullKey)
            } catch (e) {
                console.warn('Failed to get localStorage item:', e)
                return this.nodeStorage[key] ?? null
            }
        } else {
            return this.nodeStorage[key] ?? null
        }
    }

    // storeSettleSignerPrivateKey removed - no longer needed

    async storeSigningKey(key: string, value: string) {
        await this.setItem(CacheKeyHelpers.getSigningKeyKey(key), value)
    }

    // getSettleSignerPrivateKey removed - no longer needed

    async getSigningKey(key: string): Promise<string | null> {
        const value = await this.getItem(CacheKeyHelpers.getSigningKeyKey(key))
        return value ?? null
    }
}
