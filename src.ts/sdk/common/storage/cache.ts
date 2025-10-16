import type { ServiceStructOutput as InferenceServiceStructOutput } from '../../inference/contract'

export enum CacheValueTypeEnum {
    Service = 'service',
    BigInt = 'bigint',
    Other = 'other',
    Session = 'session',
}

export type CacheValueType =
    | CacheValueTypeEnum.Service
    | CacheValueTypeEnum.BigInt
    | CacheValueTypeEnum.Other
    | CacheValueTypeEnum.Session

export class Cache {
    private nodeStorage: { [key: string]: string } = {}
    private initialized = false
    private isBrowser =
        typeof window !== 'undefined' &&
        typeof window.localStorage !== 'undefined'
    private storagePrefix = '0g_cache_'

    constructor() {}

    public setLock(
        key: string,
        value: string,
        ttl: number,
        type: CacheValueType
    ): boolean {
        this.initialize()
        if (this.getStorageItem(key)) {
            return false
        }
        this.setItem(key, value, ttl, type)
        return true
    }

    public removeLock(key: string): void {
        this.initialize()
        this.removeStorageItem(key)
    }

    public setItem(key: string, value: any, ttl: number, type: CacheValueType) {
        this.initialize()
        const now = new Date()
        const item = {
            type,
            value: Cache.encodeValue(value),
            expiry: now.getTime() + ttl,
        }
        this.setStorageItem(key, JSON.stringify(item))
    }

    public getItem(key: string): any | null {
        this.initialize()
        const itemStr = this.getStorageItem(key)
        if (!itemStr) {
            return null
        }
        const item = JSON.parse(itemStr)
        const now = new Date()
        if (now.getTime() > item.expiry) {
            this.removeStorageItem(key)
            return null
        }
        return Cache.decodeValue(item.value, item.type)
    }

    private initialize() {
        if (this.initialized) {
            return
        }
        if (!this.isBrowser) {
            this.nodeStorage = {}
        } else {
            this.cleanupExpiredItems()
        }
        this.initialized = true
    }

    private setStorageItem(key: string, value: string): void {
        const fullKey = this.storagePrefix + key
        if (this.isBrowser) {
            try {
                window.localStorage.setItem(fullKey, value)
            } catch (e) {
                console.warn('Failed to set localStorage item:', e)
                this.nodeStorage[key] = value
            }
        } else {
            this.nodeStorage[key] = value
        }
    }

    private getStorageItem(key: string): string | null {
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

    private removeStorageItem(key: string): void {
        const fullKey = this.storagePrefix + key
        if (this.isBrowser) {
            try {
                window.localStorage.removeItem(fullKey)
            } catch (e) {
                console.warn('Failed to remove localStorage item:', e)
                delete this.nodeStorage[key]
            }
        } else {
            delete this.nodeStorage[key]
        }
    }

    private cleanupExpiredItems(): void {
        if (!this.isBrowser) return

        try {
            const keysToRemove: string[] = []
            for (let i = 0; i < window.localStorage.length; i++) {
                const key = window.localStorage.key(i)
                if (key && key.startsWith(this.storagePrefix)) {
                    const itemStr = window.localStorage.getItem(key)
                    if (itemStr) {
                        try {
                            const item = JSON.parse(itemStr)
                            if (new Date().getTime() > item.expiry) {
                                keysToRemove.push(key)
                            }
                        } catch (e) {
                            keysToRemove.push(key)
                        }
                    }
                }
            }
            keysToRemove.forEach((key) => window.localStorage.removeItem(key))
        } catch (e) {
            console.warn('Failed to cleanup expired items:', e)
        }
    }

    static encodeValue(value: any): string {
        return JSON.stringify(value, (_, val) =>
            typeof val === 'bigint' ? `${val.toString()}n` : val
        )
    }

    static decodeValue(encodedValue: string, type: CacheValueType): any {
        let ret = JSON.parse(encodedValue, (_, val) => {
            if (typeof val === 'string' && /^\d+n$/.test(val)) {
                return BigInt(val.slice(0, -1))
            }
            return val
        })

        if (type === CacheValueTypeEnum.Service) {
            return Cache.createServiceStructOutput(ret)
        }

        return ret
    }

    static createServiceStructOutput(
        fields: [
            string,
            string,
            string,
            bigint,
            bigint,
            bigint,
            string,
            string,
            string
        ]
    ): InferenceServiceStructOutput {
        const tuple: [
            string,
            string,
            string,
            bigint,
            bigint,
            bigint,
            string,
            string,
            string
        ] = fields

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
        }

        return Object.assign(tuple, object)
    }
}
