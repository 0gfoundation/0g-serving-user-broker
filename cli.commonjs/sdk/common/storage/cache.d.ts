import type { ServiceStructOutput as InferenceServiceStructOutput } from '../../inference/contract';
export declare enum CacheValueTypeEnum {
    Service = "service",
    BigInt = "bigint",
    Other = "other",
    Session = "session"
}
export type CacheValueType = CacheValueTypeEnum.Service | CacheValueTypeEnum.BigInt | CacheValueTypeEnum.Other | CacheValueTypeEnum.Session;
export declare class Cache {
    private nodeStorage;
    private initialized;
    private isBrowser;
    private storagePrefix;
    constructor();
    setLock(key: string, value: string, ttl: number, type: CacheValueType): boolean;
    removeLock(key: string): void;
    setItem(key: string, value: any, ttl: number, type: CacheValueType): void;
    getItem(key: string): any | null;
    private initialize;
    private setStorageItem;
    private getStorageItem;
    private removeStorageItem;
    private cleanupExpiredItems;
    static encodeValue(value: any): string;
    static decodeValue(encodedValue: string, type: CacheValueType): any;
    static createServiceStructOutput(fields: [
        string,
        string,
        string,
        bigint,
        bigint,
        bigint,
        string,
        string,
        string
    ]): InferenceServiceStructOutput;
}
//# sourceMappingURL=cache.d.ts.map