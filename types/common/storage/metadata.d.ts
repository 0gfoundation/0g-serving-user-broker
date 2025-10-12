export declare class Metadata {
    private nodeStorage;
    private initialized;
    private isBrowser;
    private storagePrefix;
    constructor();
    initialize(): Promise<void>;
    private setItem;
    private getItem;
    storeSigningKey(key: string, value: string): Promise<void>;
    getSigningKey(key: string): Promise<string | null>;
}
//# sourceMappingURL=metadata.d.ts.map