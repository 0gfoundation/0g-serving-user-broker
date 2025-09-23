export interface DirectEndpointConfig {
    endpoint: string;
    apiKey?: string;
    model?: string;
    priority?: number;
}
export interface PriorityConfig {
    providers?: Record<string, number>;
    defaultProviderPriority?: number;
    defaultEndpointPriority?: number;
}
export interface RouterServerOptions {
    providers: string[];
    directEndpoints?: Record<string, DirectEndpointConfig>;
    priorityConfig?: PriorityConfig;
    key?: string;
    rpc?: string;
    ledgerCa?: string;
    inferenceCa?: string;
    gasPrice?: string | number;
    port?: string | number;
    host?: string;
    cacheDuration?: string | number;
    requestTimeout?: string | number;
}
export declare function runRouterServer(options: RouterServerOptions): Promise<void>;
//# sourceMappingURL=router-server.d.ts.map