/**
 * Simple logger utility that supports debug mode
 * Set DEBUG=true or NODE_ENV=development to enable debug logs
 */
export declare class Logger {
    private static instance;
    private debugMode;
    private constructor();
    static getInstance(): Logger;
    /**
     * Enable or disable debug mode programmatically
     */
    setDebugMode(enabled: boolean): void;
    /**
     * Check if debug mode is enabled
     */
    isDebugMode(): boolean;
    /**
     * Log debug messages (only in debug mode)
     */
    debug(message: string, ...args: any[]): void;
    /**
     * Log info messages (always)
     */
    info(message: string, ...args: any[]): void;
    /**
     * Log warning messages (always)
     */
    warn(message: string, ...args: any[]): void;
    /**
     * Log error messages (always)
     */
    error(message: string, ...args: any[]): void;
}
export declare const logger: Logger;
//# sourceMappingURL=logger.d.ts.map