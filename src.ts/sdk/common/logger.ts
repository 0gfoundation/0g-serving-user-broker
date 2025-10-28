/**
 * Simple logger utility that supports debug mode
 * Set DEBUG=true or NODE_ENV=development to enable debug logs
 */

export class Logger {
    private static instance: Logger
    private debugMode: boolean

    private constructor() {
        // Check multiple environment variables for debug mode
        this.debugMode = 
            process.env.DEBUG === 'true' || 
            process.env.DEBUG === '1' ||
            process.env.NODE_ENV === 'development' ||
            process.env.ZG_DEBUG === 'true' ||
            process.env.ZG_DEBUG === '1'
    }

    public static getInstance(): Logger {
        if (!Logger.instance) {
            Logger.instance = new Logger()
        }
        return Logger.instance
    }

    /**
     * Enable or disable debug mode programmatically
     */
    public setDebugMode(enabled: boolean): void {
        this.debugMode = enabled
    }

    /**
     * Check if debug mode is enabled
     */
    public isDebugMode(): boolean {
        return this.debugMode
    }

    /**
     * Log debug messages (only in debug mode)
     */
    public debug(message: string, ...args: any[]): void {
        if (this.debugMode) {
            console.log(`[DEBUG] ${new Date().toISOString()} - ${message}`, ...args)
        }
    }

    /**
     * Log info messages (always)
     */
    public info(message: string, ...args: any[]): void {
        console.log(`[INFO] ${new Date().toISOString()} - ${message}`, ...args)
    }

    /**
     * Log warning messages (always)
     */
    public warn(message: string, ...args: any[]): void {
        console.warn(`[WARN] ${new Date().toISOString()} - ${message}`, ...args)
    }

    /**
     * Log error messages (always)
     */
    public error(message: string, ...args: any[]): void {
        console.error(`[ERROR] ${new Date().toISOString()} - ${message}`, ...args)
    }
}

// Export singleton instance
export const logger = Logger.getInstance()