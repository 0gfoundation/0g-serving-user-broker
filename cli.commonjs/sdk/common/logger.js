"use strict";
/**
 * Simple logger utility that supports debug mode
 * Set DEBUG=true or NODE_ENV=development to enable debug logs
 */
Object.defineProperty(exports, "__esModule", { value: true });
exports.logger = exports.Logger = void 0;
class Logger {
    static instance;
    debugMode;
    constructor() {
        // Check multiple environment variables for debug mode
        this.debugMode =
            process.env.DEBUG === 'true' ||
                process.env.DEBUG === '1' ||
                process.env.NODE_ENV === 'development' ||
                process.env.ZG_DEBUG === 'true' ||
                process.env.ZG_DEBUG === '1';
    }
    static getInstance() {
        if (!Logger.instance) {
            Logger.instance = new Logger();
        }
        return Logger.instance;
    }
    /**
     * Enable or disable debug mode programmatically
     */
    setDebugMode(enabled) {
        this.debugMode = enabled;
    }
    /**
     * Check if debug mode is enabled
     */
    isDebugMode() {
        return this.debugMode;
    }
    /**
     * Log debug messages (only in debug mode)
     */
    debug(message, ...args) {
        if (this.debugMode) {
            console.log(`[DEBUG] ${new Date().toISOString()} - ${message}`, ...args);
        }
    }
    /**
     * Log info messages (always)
     */
    info(message, ...args) {
        console.log(`[INFO] ${new Date().toISOString()} - ${message}`, ...args);
    }
    /**
     * Log warning messages (always)
     */
    warn(message, ...args) {
        console.warn(`[WARN] ${new Date().toISOString()} - ${message}`, ...args);
    }
    /**
     * Log error messages (always)
     */
    error(message, ...args) {
        console.error(`[ERROR] ${new Date().toISOString()} - ${message}`, ...args);
    }
}
exports.Logger = Logger;
// Export singleton instance
exports.logger = Logger.getInstance();
//# sourceMappingURL=logger.js.map