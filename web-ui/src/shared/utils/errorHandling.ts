import { APP_CONSTANTS } from '../constants/app';

/**
 * Custom application error class
 */
export class AppError extends Error {
  constructor(
    message: string,
    public userMessage: string,
    public code: string,
    public originalError?: Error
  ) {
    super(message);
    this.name = 'AppError';
  }
}

/**
 * Error handler utility
 */
export const errorHandler = {
  /**
   * Handle and normalize errors
   */
  handle: (error: unknown, context: string): AppError => {
    if (error instanceof AppError) {
      return error;
    }
    
    if (error instanceof Error) {
      // Check for specific error types
      if (error.message.includes('User rejected')) {
        return new AppError(
          `${context}: User rejected transaction`,
          'Transaction was cancelled by user.',
          'USER_REJECTED',
          error
        );
      }
      
      if (error.message.includes('insufficient funds')) {
        return new AppError(
          `${context}: Insufficient funds`,
          'Insufficient funds for this transaction.',
          'INSUFFICIENT_FUNDS',
          error
        );
      }
      
      return new AppError(
        `${context}: ${error.message}`,
        'An unexpected error occurred. Please try again.',
        'UNKNOWN_ERROR',
        error
      );
    }
    
    return new AppError(
      `${context}: Unknown error`,
      'An unexpected error occurred. Please try again.',
      'UNKNOWN_ERROR'
    );
  },

  /**
   * Sanitize error message for display (prevent XSS)
   */
  sanitizeErrorMessage: (error: string): string => {
    // Remove potentially dangerous characters
    const sanitized = error.replace(/[<>&"']/g, (match) => {
      const escapeMap: Record<string, string> = {
        '<': '&lt;',
        '>': '&gt;',
        '&': '&amp;',
        '"': '&quot;',
        "'": '&#x27;'
      };
      return escapeMap[match];
    });
    
    // Limit length to prevent DoS
    const maxLength = APP_CONSTANTS.LIMITS.MAX_ERROR_DISPLAY_LENGTH;
    return sanitized.length > maxLength 
      ? sanitized.substring(0, maxLength) + '...' 
      : sanitized;
  }
};

/**
 * Async operation wrapper with error handling
 */
export const withErrorHandling = async <T>(
  operation: () => Promise<T>,
  context: string
): Promise<{ data?: T; error?: AppError }> => {
  try {
    const data = await operation();
    return { data };
  } catch (error) {
    return { error: errorHandler.handle(error, context) };
  }
};