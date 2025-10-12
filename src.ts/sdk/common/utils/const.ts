// Define which errors to retry on
export const RETRY_ERROR_SUBSTRINGS = [
    'transaction underpriced',
    'replacement transaction underpriced',
    'fee too low',
    'mempool',
]
