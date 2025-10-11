// Chat component configuration constants

export const CHAT_CONFIG = {
  // Scroll behavior
  SCROLL_THRESHOLD: 100, // Distance from bottom to consider "near bottom"
  SCROLL_DELAY: 100, // Delay before auto-scrolling in ms
  
  // Message highlighting
  HIGHLIGHT_DURATION: 2000, // How long to highlight a message in ms
  HIGHLIGHT_REMOVAL_DELAY: 100, // Delay before removing highlight in ms
  HIGHLIGHT_SEARCH_LENGTH: 50, // Number of characters to match when searching
  
  // UI dimensions
  CHAT_HEIGHT: 'calc(100vh - 175px)', // Main chat container height
  ICON_SIZE: {
    small: 'w-4 h-4',
    medium: 'w-5 h-5',
    large: 'w-8 h-8',
    xlarge: 'w-16 h-16',
  },
  
  // Color schemes
  COLORS: {
    primary: 'purple',
    error: 'red',
    warning: 'yellow',
    success: 'green',
    neutral: 'gray',
  },
  
  // Z-index values
  Z_INDEX: {
    tooltip: 'z-20',
    overlay: 'z-40', 
    modal: 'z-50',
  },
} as const;

// CSS class helpers
export const CHAT_STYLES = {
  // Common button styles
  iconButton: 'text-gray-600 hover:text-purple-600 transition-colors p-1.5 border border-gray-300 rounded-lg hover:bg-purple-50 cursor-pointer',
  
  // Common container styles
  card: 'bg-white rounded-xl border border-gray-200',
  errorCard: 'bg-red-50 border border-red-200 rounded-xl p-4',
  warningCard: 'bg-purple-50 border border-purple-200 rounded-xl p-4',
  
  // Common text styles
  heading: 'text-lg font-semibold text-gray-900',
  subheading: 'text-sm font-medium',
  caption: 'text-xs text-gray-500',
  
  // Tooltip styles
  tooltip: 'absolute bottom-full left-1/2 transform -translate-x-1/2 mb-2 px-3 py-2 bg-gray-900 text-white text-xs rounded-lg opacity-0 group-hover:opacity-100 transition-opacity duration-200 pointer-events-none whitespace-nowrap',
  tooltipArrow: 'absolute top-full left-1/2 transform -translate-x-1/2 -mt-1',
} as const;