/**
 * Type definitions for the 0G Broker system
 */

export interface ServiceInfo {
  provider: string;
  model: string;
  name?: string;
  verifiability?: string;
  url?: string;
  inputPrice?: bigint;
  outputPrice?: bigint;
}

export interface ServiceMetadata {
  endpoint?: string;
  model: string;
  verifiability: string;
  inputPrice?: bigint;
  outputPrice?: bigint;
}

export interface LedgerInfo {
  ledgerInfo: [bigint, bigint];
  infers: Array<[string, bigint, bigint]>;
  fines: Array<[string, bigint, bigint]>;
}

export interface Provider {
  address: string;
  model: string;
  name: string;
  verifiability: string;
  url?: string;
  endpoint?: string;
  inputPrice?: number;
  outputPrice?: number;
  inputPriceNeuron?: bigint;
  outputPriceNeuron?: bigint;
}

/**
 * Message interface with strict typing
 */
export interface Message {
  role: "system" | "user" | "assistant";
  content: string;
  timestamp?: number;
  chatId?: string;
  isVerified?: boolean | null;
  isVerifying?: boolean;
}

/**
 * Chat session state interface
 */
export interface ChatState {
  messages: Message[];
  inputMessage: string;
  isLoading: boolean;
  isStreaming: boolean;
  error: string | null;
  selectedProvider: Provider | null;
  showHistorySidebar: boolean;
  isTopping: boolean;
  showTutorial: boolean;
}

/**
 * Chat action types for useReducer
 */
export type ChatAction = 
  | { type: 'SET_MESSAGES'; payload: Message[] }
  | { type: 'ADD_MESSAGE'; payload: Message }
  | { type: 'SET_INPUT'; payload: string }
  | { type: 'SET_LOADING'; payload: boolean }
  | { type: 'SET_STREAMING'; payload: boolean }
  | { type: 'SET_ERROR'; payload: string | null }
  | { type: 'SET_PROVIDER'; payload: Provider | null }
  | { type: 'TOGGLE_HISTORY_SIDEBAR' }
  | { type: 'SET_TOPPING'; payload: boolean }
  | { type: 'SET_TUTORIAL'; payload: boolean }
  | { type: 'RESET_CHAT' };