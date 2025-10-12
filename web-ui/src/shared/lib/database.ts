import Dexie, { type EntityTable } from 'dexie';
import { APP_CONSTANTS } from '../constants/app';

export interface ChatMessage {
  id?: number;
  session_id?: string;
  role: 'system' | 'user' | 'assistant';
  content: string;
  timestamp: number;
  chat_id?: string;
  is_verified?: boolean | null;
  is_verifying?: boolean;
  provider_address?: string;
}

export interface ChatSession {
  id?: number;
  session_id: string;
  provider_address: string;
  wallet_address: string;
  created_at: number;
  updated_at: number;
  title?: string;
}

class ChatDatabase extends Dexie {
  sessions!: EntityTable<ChatSession, 'id'>;
  messages!: EntityTable<ChatMessage, 'id'>;

  constructor() {
    super(APP_CONSTANTS.DATABASE.DB_NAME);
    
    this.version(1).stores({
      sessions: '++id, session_id, provider_address, wallet_address, created_at, updated_at',
      messages: '++id, session_id, role, timestamp, provider_address'
    });
  }
}

class DatabaseManager {
  private db: ChatDatabase | null = null;
  private initPromise: Promise<void> | null = null;

  // Get database instance, initialize if needed
  private async getDB(): Promise<ChatDatabase> {
    if (this.db) {
      return this.db;
    }
    
    // Skip on server side
    if (typeof window === 'undefined') {
      throw new Error('Database operations are not available on server side');
    }

    if (!this.initPromise) {
      this.initPromise = this.init();
    }
    
    await this.initPromise;
    
    if (!this.db) {
      throw new Error('Database initialization failed');
    }
    
    return this.db;
  }

  private async init(): Promise<void> {
    try {
      this.db = new ChatDatabase();
      await this.db.open();
      console.log('✅ Chat database initialized with Dexie.js');
    } catch (error) {
      console.error('❌ Database initialization failed:', error);
      throw error;
    }
  }

  // Chat session methods
  async createChatSession(providerAddress: string, walletAddress: string, title?: string): Promise<string> {
    const db = await this.getDB();
    const sessionId = `session_${Date.now()}_${Math.random().toString(36).substring(2)}`;
    const now = Date.now();

    await db.sessions.add({
      session_id: sessionId,
      provider_address: providerAddress,
      wallet_address: walletAddress,
      created_at: now,
      updated_at: now,
      title: title || undefined
    });

    return sessionId;
  }

  async getChatSessions(walletAddress?: string, providerAddress?: string): Promise<ChatSession[]> {
    const db = await this.getDB();
    
    const query = db.sessions.orderBy('updated_at').reverse();
    
    if (walletAddress && providerAddress) {
      return query.filter(session => 
        session.wallet_address === walletAddress && 
        session.provider_address === providerAddress
      ).toArray();
    } else if (walletAddress) {
      return query.filter(session => session.wallet_address === walletAddress).toArray();
    } else if (providerAddress) {
      return query.filter(session => session.provider_address === providerAddress).toArray();
    }
    
    return query.toArray();
  }

  async updateChatSessionTitle(sessionId: string, title: string): Promise<void> {
    const db = await this.getDB();
    await db.sessions
      .where('session_id')
      .equals(sessionId)
      .modify({
        title: title,
        updated_at: Date.now()
      });
  }

  async deleteChatSession(sessionId: string): Promise<void> {
    const db = await this.getDB();
    
    await db.transaction('rw', db.sessions, db.messages, async () => {
      // Delete messages first
      await db.messages.where('session_id').equals(sessionId).delete();
      // Delete the session
      await db.sessions.where('session_id').equals(sessionId).delete();
    });
  }

  // Chat message methods
  async saveMessage(sessionId: string, message: Omit<ChatMessage, 'id'>): Promise<number> {
    const db = await this.getDB();
    
    const messageId = await db.messages.add({
      session_id: sessionId,
      role: message.role,
      content: message.content,
      timestamp: message.timestamp,
      chat_id: message.chat_id || undefined,
      is_verified: message.is_verified ?? undefined,
      is_verifying: message.is_verifying ?? false,
      provider_address: message.provider_address || undefined,
    });

    // Update session updated_at timestamp
    await db.sessions
      .where('session_id')
      .equals(sessionId)
      .modify({ updated_at: Date.now() });

    return messageId as number;
  }

  async getMessages(sessionId: string): Promise<ChatMessage[]> {
    const db = await this.getDB();
    return db.messages
      .where('session_id')
      .equals(sessionId)
      .sortBy('timestamp');
  }

  async updateMessageVerification(messageId: number, isVerified: boolean, isVerifying: boolean = false): Promise<void> {
    const db = await this.getDB();
    await db.messages.update(messageId, {
      is_verified: isVerified,
      is_verifying: isVerifying
    });
  }

  async clearMessages(sessionId: string): Promise<void> {
    const db = await this.getDB();
    await db.messages.where('session_id').equals(sessionId).delete();
  }

  // Search messages
  async searchMessages(query: string, walletAddress?: string, providerAddress?: string): Promise<ChatMessage[]> {
    const db = await this.getDB();
    
    // Get all messages and filter by content
    let messages = await db.messages
      .orderBy('timestamp')
      .reverse()
      .limit(100)
      .toArray();

    // Filter by content
    messages = messages.filter(msg => 
      msg.content.toLowerCase().includes(query.toLowerCase())
    );

    // If wallet or provider filters are specified, we need to join with sessions
    if (walletAddress || providerAddress) {
      const sessionIds = new Set();
      
      let sessions = await db.sessions.toArray();
      if (walletAddress) {
        sessions = sessions.filter(s => s.wallet_address === walletAddress);
      }
      if (providerAddress) {
        sessions = sessions.filter(s => s.provider_address === providerAddress);
      }
      
      sessions.forEach(s => sessionIds.add(s.session_id));
      messages = messages.filter(msg => sessionIds.has(msg.session_id));
    }

    return messages;
  }

  // Get recent sessions for wallet
  async getRecentSessions(
    walletAddress: string, 
    providerAddress?: string, 
    limit: number = APP_CONSTANTS.LIMITS.SESSION_HISTORY_LIMIT
  ): Promise<ChatSession[]> {
    const db = await this.getDB();
    
    let query = db.sessions
      .where('wallet_address')
      .equals(walletAddress);
    
    if (providerAddress) {
      query = query.and(session => session.provider_address === providerAddress);
    }
    
    return query
      .reverse()
      .sortBy('updated_at')
      .then(results => results.slice(0, limit));
  }

  async close(): Promise<void> {
    if (this.db) {
      this.db.close();
      this.db = null;
      this.initPromise = null;
    }
  }
}

// Export singleton instance
export const dbManager = new DatabaseManager();