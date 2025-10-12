import { PGlite } from '@electric-sql/pglite';
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

class DatabaseManager {
  private db: PGlite | null = null;
  private initPromise: Promise<void> | null = null;

  async init(): Promise<void> {
    if (this.initPromise) {
      return this.initPromise;
    }

    this.initPromise = this._init();
    return this.initPromise;
  }

  private async _init(): Promise<void> {
    // Skip initialization on server side
    if (typeof window === 'undefined') {
      return;
    }
    
    try {
      // Initialize PGlite with IndexedDB persistence
      this.db = new PGlite({
        dataDir: APP_CONSTANTS.DATABASE.DB_NAME,
      });

      // Create tables
      await this.db.exec(`
        CREATE TABLE IF NOT EXISTS chat_sessions (
          id SERIAL PRIMARY KEY,
          session_id TEXT UNIQUE NOT NULL,
          provider_address TEXT NOT NULL,
          wallet_address TEXT,
          created_at BIGINT NOT NULL,
          updated_at BIGINT NOT NULL,
          title TEXT
        );

        CREATE TABLE IF NOT EXISTS chat_messages (
          id SERIAL PRIMARY KEY,
          session_id TEXT NOT NULL,
          role TEXT NOT NULL CHECK (role IN ('system', 'user', 'assistant')),
          content TEXT NOT NULL,
          timestamp BIGINT NOT NULL,
          chat_id TEXT,
          is_verified BOOLEAN,
          is_verifying BOOLEAN DEFAULT FALSE,
          provider_address TEXT,
          FOREIGN KEY (session_id) REFERENCES chat_sessions(session_id) ON DELETE CASCADE
        );

        CREATE INDEX IF NOT EXISTS idx_chat_messages_session_id ON chat_messages(session_id);
        CREATE INDEX IF NOT EXISTS idx_chat_messages_timestamp ON chat_messages(timestamp);
        CREATE INDEX IF NOT EXISTS idx_chat_sessions_provider ON chat_sessions(provider_address);
        CREATE INDEX IF NOT EXISTS idx_chat_sessions_wallet ON chat_sessions(wallet_address);
        CREATE INDEX IF NOT EXISTS idx_chat_sessions_updated ON chat_sessions(updated_at);
        
        -- Composite indexes for common queries
        CREATE INDEX IF NOT EXISTS idx_chat_sessions_wallet_provider ON chat_sessions(wallet_address, provider_address);
        CREATE INDEX IF NOT EXISTS idx_chat_messages_session_timestamp ON chat_messages(session_id, timestamp);
        CREATE INDEX IF NOT EXISTS idx_chat_sessions_wallet_updated ON chat_sessions(wallet_address, updated_at);
      `);

      // Migration: Add wallet_address column if it doesn't exist
      try {
        await this.db.exec(`
          ALTER TABLE chat_sessions 
          ADD COLUMN IF NOT EXISTS wallet_address TEXT;
        `);
      } catch (error) {
        // Column might already exist, which is fine
      }

    } catch (error) {
      throw error;
    }
  }

  private async ensureInit(): Promise<PGlite> {
    // Skip on server side
    if (typeof window === 'undefined') {
      throw new Error('Database operations are not available on server side');
    }
    
    if (!this.db) {
      await this.init();
    }
    if (!this.db) {
      throw new Error('Database not initialized');
    }
    return this.db;
  }

  // Chat session methods
  async createChatSession(providerAddress: string, walletAddress: string, title?: string): Promise<string> {
    const db = await this.ensureInit();
    const sessionId = `session_${Date.now()}_${Math.random().toString(36).substring(2)}`;
    const now = Date.now();

    await db.query(`
      INSERT INTO chat_sessions (session_id, provider_address, wallet_address, created_at, updated_at, title)
      VALUES ($1, $2, $3, $4, $5, $6)
    `, [sessionId, providerAddress, walletAddress, now, now, title || null]);

    return sessionId;
  }

  async getChatSessions(walletAddress?: string, providerAddress?: string): Promise<ChatSession[]> {
    const db = await this.ensureInit();
    
    let query = 'SELECT * FROM chat_sessions';
    const params: (string | number)[] = [];
    const conditions: string[] = [];
    
    if (walletAddress) {
      conditions.push(`wallet_address = $${params.length + 1}`);
      params.push(walletAddress);
    }
    
    if (providerAddress) {
      conditions.push(`provider_address = $${params.length + 1}`);
      params.push(providerAddress);
    }
    
    if (conditions.length > 0) {
      query += ' WHERE ' + conditions.join(' AND ');
    }
    
    query += ' ORDER BY updated_at DESC';

    const result = await db.query(query, params);
    return result.rows as ChatSession[];
  }

  async updateChatSessionTitle(sessionId: string, title: string): Promise<void> {
    const db = await this.ensureInit();
    await db.query('UPDATE chat_sessions SET title = $1, updated_at = $2 WHERE session_id = $3', 
      [title, Date.now(), sessionId]);
  }

  async deleteChatSession(sessionId: string): Promise<void> {
    const db = await this.ensureInit();
    
    try {
      // Start a transaction
      await db.exec('BEGIN');
      
      // First, check if the session exists
      const checkResult = await db.query('SELECT * FROM chat_sessions WHERE session_id = $1', [sessionId]);
      
      if (checkResult.rows.length === 0) {
        await db.exec('ROLLBACK');
        return;
      }
      
      // Delete messages first (even though CASCADE should handle this)
      await db.query('DELETE FROM chat_messages WHERE session_id = $1', [sessionId]);
      
      // Delete the session
      await db.query('DELETE FROM chat_sessions WHERE session_id = $1', [sessionId]);
      
      // Commit the transaction
      await db.exec('COMMIT');
      
    } catch (error) {
      await db.exec('ROLLBACK');
      throw error;
    }
  }

  // Chat message methods
  async saveMessage(sessionId: string, message: Omit<ChatMessage, 'id'>): Promise<number> {
    const db = await this.ensureInit();
    
    const result = await db.query(`
      INSERT INTO chat_messages (
        session_id, role, content, timestamp, chat_id, 
        is_verified, is_verifying, provider_address
      )
      VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
      RETURNING id
    `, [
      sessionId,
      message.role,
      message.content,
      message.timestamp,
      message.chat_id || null,
      message.is_verified ?? null,
      message.is_verifying ?? false,
      message.provider_address || null,
    ]);

    // Update session updated_at timestamp
    await db.query('UPDATE chat_sessions SET updated_at = $1 WHERE session_id = $2', 
      [Date.now(), sessionId]);

    return (result.rows[0] as any).id;
  }

  async getMessages(sessionId: string): Promise<ChatMessage[]> {
    const db = await this.ensureInit();
    
    const result = await db.query('SELECT * FROM chat_messages WHERE session_id = $1 ORDER BY timestamp ASC', 
      [sessionId]);

    return result.rows as ChatMessage[];
  }

  async updateMessageVerification(messageId: number, isVerified: boolean, isVerifying: boolean = false): Promise<void> {
    const db = await this.ensureInit();
    
    await db.query('UPDATE chat_messages SET is_verified = $1, is_verifying = $2 WHERE id = $3', 
      [isVerified, isVerifying, messageId]);
  }

  async clearMessages(sessionId: string): Promise<void> {
    const db = await this.ensureInit();
    await db.query('DELETE FROM chat_messages WHERE session_id = $1', [sessionId]);
  }

  // Search messages
  async searchMessages(query: string, walletAddress?: string, providerAddress?: string): Promise<ChatMessage[]> {
    const db = await this.ensureInit();
    
    let sqlQuery = `
      SELECT cm.* FROM chat_messages cm
      JOIN chat_sessions cs ON cm.session_id = cs.session_id
      WHERE cm.content ILIKE $1
    `;
    const params: (string | number)[] = [`%${query}%`];
    
    if (walletAddress) {
      sqlQuery += ` AND cs.wallet_address = $${params.length + 1}`;
      params.push(walletAddress);
    }
    
    if (providerAddress) {
      sqlQuery += ` AND cs.provider_address = $${params.length + 1}`;
      params.push(providerAddress);
    }
    
    sqlQuery += ' ORDER BY cm.timestamp DESC LIMIT 100';

    const result = await db.query(sqlQuery, params);
    return result.rows as ChatMessage[];
  }

  // Get recent sessions for wallet
  async getRecentSessions(walletAddress: string, providerAddress?: string, limit: number = APP_CONSTANTS.LIMITS.SESSION_HISTORY_LIMIT): Promise<ChatSession[]> {
    const db = await this.ensureInit();
    
    let query = `
      SELECT * FROM chat_sessions 
      WHERE wallet_address = $1
    `;
    const params: (string | number)[] = [walletAddress];
    
    if (providerAddress) {
      query += ` AND provider_address = $${params.length + 1}`;
      params.push(providerAddress);
    }
    
    query += ` ORDER BY updated_at DESC LIMIT $${params.length + 1}`;
    params.push(limit);
    
    const result = await db.query(query, params);

    return result.rows as ChatSession[];
  }

  async close(): Promise<void> {
    if (this.db) {
      await this.db.close();
      this.db = null;
      this.initPromise = null;
    }
  }
}

// Export singleton instance
export const dbManager = new DatabaseManager();