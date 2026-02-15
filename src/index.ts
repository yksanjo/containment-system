/**
 * Containment System
 * 
 * Standalone library for session quarantine and threat containment management.
 */

export type ThreatLevel = 1 | 2 | 3 | 4;

export interface QuarantineRecord {
  sessionId: string;
  timestamp: string;
  reason: string;
  released: boolean;
  releasedAt?: string;
  threatLevel: ThreatLevel;
}

export interface ContainmentConfig {
  autoContainThreshold: ThreatLevel;
  maxQuarantineDuration?: number;
}

export class ContainmentSystem {
  private config: ContainmentConfig;
  private quarantinedSessions: Map<string, QuarantineRecord>;

  constructor(config: ContainmentConfig) {
    this.config = config;
    this.quarantinedSessions = new Map();
  }

  /**
   * Quarantine a session
   */
  quarantine(sessionId: string, reason: string): boolean {
    if (this.isQuarantined(sessionId)) {
      return false;
    }

    const record: QuarantineRecord = {
      sessionId,
      timestamp: new Date().toISOString(),
      reason,
      released: false,
      threatLevel: this.config.autoContainThreshold
    };

    this.quarantinedSessions.set(sessionId, record);
    return true;
  }

  /**
   * Release a quarantined session
   */
  release(sessionId: string): boolean {
    const record = this.quarantinedSessions.get(sessionId);
    
    if (!record) {
      return false;
    }

    record.released = true;
    record.releasedAt = new Date().toISOString();
    
    return true;
  }

  /**
   * Check if a session is quarantined
   */
  isQuarantined(sessionId: string): boolean {
    const record = this.quarantinedSessions.get(sessionId);
    return record !== undefined && !record.released;
  }

  /**
   * Get quarantine record
   */
  getRecord(sessionId: string): QuarantineRecord | null {
    return this.quarantinedSessions.get(sessionId) || null;
  }

  /**
   * Get all quarantined sessions
   */
  getQuarantinedSessions(): QuarantineRecord[] {
    return Array.from(this.quarantinedSessions.values())
      .filter(r => !r.released);
  }

  /**
   * Get quarantine history
   */
  getHistory(): QuarantineRecord[] {
    return Array.from(this.quarantinedSessions.values());
  }

  /**
   * Should auto-contain based on threat level
   */
  shouldAutoContain(threatLevel: ThreatLevel): boolean {
    return threatLevel >= this.config.autoContainThreshold;
  }

  /**
   * Get statistics
   */
  getStats(): {
    totalQuarantined: number;
    currentlyQuarantined: number;
    released: number;
    averageQuarantineTime: number;
  } {
    const records = Array.from(this.quarantinedSessions.values());
    const currentlyQuarantined = records.filter(r => !r.released).length;
    const released = records.filter(r => r.released).length;
    
    const quarantineTimes = records
      .filter(r => r.released && r.releasedAt)
      .map(r => {
        const start = new Date(r.timestamp).getTime();
        const end = new Date(r.releasedAt!).getTime();
        return end - start;
      });
    
    const avgTime = quarantineTimes.length > 0
      ? quarantineTimes.reduce((a, b) => a + b, 0) / quarantineTimes.length
      : 0;

    return {
      totalQuarantined: records.length,
      currentlyQuarantined,
      released,
      averageQuarantineTime: avgTime
    };
  }

  /**
   * Clear old records
   */
  clearOldRecords(olderThanMs: number = 86400000): void {
    const cutoff = Date.now() - olderThanMs;
    
    for (const [sessionId, record] of this.quarantinedSessions) {
      if (record.released) {
        const releasedAt = record.releasedAt 
          ? new Date(record.releasedAt).getTime() 
          : 0;
        
        if (releasedAt > 0 && releasedAt < cutoff) {
          this.quarantinedSessions.delete(sessionId);
        }
      }
    }
  }
}

export default ContainmentSystem;
