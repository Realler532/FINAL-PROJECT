import { io, Socket } from 'socket.io-client';

export interface BackendThreat {
  id: string;
  timestamp: string;
  source_ip: string;
  destination_ip: string;
  threat_type: string;
  severity: number;
  confidence: number;
  description: string;
  indicators: string[];
  blocked: boolean;
}

export interface BackendStats {
  total_threats: number;
  active_threats: number;
  blocked_ips: number;
  threats_last_hour: number;
  threats_last_24h: number;
  threat_types: Record<string, number>;
  top_threat_ips: Array<{
    ip: string;
    threat_count: number;
    max_severity: number;
    blocked: boolean;
  }>;
  severity_distribution: Record<string, number>;
  correlations: Array<{
    type: string;
    source_ip: string;
    threat_count: number;
    severity: number;
    timespan: number;
    description: string;
  }>;
}

class BackendService {
  private socket: Socket | null = null;
  private backendUrl = 'http://localhost:5000';
  private isConnected = false;
  private reconnectAttempts = 0;
  private maxReconnectAttempts = 5;
  private reconnectDelay = 3000;

  // Event listeners
  private threatListeners: Array<(threat: BackendThreat) => void> = [];
  private statsListeners: Array<(stats: BackendStats) => void> = [];
  private connectionListeners: Array<(connected: boolean) => void> = [];

  constructor() {
    this.connect();
  }

  private connect() {
    try {
      this.socket = io(this.backendUrl, {
        transports: ['websocket', 'polling'],
        timeout: 10000,
        forceNew: true
      });

      this.socket.on('connect', () => {
        console.log('Connected to threat detection backend');
        this.isConnected = true;
        this.reconnectAttempts = 0;
        this.notifyConnectionListeners(true);
        
        // Subscribe to threat updates
        this.socket?.emit('subscribe_threats');
        
        // Fetch initial data
        this.fetchInitialData();
      });

      this.socket.on('disconnect', () => {
        console.log('Disconnected from threat detection backend');
        this.isConnected = false;
        this.notifyConnectionListeners(false);
        this.attemptReconnect();
      });

      this.socket.on('threat_detected', (threat: BackendThreat) => {
        console.log('New threat detected:', threat);
        this.notifyThreatListeners(threat);
      });

      this.socket.on('connect_error', (error) => {
        console.error('Backend connection error:', error);
        this.isConnected = false;
        this.notifyConnectionListeners(false);
        this.attemptReconnect();
      });

    } catch (error) {
      console.error('Failed to initialize backend connection:', error);
      this.attemptReconnect();
    }
  }

  private attemptReconnect() {
    if (this.reconnectAttempts < this.maxReconnectAttempts) {
      this.reconnectAttempts++;
      console.log(`Attempting to reconnect to backend (${this.reconnectAttempts}/${this.maxReconnectAttempts})...`);
      
      setTimeout(() => {
        this.connect();
      }, this.reconnectDelay * this.reconnectAttempts);
    } else {
      console.error('Max reconnection attempts reached. Backend connection failed.');
    }
  }

  private async fetchInitialData() {
    try {
      // Fetch recent threats
      const threatsResponse = await fetch(`${this.backendUrl}/api/threats?limit=50`);
      if (threatsResponse.ok) {
        const threats = await threatsResponse.json();
        threats.forEach((threat: BackendThreat) => {
          this.notifyThreatListeners(threat);
        });
      }

      // Fetch statistics
      const statsResponse = await fetch(`${this.backendUrl}/api/statistics`);
      if (statsResponse.ok) {
        const stats = await statsResponse.json();
        this.notifyStatsListeners(stats);
      }

      // Set up periodic stats updates
      setInterval(() => {
        this.fetchStats();
      }, 10000); // Update every 10 seconds

    } catch (error) {
      console.error('Failed to fetch initial data:', error);
    }
  }

  private async fetchStats() {
    try {
      const response = await fetch(`${this.backendUrl}/api/statistics`);
      if (response.ok) {
        const stats = await response.json();
        this.notifyStatsListeners(stats);
      }
    } catch (error) {
      console.error('Failed to fetch stats:', error);
    }
  }

  // Public methods for subscribing to events
  onThreatDetected(callback: (threat: BackendThreat) => void) {
    this.threatListeners.push(callback);
    return () => {
      this.threatListeners = this.threatListeners.filter(cb => cb !== callback);
    };
  }

  onStatsUpdate(callback: (stats: BackendStats) => void) {
    this.statsListeners.push(callback);
    return () => {
      this.statsListeners = this.statsListeners.filter(cb => cb !== callback);
    };
  }

  onConnectionChange(callback: (connected: boolean) => void) {
    this.connectionListeners.push(callback);
    return () => {
      this.connectionListeners = this.connectionListeners.filter(cb => cb !== callback);
    };
  }

  // Notification methods
  private notifyThreatListeners(threat: BackendThreat) {
    this.threatListeners.forEach(callback => {
      try {
        callback(threat);
      } catch (error) {
        console.error('Error in threat listener:', error);
      }
    });
  }

  private notifyStatsListeners(stats: BackendStats) {
    this.statsListeners.forEach(callback => {
      try {
        callback(stats);
      } catch (error) {
        console.error('Error in stats listener:', error);
      }
    });
  }

  private notifyConnectionListeners(connected: boolean) {
    this.connectionListeners.forEach(callback => {
      try {
        callback(connected);
      } catch (error) {
        console.error('Error in connection listener:', error);
      }
    });
  }

  // Public API methods
  async blockIP(ip: string): Promise<boolean> {
    try {
      const response = await fetch(`${this.backendUrl}/api/block/${ip}`, {
        method: 'POST'
      });
      return response.ok;
    } catch (error) {
      console.error('Failed to block IP:', error);
      return false;
    }
  }

  async unblockIP(ip: string): Promise<boolean> {
    try {
      const response = await fetch(`${this.backendUrl}/api/unblock/${ip}`, {
        method: 'POST'
      });
      return response.ok;
    } catch (error) {
      console.error('Failed to unblock IP:', error);
      return false;
    }
  }

  async submitNetworkEvent(eventData: any): Promise<boolean> {
    try {
      const response = await fetch(`${this.backendUrl}/api/submit_event`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify(eventData)
      });
      return response.ok;
    } catch (error) {
      console.error('Failed to submit network event:', error);
      return false;
    }
  }

  isBackendConnected(): boolean {
    return this.isConnected;
  }

  disconnect() {
    if (this.socket) {
      this.socket.disconnect();
      this.socket = null;
    }
    this.isConnected = false;
  }
}

// Export singleton instance
export const backendService = new BackendService();