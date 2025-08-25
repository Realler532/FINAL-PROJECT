import { useEffect, useState } from 'react'
import { supabase } from '../lib/supabaseClient'
import { backendService, BackendThreat, BackendStats } from '../services/backendService'
import { Incident, NetworkTraffic, SystemStatus, Alert, ThreatDetection, AnomalyDetection } from '../types/incident'
import { generateSystemStatus, generateNetworkTraffic, generateAlert, generateThreatDetection, generateAnomalyDetection, correlateAlerts } from '../utils/dataSimulator'

import { fetchAlerts as fetchBackendAlerts } from '../services/backendApi'


export function useIncidentData() {
  const [incidents, setIncidents] = useState<Incident[]>([])
  const [networkTraffic, setNetworkTraffic] = useState<NetworkTraffic[]>([])
  const [systemStatus, setSystemStatus] = useState<SystemStatus[]>([])
  const [alerts, setAlerts] = useState<Alert[]>([])
  const [threatDetections, setThreatDetections] = useState<ThreatDetection[]>([])
  const [anomalies, setAnomalies] = useState<AnomalyDetection[]>([])
  const [isMonitoring, setIsMonitoring] = useState(true)
  const [backendConnected, setBackendConnected] = useState(false)
  const [backendStats, setBackendStats] = useState<BackendStats | null>(null)

  useEffect(() => {
    // Initialize with some default data
    setSystemStatus(generateSystemStatus())
    
    // Set up periodic data generation for demo purposes
    const interval = setInterval(() => {
      if (isMonitoring) {
        // Generate some demo network traffic
        setNetworkTraffic(prev => {
          const newTraffic = generateNetworkTraffic()
          return [newTraffic, ...prev.slice(0, 99)] // Keep last 100 entries
        })
        
        // Occasionally generate alerts and threats
        if (Math.random() < 0.3) {
          const newAlert = generateAlert()
          setAlerts(prev => {
            const updated = [newAlert, ...prev.slice(0, 49)]
            return correlateAlerts(updated)
          })
        }
        
        if (Math.random() < 0.2) {
          const newThreat = generateThreatDetection()
          setThreatDetections(prev => [newThreat, ...prev.slice(0, 29)])
        }
        
        if (Math.random() < 0.15) {
          const newAnomaly = generateAnomalyDetection()
          setAnomalies(prev => [newAnomaly, ...prev.slice(0, 19)])
        }
      }
    }, 2000)

    // Set up backend service listeners
    const unsubscribeThreat = backendService.onThreatDetected((threat: BackendThreat) => {
      // Convert backend threat to incident
      const incident: Incident = {
        id: threat.id,
        timestamp: new Date(threat.timestamp),
        type: threat.threat_type as any,
        severity: threat.severity >= 8 ? 'critical' : threat.severity >= 6 ? 'high' : threat.severity >= 4 ? 'medium' : 'low',
        source: threat.source_ip,
        target: threat.destination_ip,
        description: threat.description,
        status: threat.blocked ? 'contained' : 'detected',
        responseActions: threat.blocked ? ['Block IP address', 'Notify security team'] : ['Investigate source'],
        affectedSystems: [threat.destination_ip]
      }
      
      setIncidents(prev => [incident, ...prev.slice(0, 49)])
      
      // Also create an alert
      const alert: Alert = {
        id: `ALT-${threat.id}`,
        timestamp: new Date(threat.timestamp),
        message: threat.description,
        type: threat.severity >= 8 ? 'critical' : threat.severity >= 6 ? 'error' : 'warning',
        acknowledged: false,
        sourceSystem: 'Backend Threat Detection',
        riskScore: Math.round(threat.confidence * 100),
        isDuplicate: false,
        relatedAlerts: []
      }
      
      setAlerts(prev => {
        const updated = [alert, ...prev.slice(0, 49)]
        return correlateAlerts(updated)
      })
      
      // Create threat detection entry
      const threatDetection: ThreatDetection = {
        id: `THR-${threat.id}`,
        timestamp: new Date(threat.timestamp),
        threatType: threat.threat_type.includes('behavioral') ? 'behavioral_anomaly' : 
                   threat.threat_type.includes('signature') ? 'signature_match' : 'ml_detection',
        confidence: Math.round(threat.confidence * 100),
        riskScore: Math.round(threat.confidence * 100),
        indicators: threat.indicators,
        affectedAssets: [threat.destination_ip],
        mitreTactics: ['Initial Access', 'Execution'],
        description: threat.description
      }
      
      setThreatDetections(prev => [threatDetection, ...prev.slice(0, 29)])
    })

    const unsubscribeStats = backendService.onStatsUpdate((stats: BackendStats) => {
      setBackendStats(stats)
    })

    const unsubscribeConnection = backendService.onConnectionChange((connected: boolean) => {
      setBackendConnected(connected)
    })

    // Supabase setup (keep existing functionality)
    fetchAlerts()
    fetchAlertsFromBackend()

    const channel = supabase.channel('public:alerts')
      .on('postgres_changes', { event: '*', schema: 'public', table: 'alerts' }, (payload) => {
        fetchAlerts()
      })
      .subscribe()

    return () => {
      clearInterval(interval)
      unsubscribeThreat()
      unsubscribeStats()
      unsubscribeConnection()
      
      try {
        supabase.removeChannel(channel)
      } catch (e) {
        // ignore
      }
    }
  }, [isMonitoring])

  async function fetchAlerts() {
    const { data, error } = await supabase.from('alerts').select('*').order('timestamp', { ascending: false })
    if (!error && data) setAlerts(data)
  }


  async function fetchAlertsFromBackend() {
    try {
      const items = await fetchBackendAlerts(50)
      if (items && items.length) {
        setAlerts(items)
      }
    } catch (e) {
      console.warn('Backend alerts fetch failed', e)
    }
  }
  const toggleMonitoring = () => {
    setIsMonitoring(!isMonitoring)
  }

  const acknowledgeAlert = (alertId: string) => {
    setAlerts(prev => prev.map(alert => 
      alert.id === alertId ? { ...alert, acknowledged: true } : alert
    ))
  }

  const resolveIncident = (incidentId: string) => {
    setIncidents(prev => prev.map(incident => 
      incident.id === incidentId ? { ...incident, status: 'resolved' as const } : incident
    ))
  }

  return { 
    incidents,
    networkTraffic,
    systemStatus,
    alerts,
    threatDetections,
    anomalies,
    isMonitoring,
    toggleMonitoring,
    acknowledgeAlert,
    resolveIncident,
    backendConnected,
    backendStats,
    blockIP: backendService.blockIP.bind(backendService),
    unblockIP: backendService.unblockIP.bind(backendService)
  }
}