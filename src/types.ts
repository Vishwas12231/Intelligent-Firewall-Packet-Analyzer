export interface Packet {
  id: string;
  timestamp: string; // ISO string
  sourceIp: string;
  destIp: string;
  sourcePort: number;
  destPort: number;
  protocol: 'TCP' | 'UDP' | 'ICMP' | 'HTTP' | 'HTTPS' | 'DNS';
  size: number;
  flags: string;
  payload: string;
  anomalyScore: number; // 0 to 100
  threatCategory: 'Normal' | 'DDoS Attempt' | 'Brute Force' | 'Port Scan' | 'SQL Injection' | 'Anomaly';
  status: 'Allowed' | 'Blocked';
}

export interface FirewallRule {
  id: string;
  name: string;
  type: 'ALLOW' | 'BLOCK';
  sourceIP: string; // Wildcard "*" or explicit IP
  destIP: string; // Wildcard "*"
  port: string; // Wildcard "*" or explicit number
  protocol: 'ANY' | 'TCP' | 'UDP' | 'ICMP' | 'HTTP' | 'HTTPS' | 'DNS';
  description: string;
  createdAt: string;
  isActive: boolean;
}

export interface SecurityAlert {
  id: string;
  timestamp: string;
  severity: 'INFO' | 'WARNING' | 'CRITICAL';
  type: string; // DDoS, Port Scan, Brute Force, Payload anomaly, etc.
  sourceIP: string;
  destIP: string;
  message: string;
  packetLink?: string; // Packet ID that triggered it
  acknowledged: boolean;
}

export interface BlockedAttack {
  id: string;
  timestamp: string;
  sourceIP: string;
  destIP: string;
  protocol: string;
  port: number;
  attackType: string;
  severity: 'WARNING' | 'CRITICAL';
  ruleMatched?: string;
}

export interface TrafficStats {
  totalPackets: number;
  blockedPackets: number;
  averagePacketSize: number;
  alertCount: number;
  protocolDistribution: {
    TCP: number;
    UDP: number;
    ICMP: number;
    HTTP: number;
    HTTPS: number;
    DNS: number;
  };
  attackDistribution: {
    'DDoS': number;
    'Brute Force': number;
    'Port Scan': number;
    'SQL Injection': number;
    'Other Anomaly': number;
  };
}
