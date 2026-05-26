import express from "express";
import path from "path";
import { createServer as createViteServer } from "vite";
import { GoogleGenAI, Type } from "@google/genai";
import dotenv from "dotenv";

dotenv.config();

// Initialize server-side Gemini API client
const ai = new GoogleGenAI({
  apiKey: process.env.GEMINI_API_KEY,
  httpOptions: {
    headers: {
      'User-Agent': 'aistudio-build',
    }
  }
});

const app = express();
const PORT = 3000;

app.use(express.json());

// In-Memory Database for local live-updating simulations
// Since this is a specialized live sandbox simulation with a complete modular backend
let packets: any[] = [];
let firewallRules: any[] = [
  {
    id: "rule_1",
    name: "Block Known Tor Exit Node",
    type: "BLOCK",
    sourceIP: "185.220.101.5",
    destIP: "*",
    port: "*",
    protocol: "ANY",
    description: "Automatic threat intelligence blocking of hazardous IPs.",
    createdAt: new Date().toISOString(),
    isActive: true,
  },
  {
    id: "rule_2",
    name: "Allow standard HTTPS web ingress",
    type: "ALLOW",
    sourceIP: "*",
    destIP: "*",
    port: "443",
    protocol: "HTTPS",
    description: "Accepting standard TLS secure handshake communication.",
    createdAt: new Date().toISOString(),
    isActive: true,
  }
];

let alerts: any[] = [];
let blockedAttacks: any[] = [];
let isCapturing = true; // Simulating active interface capture state

// IP blacklist tracker for quick lookup
const blacklistedIPs = new Set<string>(["185.220.101.5"]);
const whitelistedIPs = new Set<string>(["192.168.1.50", "127.0.0.1"]);

// Generate seed packet data automatically to kickstart simulation
const ipCatalog = {
  malicious: ["185.220.101.5", "45.143.203.14", "81.92.201.35", "103.84.241.12", "198.51.100.42"],
  normal: ["192.168.1.10", "192.168.1.25", "10.0.0.8", "172.16.2.55", "142.250.190.46", "31.13.72.36", "8.8.8.8"]
};

// Simulated Packet Generator supporting live stream & analytics
function generateSimulatedPacket(): any {
  const isAttack = Math.random() < 0.22; // 22% chance of malicious/suspicious activity
  const protocolChoices = ["TCP", "UDP", "ICMP", "HTTP", "HTTPS", "DNS"] as const;
  const protocol = protocolChoices[Math.floor(Math.random() * protocolChoices.length)];
  
  let sourceIp = "";
  let destIp = "";
  let sourcePort = Math.floor(Math.random() * 63000) + 1024;
  let destPort = 80;
  let size = Math.floor(Math.random() * 1200) + 64;
  let flags = "S";
  let payload = "";
  let anomalyScore = Math.floor(Math.random() * 15); // baseline normal anomaly score is low
  let threatCategory: 'Normal' | 'DDoS Attempt' | 'Brute Force' | 'Port Scan' | 'SQL Injection' | 'Anomaly' = 'Normal';
  
  // Custom port mapping depending on protocol
  if (protocol === "HTTPS") destPort = 443;
  else if (protocol === "DNS") destPort = 53;
  else if (protocol === "HTTP") destPort = 80;
  else if (protocol === "ICMP") {
    destPort = 0;
    sourcePort = 0;
  }

  if (isAttack) {
    sourceIp = ipCatalog.malicious[Math.floor(Math.random() * ipCatalog.malicious.length)];
    destIp = "192.168.1.100"; // target internal server
    anomalyScore = Math.floor(Math.random() * 50) + 50; // high score
    
    const attackDice = Math.random();
    if (attackDice < 0.25) {
      threatCategory = "DDoS Attempt";
      size = 1480;
      flags = "S";
      payload = "SYNFLOOD_ATTACK_PATTERN_DETECTED_SEQ_" + Math.floor(Math.random()*100000);
    } else if (attackDice < 0.50) {
      threatCategory = "Port Scan";
      destPort = Math.floor(Math.random() * 1024);
      flags = "S";
      payload = "NMAP_TCP_SYN_STEALTH_SCAN_PING";
    } else if (attackDice < 0.75) {
      threatCategory = "Brute Force";
      destPort = 22; // SSH
      flags = "PA";
      payload = "SSH-2.0-OpenSSH_8.2p1; USER root; PASS admin123; Login failed";
    } else {
      threatCategory = "SQL Injection";
      destPort = 80;
      flags = "PA";
      payload = "GET /vulnerables.php?id=1' UNION SELECT username, password FROM users -- HTTP/1.1";
    }
  } else {
    sourceIp = ipCatalog.normal[Math.floor(Math.random() * ipCatalog.normal.length)];
    destIp = "192.168.1.100";
    if (Math.random() < 0.15) {
      // Occasional non-threatening slight anomaly
      anomalyScore = Math.floor(Math.random() * 25) + 20;
      threatCategory = "Anomaly";
      payload = "Unusual Keep-Alive response payload received from user service browser host";
    } else {
      payload = `GET /assets/config.json HTTP/1.1 Host: dev-server-local`;
    }
  }

  // Determine Firewall action
  let status: 'Allowed' | 'Blocked' = 'Allowed';
  let matchedRule: any = null;

  // 1. Blacklist check
  if (blacklistedIPs.has(sourceIp)) {
    status = 'Blocked';
  } else {
    // 2. Custom Rule Match
    for (const rule of firewallRules) {
      if (!rule.isActive) continue;
      
      const ipMatch = rule.sourceIP === "*" || rule.sourceIP === sourceIp;
      const destIpMatch = rule.destIP === "*" || rule.destIP === destIp;
      const portMatch = rule.port === "*" || String(rule.port) === String(destPort);
      const protocolMatch = rule.protocol === "ANY" || rule.protocol === protocol;

      if (ipMatch && destIpMatch && portMatch && protocolMatch) {
        matchedRule = rule;
        status = rule.type === 'BLOCK' ? 'Blocked' : 'Allowed';
        break; // first rule wins (simulated rule ordering)
      }
    }
  }

  // Force whitelisting to bypass blocking rules for safe IPs
  if (whitelistedIPs.has(sourceIp)) {
    status = 'Allowed';
  }

  const packet = {
    id: "pkt_" + Math.floor(Math.random() * 1000000),
    timestamp: new Date().toISOString(),
    sourceIp,
    destIp,
    sourcePort,
    destPort,
    protocol,
    size,
    flags,
    payload,
    anomalyScore,
    threatCategory,
    status
  };

  // If blocked, log to attacker history
  if (status === 'Blocked' && isAttack) {
    const attackId = "atk_" + Math.floor(Math.random() * 100000);
    blockedAttacks.unshift({
      id: attackId,
      timestamp: packet.timestamp,
      sourceIP: sourceIp,
      destIP: destIp,
      protocol: protocol,
      port: destPort,
      attackType: threatCategory,
      severity: anomalyScore > 80 ? 'CRITICAL' : 'WARNING',
      ruleMatched: matchedRule ? matchedRule.name : "System IP Blacklist Rule"
    });

    // Also trigger critical security warning alert if it wasn't there before
    const isIpDDoSAlerted = alerts.some(a => a.sourceIP === sourceIp && a.type === threatCategory && !a.acknowledged);
    if (!isIpDDoSAlerted) {
      alerts.unshift({
        id: "alt_" + Math.floor(Math.random() * 100000),
        timestamp: packet.timestamp,
        severity: anomalyScore > 80 ? 'CRITICAL' : 'WARNING',
        type: threatCategory,
        sourceIP: sourceIp,
        destIP: destIp,
        message: `Intrusion Prevention System (IPS) successfully intercepted and blocked a high-level ${threatCategory} from source: ${sourceIp}. Anomaly Threat Score: ${anomalyScore}/100.`,
        packetLink: packet.id,
        acknowledged: false,
      });
    }
  }

  return packet;
}

// Generate starting log database
for (let i = 0; i < 50; i++) {
  packets.unshift(generateSimulatedPacket());
}

// Background packet engine
setInterval(() => {
  if (isCapturing) {
    const maxBuffer = 300;
    const newPacket = generateSimulatedPacket();
    packets.unshift(newPacket);
    if (packets.length > maxBuffer) {
      packets.pop();
    }
  }
}, 3000);

// API Endpoints for UI to access full suite of simulator functionality

// Complete Packet Feed
app.get("/api/packets", (req, res) => {
  res.json({
    packets,
    isCapturing
  });
});

// Capture Toggle API
app.post("/api/packets/toggle", (req, res) => {
  isCapturing = !isCapturing;
  res.json({ isCapturing });
});

// Clear simulation logs
app.post("/api/packets/clear", (req, res) => {
  packets = [];
  res.json({ success: true, packets });
});

// Firewall rules CRUD
app.get("/api/firewall/rules", (req, res) => {
  res.json({ rules: firewallRules });
});

app.post("/api/firewall/rules", (req, res) => {
  const { name, type, sourceIP, destIP, port, protocol, description } = req.body;
  if (!name || !type || !sourceIP || !protocol) {
    return res.status(400).json({ error: "Missing required firewall parameters" });
  }

  const newRule = {
    id: "rule_" + Math.floor(Math.random() * 100000),
    name,
    type,
    sourceIP: sourceIP.trim(),
    destIP: destIP ? destIP.trim() : "*",
    port: port ? port.trim() : "*",
    protocol,
    description: description || "Manually added firewall standard rule configuration.",
    createdAt: new Date().toISOString(),
    isActive: true
  };

  firewallRules.unshift(newRule);
  
  // If rule is active block, put in fast-path blacklist lookup
  if (newRule.type === "BLOCK" && newRule.sourceIP !== "*") {
    blacklistedIPs.add(newRule.sourceIP);
  }

  res.json({ success: true, rule: newRule, rules: firewallRules });
});

app.delete("/api/firewall/rules/:id", (req, res) => {
  const ruleId = req.params.id;
  const ruleToRemove = firewallRules.find(r => r.id === ruleId);
  if (ruleToRemove) {
    if (ruleToRemove.type === "BLOCK" && ruleToRemove.sourceIP !== "*") {
      blacklistedIPs.delete(ruleToRemove.sourceIP);
    }
    firewallRules = firewallRules.filter(r => r.id !== ruleId);
  }
  res.json({ success: true, rules: firewallRules });
});

app.post("/api/firewall/rules/:id/toggle", (req, res) => {
  const ruleId = req.params.id;
  firewallRules = firewallRules.map(r => {
    if (r.id === ruleId) {
      const updated = { ...r, isActive: !r.isActive };
      if (!updated.isActive) {
        if (updated.type === "BLOCK" && updated.sourceIP !== "*") {
          blacklistedIPs.delete(updated.sourceIP);
        }
      } else {
        if (updated.type === "BLOCK" && updated.sourceIP !== "*") {
          blacklistedIPs.add(updated.sourceIP);
        }
      }
      return updated;
    }
    return r;
  });
  res.json({ success: true, rules: firewallRules });
});

// Attack History Feed
app.get("/api/firewall/attacks", (req, res) => {
  res.json({ blockedAttacks });
});

// Security Alert Center
app.get("/api/alerts", (req, res) => {
  res.json({ alerts });
});

app.post("/api/alerts/acknowledge/:id", (req, res) => {
  const alertId = req.params.id;
  alerts = alerts.map(alert => {
    if (alert.id === alertId) {
      return { ...alert, acknowledged: true };
    }
    return alert;
  });
  res.json({ success: true, alerts });
});

// Whitelist and Blacklist dynamic managers
app.get("/api/lists", (req, res) => {
  res.json({
    blacklist: Array.from(blacklistedIPs),
    whitelist: Array.from(whitelistedIPs)
  });
});

app.post("/api/lists/add", (req, res) => {
  const { listType, ipAddress } = req.body;
  if (!ipAddress) return res.status(400).json({ error: "IP address required" });
  
  if (listType === "blacklist") {
    whitelistedIPs.delete(ipAddress);
    blacklistedIPs.add(ipAddress);
  } else if (listType === "whitelist") {
    blacklistedIPs.delete(ipAddress);
    whitelistedIPs.add(ipAddress);
  }
  res.json({
    success: true,
    blacklist: Array.from(blacklistedIPs),
    whitelist: Array.from(whitelistedIPs)
  });
});

app.post("/api/lists/remove", (req, res) => {
  const { listType, ipAddress } = req.body;
  if (listType === "blacklist") {
    blacklistedIPs.delete(ipAddress);
  } else if (listType === "whitelist") {
    whitelistedIPs.delete(ipAddress);
  }
  res.json({
    success: true,
    blacklist: Array.from(blacklistedIPs),
    whitelist: Array.from(whitelistedIPs)
  });
});

// Industry-Grade AI Model Integration endpoint
// Uses Gemini API to evaluate packet threat context or suggest optimized custom rules
app.post("/api/ai/analyze-packet", async (req, res) => {
  const { packetData } = req.body;
  if (!packetData) {
    return res.status(400).json({ error: "Missing packet data parameter for evaluation" });
  }

  try {
    const prompt = `Analyze the following TCP/IP raw packet header and payload parameters. Provide a swift, standard, industry-grade cybersecurity assessment.
Packet Details:
- Source IP: ${packetData.sourceIp}
- Dest IP: ${packetData.destIp}
- Ports: ${packetData.sourcePort} -> ${packetData.destPort}
- Protocol: ${packetData.protocol}
- Payload Segment: "${packetData.payload}"
- Current Simulated Anomaly Score: ${packetData.anomalyScore}

Suggest the following schema response ONLY. Write it as standard JSON parsable output (Do not include other commentary):
{
  "analyzedSeverity": "LOW | MEDIUM | HIGH | CRITICAL",
  "signatureIdentified": "Specific attack signature name or None/Normal Traffic",
  "firewallRecommendation": "ALLOW | BLOCK",
  "explanation": "A concise single-sentence cyber explanation of the traffic anomaly of what this payload implies.",
  "suggestedRuleName": "An elegant descriptive name for an ACL firewall control block"
}`;

    const response = await ai.models.generateContent({
      model: "gemini-3.5-flash",
      contents: prompt,
      config: {
        responseMimeType: "application/json"
      }
    });

    const aiText = response.text;
    res.json(JSON.parse(aiText));
  } catch (err: any) {
    // Graceful fallback to simulated rule generation engine if Gemini API feels transient
    const baselineAnomaly = packetData.anomalyScore || 0;
    let severity = "LOW";
    let rec = "ALLOW";
    let explanation = "Packet parameters correspond with normal sandbox diagnostic payload patterns.";
    let ruleName = `Secure ingress from ${packetData.sourceIp}`;

    if (baselineAnomaly > 75) {
      severity = "CRITICAL";
      rec = "BLOCK";
      explanation = `Suspicious packet structure showing clear ${packetData.threatCategory || 'malicious'} indicators in the application layer payload.`;
      ruleName = `Drop malicious traffic from ${packetData.sourceIp}`;
    }

    res.json({
      analyzedSeverity: severity,
      signatureIdentified: packetData.threatCategory !== 'Normal' ? packetData.threatCategory : "None",
      firewallRecommendation: rec,
      explanation: explanation,
      suggestedRuleName: ruleName
    });
  }
});

// Mount Vite middleware for production and development flows
async function startServer() {
  if (process.env.NODE_ENV !== "production") {
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: "spa",
    });
    app.use(vite.middlewares);
  } else {
    const distPath = path.join(process.cwd(), 'dist');
    app.use(express.static(distPath));
    app.get('*', (req, res) => {
      res.sendFile(path.join(distPath, 'index.html'));
    });
  }

  app.listen(PORT, "0.0.0.0", () => {
    console.log(`Intelligent Firewall Monitor backend active on http://0.0.0.0:${PORT}`);
  });
}

startServer();
