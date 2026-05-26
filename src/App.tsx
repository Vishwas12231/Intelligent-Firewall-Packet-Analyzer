import React from 'react';
import { 
  Shield, 
  Activity, 
  AlertTriangle, 
  Server, 
  Database, 
  Terminal, 
  Cpu, 
  CheckCircle, 
  Sparkles,
  RefreshCw,
  Search,
  Filter,
  Download,
  Trash2,
  Lock,
  Compass,
  FileText
} from 'lucide-react';
import { 
  AreaChart, Area, 
  BarChart, Bar, 
  LineChart, Line, 
  XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer,
  PieChart, Pie, Cell
} from 'recharts';
import { motion, AnimatePresence } from 'motion/react';
import { Packet, FirewallRule, SecurityAlert, BlockedAttack, TrafficStats } from './types';

export default function App() {
  const [activeTab, setActiveTab] = React.useState<'dashboard' | 'packets' | 'firewall' | 'alerts' | 'blacklist' | 'education'>('dashboard');
  
  // Realtime States
  const [packets, setPackets] = React.useState<Packet[]>([]);
  const [isCapturing, setIsCapturing] = React.useState(true);
  const [firewallRules, setFirewallRules] = React.useState<FirewallRule[]>([]);
  const [alerts, setAlerts] = React.useState<SecurityAlert[]>([]);
  const [blockedAttacks, setBlockedAttacks] = React.useState<BlockedAttack[]>([]);
  const [blacklist, setBlacklist] = React.useState<string[]>([]);
  const [whitelist, setWhitelist] = React.useState<string[]>([]);
  const [isRefreshing, setIsRefreshing] = React.useState(false);
  
  // Filters
  const [selectedProtocolFilter, setSelectedProtocolFilter] = React.useState<string>('ALL');
  const [selectedThreatFilter, setSelectedThreatFilter] = React.useState<string>('ALL');
  const [searchQuery, setSearchQuery] = React.useState<string>('');
  
  // Interactive Packet Inspector / AI Modal Tool State
  const [selectedPacket, setSelectedPacket] = React.useState<Packet | null>(null);
  const [isLoadingAiAnalysis, setIsLoadingAiAnalysis] = React.useState(false);
  const [aiAnalysisResult, setAiAnalysisResult] = React.useState<any | null>(null);

  // New Rule Modal Form State
  const [showRuleModal, setShowRuleModal] = React.useState(false);
  const [newRule, setNewRule] = React.useState({
    name: '',
    type: 'BLOCK' as 'ALLOW' | 'BLOCK',
    sourceIP: '',
    destIP: '*',
    port: '',
    protocol: 'ANY' as 'ANY' | 'TCP' | 'UDP' | 'ICMP' | 'HTTP' | 'HTTPS' | 'DNS',
    description: ''
  });

  // Blacklist/Whitelist Addition state
  const [newIpToList, setNewIpToList] = React.useState('');
  const [listTypeSelection, setListTypeSelection] = React.useState<'blacklist' | 'whitelist'>('blacklist');

  // Load backend systems data
  const fetchData = async () => {
    try {
      setIsRefreshing(true);
      const [packetsRes, rulesRes, alertsRes, attacksRes, listsRes] = await Promise.all([
        fetch('/api/packets'),
        fetch('/api/firewall/rules'),
        fetch('/api/alerts'),
        fetch('/api/firewall/attacks'),
        fetch('/api/lists')
      ]);

      if (packetsRes.ok) {
        const data = await packetsRes.json();
        setPackets(data.packets || []);
        setIsCapturing(data.isCapturing);
      }
      if (rulesRes.ok) {
        const data = await rulesRes.json();
        setFirewallRules(data.rules || []);
      }
      if (alertsRes.ok) {
        const data = await alertsRes.json();
        setAlerts(data.alerts || []);
      }
      if (attacksRes.ok) {
        const data = await attacksRes.json();
        setBlockedAttacks(data.blockedAttacks || []);
      }
      if (listsRes.ok) {
        const data = await listsRes.json();
        setBlacklist(data.blacklist || []);
        setWhitelist(data.whitelist || []);
      }
    } catch (err) {
      console.error("Failed to connect to full-stack API server endpoints", err);
    } finally {
      setIsRefreshing(false);
    }
  };

  // Poll for packet updates periodically to simulate active Wireshark capture stream
  React.useEffect(() => {
    fetchData(); // first load

    const pollInterval = setInterval(async () => {
      if (isCapturing) {
        try {
          const packetsRes = await fetch('/api/packets');
          if (packetsRes.ok) {
            const data = await packetsRes.json();
            setPackets(data.packets || []);
          }
          // occasionally poll alerts & attacks so lists keep in sync neatly
          const [alertsRes, attacksRes] = await Promise.all([
            fetch('/api/alerts'),
            fetch('/api/firewall/attacks')
          ]);
          if (alertsRes.ok) {
            const data = await alertsRes.json();
            setAlerts(data.alerts || []);
          }
          if (attacksRes.ok) {
            const data = await attacksRes.json();
            setBlockedAttacks(data.blockedAttacks || []);
          }
        } catch (e) {
          console.warn("Polling connection to engine delayed", e);
        }
      }
    }, 4000);

    return () => clearInterval(pollInterval);
  }, [isCapturing]);

  // Actions Toggle Capture Engine
  const toggleCapture = async () => {
    try {
      const res = await fetch('/api/packets/toggle', { method: 'POST' });
      if (res.ok) {
        const data = await res.json();
        setIsCapturing(data.isCapturing);
      }
    } catch (err) {
      console.error(err);
    }
  };

  // Action Clear Logs
  const clearLogs = async () => {
    try {
      const res = await fetch('/api/packets/clear', { method: 'POST' });
      if (res.ok) {
        setPackets([]);
      }
    } catch (err) {
      console.error(err);
    }
  };

  // Action Add rule
  const handleAddRule = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!newRule.name || !newRule.sourceIP || !newRule.protocol) return;

    try {
      const res = await fetch('/api/firewall/rules', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(newRule)
      });
      if (res.ok) {
        const data = await res.json();
        setFirewallRules(data.rules);
        setShowRuleModal(false);
        setNewRule({
          name: '',
          type: 'BLOCK',
          sourceIP: '',
          destIP: '*',
          port: '',
          protocol: 'ANY',
          description: ''
        });
        // refresh stats
        fetchData();
      }
    } catch (err) {
      console.error(err);
    }
  };

  // Action Toggle Active Rule
  const toggleRule = async (ruleId: string) => {
    try {
      const res = await fetch(`/api/firewall/rules/${ruleId}/toggle`, { method: 'POST' });
      if (res.ok) {
        const data = await res.json();
        setFirewallRules(data.rules);
      }
    } catch (err) {
      console.error(err);
    }
  };

  // Action Delete rule
  const deleteRule = async (ruleId: string) => {
    try {
      const res = await fetch(`/api/firewall/rules/${ruleId}`, { method: 'DELETE' });
      if (res.ok) {
        const data = await res.json();
        setFirewallRules(data.rules);
      }
    } catch (err) {
      console.error(err);
    }
  };

  // Action Acknowledge alert
  const acknowledgeAlert = async (alertId: string) => {
    try {
      const res = await fetch(`/api/alerts/acknowledge/${alertId}`, { method: 'POST' });
      if (res.ok) {
        const data = await res.json();
        setAlerts(data.alerts);
      }
    } catch (err) {
      console.error(err);
    }
  };

  // Whitelist / Blacklist add action
  const handleAddIpAddress = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!newIpToList) return;
    try {
      const res = await fetch('/api/lists/add', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ listType: listTypeSelection, ipAddress: newIpToList })
      });
      if (res.ok) {
        const data = await res.json();
        setBlacklist(data.blacklist);
        setWhitelist(data.whitelist);
        setNewIpToList('');
      }
    } catch (err) {
      console.error(err);
    }
  };

  // Whitelist / Blacklist remove action
  const handleRemoveIpAddress = async (listType: 'blacklist' | 'whitelist', ip: string) => {
    try {
      const res = await fetch('/api/lists/remove', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ listType, ipAddress: ip })
      });
      if (res.ok) {
        const data = await res.json();
        setBlacklist(data.blacklist);
        setWhitelist(data.whitelist);
      }
    } catch (err) {
      console.error(err);
    }
  };

  // Action Trigger Real intelligent API evaluation using Gemini and Threat Classifier Scoring Systems
  const runAiEnginePrediction = async (packet: Packet) => {
    setIsLoadingAiAnalysis(true);
    setAiAnalysisResult(null);
    try {
      const res = await fetch('/api/ai/analyze-packet', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ packetData: packet })
      });
      if (res.ok) {
        const parsed = await res.json();
        setAiAnalysisResult(parsed);
      }
    } catch (err) {
      console.error(err);
    } finally {
      setIsLoadingAiAnalysis(false);
    }
  };

  // Handler for Exporting Reports gracefully, supporting mock formatting PDF download/CSV to browser
  const handleExportCSV = () => {
    const headers = "ID,Timestamp,Source IP,Dest IP,Protocol,Size,Threat Category,Status,Anomaly Score\n";
    const rows = packets.map(p => 
      `"${p.id}","${p.timestamp}","${p.sourceIp}","${p.destIp}","${p.protocol}",${p.size},"${p.threatCategory}","${p.status}",${p.anomalyScore}`
    ).join("\n");
    
    const blob = new Blob([headers + rows], { type: 'text/csv;charset=utf-8;' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.setAttribute("href", url);
    link.setAttribute("download", `Firewall_Traffic_Report_${new Date().toISOString().substring(0, 10)}.csv`);
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
  };

  // Calculate high quality reactive statistics from live log database state
  const stats: TrafficStats = React.useMemo(() => {
    const total = packets.length;
    const blocked = packets.filter(p => p.status === 'Blocked').length;
    const alertCount = alerts.filter(a => !a.acknowledged).length;
    const avgSize = total > 0 ? Math.round(packets.reduce((acc, curr) => acc + curr.size, 0) / total) : 0;

    const protocols = { TCP: 0, UDP: 0, ICMP: 0, HTTP: 0, HTTPS: 0, DNS: 0 };
    const attacks = { 'DDoS': 0, 'Brute Force': 0, 'Port Scan': 0, 'SQL Injection': 0, 'Other Anomaly': 0 };

    packets.forEach(p => {
      if (p.protocol in protocols) {
        protocols[p.protocol as keyof typeof protocols]++;
      }
      
      if (p.threatCategory === 'DDoS Attempt') attacks['DDoS']++;
      else if (p.threatCategory === 'Brute Force') attacks['Brute Force']++;
      else if (p.threatCategory === 'Port Scan') attacks['Port Scan']++;
      else if (p.threatCategory === 'SQL Injection') attacks['SQL Injection']++;
      else if (p.threatCategory === 'Anomaly') attacks['Other Anomaly']++;
    });

    return {
      totalPackets: total,
      blockedPackets: blocked,
      averagePacketSize: avgSize,
      alertCount,
      protocolDistribution: protocols,
      attackDistribution: attacks
    };
  }, [packets, alerts]);

  // Transform protocols distribution schema object to recharts-friendly array
  const protocolChartData = Object.entries(stats.protocolDistribution).map(([name, value]) => ({
    name,
    value
  }));

  // Threat score trend analysis lines charts (latest 30 packets anomaly scoring behavior)
  const scoreTrendData = packets.slice(0, 20).reverse().map((p, idx) => ({
    name: idx,
    score: p.anomalyScore,
    ip: p.sourceIp,
    protocol: p.protocol,
    type: p.threatCategory
  }));

  // Filtering Packets list logic
  const filteredPackets = React.useMemo(() => {
    return packets.filter(p => {
      const matchProtocol = selectedProtocolFilter === 'ALL' || p.protocol === selectedProtocolFilter;
      const matchThreat = selectedThreatFilter === 'ALL' || 
                           (selectedThreatFilter === 'THREATS' && p.threatCategory !== 'Normal') ||
                           p.threatCategory === selectedThreatFilter;
      const matchSearch = p.sourceIp.includes(searchQuery) || 
                          p.destIp.includes(searchQuery) || 
                          p.payload.toLowerCase().includes(searchQuery.toLowerCase());
      return matchProtocol && matchThreat && matchSearch;
    });
  }, [packets, selectedProtocolFilter, selectedThreatFilter, searchQuery]);

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 flex flex-col font-sans selection:bg-cyan-500 selection:text-slate-900">
      
      {/* Dynamic Header Alert Notice Bar */}
      {alerts.some(a => !a.acknowledged && a.severity === 'CRITICAL') && (
        <div className="bg-gradient-to-r from-red-600 via-rose-600 to-amber-600 text-white px-4 py-2 text-xs md:text-sm font-semibold flex items-center justify-between shadow-lg">
          <div className="flex items-center gap-2">
            <span className="flex h-2 w-2 relative">
              <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-white opacity-75"></span>
              <span className="relative inline-flex rounded-full h-2 w-2 bg-white"></span>
            </span>
            <AlertTriangle className="h-4 w-4 shrink-0" />
            <span>CRITICAL INTRUSION INCIDENT(S) DETECTED: Automated firewall rules currently dropping hazardous payloads.</span>
          </div>
          <button 
            onClick={() => setActiveTab('alerts')} 
            className="hover:underline bg-white/20 px-2 py-0.5 rounded text-[11px] transition"
          >
            Investigate Alert Incident
          </button>
        </div>
      )}

      {/* Main App Navigation Brand Banner */}
      <header className="border-b border-slate-900 bg-slate-950/80 backdrop-blur-md sticky top-0 z-40">
        <div className="max-w-7xl mx-auto px-4 py-3 flex flex-col md:flex-row justify-between items-center gap-4">
          
          <div className="flex items-center gap-3">
            <div className="bg-gradient-to-tr from-cyan-500 to-indigo-600 p-2 rounded-xl text-slate-950 shadow-md shadow-indigo-500/10">
              <Shield className="h-6 w-6 stroke-[2.5]" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h1 className="text-lg font-bold tracking-tight text-white font-sans sm:text-xl">AEGIS-ENGINE</h1>
                <span className="bg-emerald-500/10 text-emerald-400 text-[10px] px-1.5 py-0.5 rounded font-mono border border-emerald-400/20">
                  SECURE ACTIVE
                </span>
              </div>
              <p className="text-xs text-slate-400">Intelligent Threat Prevention System & Network Stream Analyzer</p>
            </div>
          </div>

          <nav className="flex items-center gap-1 bg-slate-900/50 p-1 rounded-lg border border-slate-800">
            <button 
              onClick={() => setActiveTab('dashboard')}
              className={`px-3 py-1.5 rounded-md text-xs font-semibold transition flex items-center gap-1.5 ${activeTab === 'dashboard' ? 'bg-cyan-500/15 text-cyan-400 border border-cyan-400/20' : 'text-slate-400 hover:text-slate-200'}`}
            >
              <Activity className="h-3.5 w-3.5" />
              Overview
            </button>
            <button 
              onClick={() => setActiveTab('packets')}
              className={`px-3 py-1.5 rounded-md text-xs font-semibold transition flex items-center gap-1.5 ${activeTab === 'packets' ? 'bg-cyan-500/15 text-cyan-400 border border-cyan-400/20' : 'text-slate-400 hover:text-slate-200'}`}
            >
              <Terminal className="h-3.5 w-3.5" />
              Stream
            </button>
            <button 
              onClick={() => setActiveTab('firewall')}
              className={`px-3 py-1.5 rounded-md text-xs font-semibold transition flex items-center gap-1.5 ${activeTab === 'firewall' ? 'bg-cyan-500/15 text-cyan-400 border border-cyan-400/20' : 'text-slate-400 hover:text-slate-200'}`}
            >
              <Lock className="h-3.5 w-3.5" />
              ACL Rules
            </button>
            <button 
              onClick={() => setActiveTab('alerts')}
              className={`px-3 py-1.5 rounded-md text-xs font-semibold transition flex items-center gap-1.5 ${activeTab === 'alerts' ? 'bg-cyan-500/15 text-cyan-400 border border-cyan-400/20' : 'text-slate-400 hover:text-slate-200'}`}
            >
              <AlertTriangle className="h-3.5 w-3.5" />
              Incidents
              {stats.alertCount > 0 && (
                <span className="bg-red-500 text-white text-[9px] px-1 py-0.2 rounded-full font-mono font-bold animate-pulse">
                  {stats.alertCount}
                </span>
              )}
            </button>
            <button 
              onClick={() => setActiveTab('blacklist')}
              className={`px-3 py-1.5 rounded-md text-xs font-semibold transition flex items-center gap-1.5 ${activeTab === 'blacklist' ? 'bg-cyan-500/15 text-cyan-400 border border-cyan-400/20' : 'text-slate-400 hover:text-slate-200'}`}
            >
              <Database className="h-3.5 w-3.5" />
              Access Control
            </button>
            <button 
              onClick={() => setActiveTab('education')}
              className={`px-3 py-1.5 rounded-md text-xs font-semibold transition flex items-center gap-1.5 ${activeTab === 'education' ? 'bg-cyan-500/15 text-cyan-400 border border-cyan-400/20' : 'text-slate-400 hover:text-slate-200'}`}
            >
              <Compass className="h-3.5 w-3.5" />
              Documentation
            </button>
          </nav>

          <div className="flex items-center gap-2">
            <button
              onClick={fetchData}
              disabled={isRefreshing}
              className="p-1.5 rounded-lg border border-slate-800 bg-slate-900 text-slate-400 hover:text-slate-200 hover:bg-slate-800 transition disabled:opacity-50"
              title="Manual Poll Status"
            >
              <RefreshCw className={`h-4 w-4 ${isRefreshing ? 'animate-spin' : ''}`} />
            </button>

            {/* Quick Engine Status Controller */}
            <button
              onClick={toggleCapture}
              className={`px-3 py-1.5 rounded-lg text-xs font-semibold transition flex items-center gap-2 border ${
                isCapturing 
                  ? 'bg-emerald-500/10 text-emerald-400 border-emerald-400/20 hover:bg-emerald-500/20'
                  : 'bg-red-500/15 text-red-400 border-red-500/20 hover:bg-red-500/25'
              }`}
            >
              <span className={`h-2.5 w-2.5 rounded-full ${isCapturing ? 'bg-emerald-400 animate-pulse' : 'bg-red-400'}`} />
              {isCapturing ? 'Capture Ingress: Active' : 'Capture Stopped'}
            </button>
          </div>

        </div>
      </header>

      {/* Main Core Layout Panels Container */}
      <main className="flex-1 max-w-7xl w-full mx-auto p-4 flex flex-col gap-6">

        {/* Real-time Widget Metrics Strip */}
        <section className="grid grid-cols-2 lg:grid-cols-4 gap-4">
          
          <div className="bg-slate-900/60 border border-slate-800/80 p-4 rounded-xl flex items-center justify-between">
            <div>
              <p className="text-[10px] uppercase tracking-wider text-slate-400 font-mono">Stream Packet Buffer</p>
              <h3 className="text-2xl font-bold tracking-tight text-white mt-1">{stats.totalPackets}</h3>
              <p className="text-[10px] text-cyan-400 mt-1 flex items-center gap-1">
                <span>Active FIFO circular queue</span>
              </p>
            </div>
            <div className="bg-cyan-500/10 p-2.5 rounded-lg text-cyan-400 border border-cyan-400/10">
              <Activity className="h-5 w-5" />
            </div>
          </div>

          <div className="bg-slate-900/60 border border-slate-800/80 p-4 rounded-xl flex items-center justify-between">
            <div>
              <p className="text-[10px] uppercase tracking-wider text-slate-400 font-mono">IPS Blocks Engaged</p>
              <h3 className="text-2xl font-bold tracking-tight text-rose-400 mt-1">{stats.blockedPackets}</h3>
              <p className="text-[10px] text-rose-500 mt-1 flex items-center gap-1 font-mono">
                <span>{packets.length > 0 ? Math.round((stats.blockedPackets / packets.length)*100) : 0}% mitigation rate</span>
              </p>
            </div>
            <div className="bg-rose-500/10 p-2.5 rounded-lg text-rose-400 border border-rose-400/10">
              <Shield className="h-5 w-5" />
            </div>
          </div>

          <div className="bg-slate-900/60 border border-slate-800/80 p-4 rounded-xl flex items-center justify-between">
            <div>
              <p className="text-[10px] uppercase tracking-wider text-slate-400 font-mono">Active Firewall Rules</p>
              <h3 className="text-2xl font-bold tracking-tight text-indigo-400 mt-1">{firewallRules.filter(r => r.isActive).length}</h3>
              <p className="text-[10px] text-slate-400 mt-1 flex items-center gap-1">
                <span>Total compiled ACL: {firewallRules.length}</span>
              </p>
            </div>
            <div className="bg-indigo-500/10 p-2.5 rounded-lg text-indigo-400 border border-indigo-400/10">
              <Server className="h-5 w-5" />
            </div>
          </div>

          <div className="bg-slate-900/60 border border-slate-800/80 p-4 rounded-xl flex items-center justify-between">
            <div>
              <p className="text-[10px] uppercase tracking-wider text-slate-400 font-mono">Threat Alarm Queue</p>
              <h3 className={`text-2xl font-bold tracking-tight mt-1 ${stats.alertCount > 0 ? 'text-amber-400' : 'text-emerald-400'}`}>
                {stats.alertCount}
              </h3>
              <p className="text-[10px] text-slate-400 mt-1 flex items-center gap-1">
                <span>Urgent raw system flags</span>
              </p>
            </div>
            <div className={`p-2.5 rounded-lg border ${stats.alertCount > 0 ? 'bg-amber-500/10 text-amber-400 border-amber-400/10' : 'bg-emerald-500/10 text-emerald-400 border-emerald-400/10'}`}>
              <AlertTriangle className="h-5 w-5" />
            </div>
          </div>

        </section>

        {/* Tab Selection Layout switcher */}
        <AnimatePresence mode="wait">
          {activeTab === 'dashboard' && (
            <motion.div 
              key="dashboard"
              initial={{ opacity: 0, y: 5 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, y: -5 }}
              transition={{ duration: 0.15 }}
              className="space-y-6"
            >
              {/* Dashboard Layout row */}
              <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
                
                {/* Visual Section: Network Stream Realtime Flow Intensity */}
                <div className="bg-slate-900/40 border border-slate-900/80 rounded-xl p-5 lg:col-span-2 flex flex-col justify-between">
                  <div>
                    <div className="flex justify-between items-center mb-4">
                      <div>
                        <h4 className="text-sm font-semibold text-white">Threat Stream Score Trends</h4>
                        <p className="text-xs text-slate-400">Chronological live traffic payload risk levels</p>
                      </div>
                      <span className="bg-cyan-500/10 text-cyan-400 text-[10px] px-2 py-0.5 rounded-full font-mono border border-cyan-400/20">
                        Live Tracking Trace
                      </span>
                    </div>

                    {scoreTrendData.length > 0 ? (
                      <div className="h-64 mt-4 w-full">
                        <ResponsiveContainer width="100%" height="100%">
                          <AreaChart data={scoreTrendData}>
                            <defs>
                              <linearGradient id="scoreColor" x1="0" y1="0" x2="0" y2="1">
                                <stop offset="5%" stopColor="#06b6d4" stopOpacity={0.2}/>
                                <stop offset="95%" stopColor="#06b6d4" stopOpacity={0}/>
                              </linearGradient>
                            </defs>
                            <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" />
                            <XAxis dataKey="name" stroke="#64748b" fontSize={11} label={{ value: 'Packets (Chronological FIFO)', position: 'insideBottom', offset: -5 }} />
                            <YAxis stroke="#64748b" fontSize={11} domain={[0, 100]} />
                            <Tooltip 
                              contentStyle={{ backgroundColor: '#0f172a', borderColor: '#1e293b', color: '#fff' }}
                              labelFormatter={(lbl) => `Stream Packet ID: #${lbl}`}
                            />
                            <Area type="monotone" dataKey="score" stroke="#06b6d4" strokeWidth={2} fillOpacity={1} fill="url(#scoreColor)" name="Anomaly Factor %" />
                          </AreaChart>
                        </ResponsiveContainer>
                      </div>
                    ) : (
                      <div className="h-64 flex flex-col items-center justify-center border border-dashed border-slate-800 rounded-lg p-5">
                        <Terminal className="h-8 w-8 text-slate-600 mb-2" />
                        <p className="text-xs text-slate-400 text-center">No trace trace statistics available yet. Tap Capure on top-right to initiate streams.</p>
                      </div>
                    )}
                  </div>
                  
                  <div className="pt-4 border-t border-slate-900 flex items-center justify-between text-xs text-slate-400 font-mono">
                    <span>Mean packet transmission frequency: Fast (~3000ms sandbox buffer updates)</span>
                    <span className="text-slate-500">Node JS Ingress Handler active</span>
                  </div>
                </div>

                {/* Protocol Distribution Ratio Chart */}
                <div className="bg-slate-900/40 border border-slate-900/80 rounded-xl p-5 flex flex-col justify-between">
                  <div>
                    <h4 className="text-sm font-semibold text-white mb-2">Protocol Multiplex Ratio</h4>
                    <p className="text-xs text-slate-400 mb-4">Relative frequency distribution across network protocols</p>

                    <div className="h-56 mt-4 flex items-center justify-center relative">
                      <ResponsiveContainer width="100%" height="100%">
                        <BarChart data={protocolChartData} layout="vertical">
                          <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" />
                          <XAxis type="number" stroke="#64748b" fontSize={10} />
                          <YAxis dataKey="name" type="category" stroke="#64748b" fontSize={10} width={40} />
                          <Tooltip contentStyle={{ backgroundColor: '#0f172a', borderColor: '#1e293b', color: '#fff' }} />
                          <Bar dataKey="value" fill="#6366f1" radius={[0, 4, 4, 0]} name="Packets Count">
                            {protocolChartData.map((entry, index) => {
                              const colors = ['#3b82f6', '#10b981', '#f59e0b', '#ec4899', '#6366f1', '#14b8a6'];
                              return <Cell key={`cell-${index}`} fill={colors[index % colors.length]} />;
                            })}
                          </Bar>
                        </BarChart>
                      </ResponsiveContainer>
                    </div>
                  </div>

                  <div className="bg-slate-950 p-3 rounded-lg border border-slate-900 text-xs flex justify-between items-center text-slate-400 mt-2 font-mono">
                    <span>Mean Packets Size:</span>
                    <span className="text-white font-bold">{stats.averagePacketSize} bytes</span>
                  </div>
                </div>

              </div>

              {/* Sub-Layout Block: Intrusion Prevention Threat Types Analysis & Live Alerts Panel */}
              <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                
                {/* Left Widget: Current Identified Malicious Traffic Distribution */}
                <div className="bg-slate-900/40 border border-slate-900/80 rounded-xl p-5">
                  <h4 className="text-sm font-semibold text-white mb-1">Threat Assessment Breakdown</h4>
                  <p className="text-xs text-slate-400 mb-4">Intrusion classification logged across simulated system breaches</p>

                  <div className="grid grid-cols-2 gap-4">
                    <div className="space-y-3">
                      <div className="p-3 bg-red-950/20 rounded-lg border border-red-500/10">
                        <span className="text-[10px] text-slate-400 font-mono">DDoS Attacks</span>
                        <div className="flex justify-between items-baseline mt-1">
                          <span className="text-lg font-bold text-red-400">{stats.attackDistribution['DDoS']}</span>
                          <span className="text-xs text-slate-500">blocks</span>
                        </div>
                      </div>

                      <div className="p-3 bg-amber-950/20 rounded-lg border border-amber-500/10">
                        <span className="text-[10px] text-slate-400 font-mono">Port Scanning</span>
                        <div className="flex justify-between items-baseline mt-1">
                          <span className="text-lg font-bold text-amber-400">{stats.attackDistribution['Port Scan']}</span>
                          <span className="text-xs text-slate-500">scans</span>
                        </div>
                      </div>
                    </div>

                    <div className="space-y-3">
                      <div className="p-3 bg-indigo-950/20 rounded-lg border border-indigo-500/10">
                        <span className="text-[10px] text-slate-400 font-mono">Brute Force IPs</span>
                        <div className="flex justify-between items-baseline mt-1">
                          <span className="text-lg font-bold text-indigo-400">{stats.attackDistribution['Brute Force']}</span>
                          <span className="text-xs text-slate-500">dropped</span>
                        </div>
                      </div>

                      <div className="p-3 bg-orange-950/20 rounded-lg border border-orange-500/10">
                        <span className="text-[10px] text-slate-400 font-mono">SQL Inject Payload</span>
                        <div className="flex justify-between items-baseline mt-1">
                          <span className="text-lg font-bold text-orange-400">{stats.attackDistribution['SQL Injection']}</span>
                          <span className="text-xs text-slate-500">payloads</span>
                        </div>
                      </div>
                    </div>
                  </div>

                  {/* High level AI Explanation Banner */}
                  <div className="mt-4 p-3 bg-slate-950 rounded-lg border border-slate-900 flex gap-2.5 text-xs text-slate-450 items-start">
                    <Cpu className="h-4 w-4 text-cyan-400 shrink-0 mt-0.5" />
                    <div>
                      <p className="text-slate-200 font-medium">Real-time Statistical Engine Status</p>
                      <p className="text-[11px] text-slate-400 mt-1 leading-relaxed">
                        Evaluating patterns with deep inspection logic, capturing anomalies under Bayesian threat index algorithms. Fully adaptable firewall triggers immediate automated rules block.
                      </p>
                    </div>
                  </div>
                </div>

                {/* Right Widget: Active Blocked Attacks History log */}
                <div className="bg-slate-900/40 border border-slate-900/80 rounded-xl p-5 flex flex-col justify-between">
                  <div>
                    <div className="flex justify-between items-center mb-3">
                      <h4 className="text-sm font-semibold text-white">Blocked Attack Logs</h4>
                      <button 
                        onClick={() => setActiveTab('alerts')} 
                        className="text-xs text-cyan-400 hover:underline flex items-center gap-1 font-mono"
                      >
                        All incidents &rarr;
                      </button>
                    </div>
                    <p className="text-xs text-slate-400 mb-4">IPS Active block history for stateful traffic enforcement</p>

                    <div className="space-y-2.5 max-h-[220px] overflow-y-auto">
                      {blockedAttacks.length > 0 ? (
                        blockedAttacks.slice(0, 4).map((block) => (
                          <div 
                            key={block.id} 
                            className="bg-slate-950 p-3 rounded-lg border border-rose-500/10 flex items-center justify-between text-xs transition hover:border-rose-500/20"
                          >
                            <div className="space-y-1">
                              <div className="flex items-center gap-2">
                                <span className="bg-red-500/20 text-red-500 font-mono text-[9px] px-1 rounded">
                                  {block.attackType}
                                </span>
                                <span className="text-[10px] text-slate-500 font-mono">
                                  {new Date(block.timestamp).toLocaleTimeString()}
                                </span>
                              </div>
                              <div className="text-slate-300 font-mono mt-1">
                                IP: <span className="text-white font-semibold">{block.sourceIP}</span> &rarr; {block.port} ({block.protocol})
                              </div>
                            </div>
                            <span className="text-[10px] uppercase font-mono text-rose-400 bg-rose-400/5 px-2 py-0.5 rounded border border-rose-400/10">
                              Dropped
                            </span>
                          </div>
                        ))
                      ) : (
                        <div className="p-8 text-center text-slate-500 text-xs">
                          No blocked attacks logged since capture trace started. Active state secure.
                        </div>
                      )}
                    </div>
                  </div>

                  <div className="text-[11px] text-slate-400 italic mt-3 pt-3 border-t border-slate-900">
                    Aegis stateful packet filter drops blacklisted source traffic at Layer 3 interface directly.
                  </div>
                </div>

              </div>

              {/* Action Banner to Packet Inspector */}
              <div className="bg-gradient-to-r from-cyan-600/10 to-indigo-600/10 border border-cyan-500/20 rounded-xl p-5 flex flex-col md:flex-row justify-between items-center gap-4">
                <div className="flex items-start gap-3">
                  <Sparkles className="h-5 w-5 text-cyan-400 shrink-0 mt-0.5" />
                  <div>
                    <h5 className="text-sm font-semibold text-white">Full Packet Inspection Feed Ready</h5>
                    <p className="text-xs text-slate-300 mt-1 max-w-xl">
                      Inspect individual frames directly, explore raw hexadecimal payload structures, and utilize AI integration models to evaluate traffic vulnerabilities and auto-generate firewall code rules.
                    </p>
                  </div>
                </div>
                <button 
                  onClick={() => setActiveTab('packets')}
                  className="px-4 py-2 bg-gradient-to-r from-cyan-500 to-blue-600 text-slate-950 rounded-lg text-xs font-bold shadow-md hover:opacity-90 active:scale-95 transition whitespace-nowrap"
                >
                  Inspect Packets Live
                </button>
              </div>

            </motion.div>
          )}

          {activeTab === 'packets' && (
            <motion.div 
              key="packets"
              initial={{ opacity: 0, y: 5 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, y: -5 }}
              transition={{ duration: 0.15 }}
              className="space-y-6"
            >
              
              {/* Filter Configuration Strip */}
              <div className="bg-slate-900 border border-slate-800 rounded-xl p-4 flex flex-col md:flex-row justify-between items-center gap-4">
                
                <div className="flex flex-wrap items-center gap-3 w-full md:w-auto">
                  
                  {/* Search */}
                  <div className="relative w-full sm:w-64">
                    <Search className="absolute left-2.5 top-2.5 h-3.5 w-3.5 text-slate-500" />
                    <input 
                      type="text" 
                      placeholder="Search source IP, payload..."
                      value={searchQuery}
                      onChange={(e) => setSearchQuery(e.target.value)}
                      className="bg-slate-950 border border-slate-800 text-xs rounded-lg pl-8 pr-3 py-2 w-full focus:outline-none focus:border-cyan-500 transition text-slate-350"
                    />
                  </div>

                  {/* Protocol selection */}
                  <div className="flex items-center gap-1.5">
                    <Filter className="h-3.5 w-3.5 text-slate-400" />
                    <span className="text-xs text-slate-400">Protocol:</span>
                    <select 
                      value={selectedProtocolFilter}
                      onChange={(e) => setSelectedProtocolFilter(e.target.value)}
                      className="bg-slate-950 border border-slate-800 text-xs rounded-lg px-2.5 py-1.5 text-slate-300 focus:outline-none focus:border-cyan-500"
                    >
                      <option value="ALL">All Protocols</option>
                      <option value="TCP">TCP Only</option>
                      <option value="UDP">UDP Only</option>
                      <option value="ICMP">ICMP Only</option>
                      <option value="HTTP">HTTP</option>
                      <option value="HTTPS">HTTPS</option>
                      <option value="DNS">DNS</option>
                    </select>
                  </div>

                  {/* Threat classification selection */}
                  <div className="flex items-center gap-1.5">
                    <select 
                      value={selectedThreatFilter}
                      onChange={(e) => setSelectedThreatFilter(e.target.value)}
                      className="bg-slate-950 border border-slate-800 text-xs rounded-lg px-2.5 py-1.5 text-slate-300 focus:outline-none focus:border-cyan-500"
                    >
                      <option value="ALL">All Traffic Categories</option>
                      <option value="THREATS">Identified Malicious/Threats</option>
                      <option value="DDoS Attempt">DDoS Attacks Only</option>
                      <option value="Port Scan">Nmap scans</option>
                      <option value="Brute Force">Brute force SSH</option>
                      <option value="SQL Injection">SQL Injection attempts</option>
                      <option value="Normal">Normal Traffic</option>
                    </select>
                  </div>

                </div>

                <div className="flex items-center gap-2 shrink-0 w-full md:w-auto justify-end">
                  <button 
                    onClick={handleExportCSV}
                    className="px-3 py-2 bg-slate-950 border border-slate-800 hover:bg-slate-800 text-xs font-semibold rounded-lg text-slate-300 flex items-center gap-1.5 transition"
                  >
                    <Download className="h-3.5 w-3.5" />
                    Export CSV Report
                  </button>
                  <button 
                    onClick={clearLogs}
                    className="px-3 py-2 bg-slate-950 border border-slate-800 hover:bg-red-500/10 text-slate-400 hover:text-red-300 text-xs font-semibold rounded-lg flex items-center gap-1.5 transition"
                  >
                    <Trash2 className="h-3.5 w-3.5" />
                    Reset Buffer
                  </button>
                </div>

              </div>

              {/* Major layout splitting block: Realtime logs list + Active Packet detailed inspector panel */}
              <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
                
                {/* Packets Stream table */}
                <div className="lg:col-span-2 space-y-3">
                  <div className="flex justify-between items-center bg-slate-900/60 p-3 rounded-lg border border-slate-800/80">
                    <span className="text-xs font-semibold text-white font-mono">
                      Filtered: {filteredPackets.length} of {packets.length} buffers
                    </span>
                    <span className="text-[10px] text-slate-500">
                      Tap a row to inspect hex payload details or trigger AI rules recommendation.
                    </span>
                  </div>

                  <div className="bg-slate-900/20 border border-slate-900 rounded-xl overflow-hidden">
                    <div className="overflow-x-auto">
                      <table className="w-full text-left text-xs border-collapse">
                        <thead>
                          <tr className="border-b border-slate-900 bg-slate-950 text-slate-400 font-mono text-[10px] uppercase">
                            <th className="py-3 px-4">Protocol</th>
                            <th className="py-3 px-3">Orig IP / Port</th>
                            <th className="py-3 px-3">Dest IP / Port</th>
                            <th className="py-3 px-3 text-center">Threat Assessment</th>
                            <th className="py-3 px-3 text-center">Risk Score</th>
                            <th className="py-3 px-4 text-center">Action</th>
                          </tr>
                        </thead>
                        <tbody className="divide-y divide-slate-900">
                          {filteredPackets.length > 0 ? (
                            filteredPackets.map((pkt) => (
                              <tr 
                                key={pkt.id}
                                onClick={() => {
                                  setSelectedPacket(pkt);
                                  setAiAnalysisResult(null);
                                }}
                                className={`hover:bg-slate-900/60 transition cursor-pointer ${selectedPacket?.id === pkt.id ? 'bg-slate-900 border-l-2 border-cyan-400' : ''}`}
                              >
                                
                                {/* Protocol Badge */}
                                <td className="py-3 px-4">
                                  <span className={`px-2 py-0.5 rounded font-mono text-[10px] font-bold ${
                                    pkt.protocol === 'TCP' ? 'bg-blue-500/20 text-blue-400 ring-1 ring-blue-500/30' :
                                    pkt.protocol === 'UDP' ? 'bg-amber-500/20 text-amber-500 ring-1 ring-amber-500/30' :
                                    pkt.protocol === 'ICMP' ? 'bg-purple-500/20 text-purple-400 ring-1 ring-purple-500/30' :
                                    pkt.protocol === 'HTTPS' ? 'bg-emerald-500/20 text-emerald-400 ring-1 ring-emerald-500/30' :
                                    'bg-indigo-500/20 text-indigo-400 ring-1 ring-indigo-500/30'
                                  }`}>
                                    {pkt.protocol}
                                  </span>
                                </td>

                                {/* Orig / Source */}
                                <td className="py-3 px-3 font-mono">
                                  <div className="text-slate-250 font-semibold">{pkt.sourceIp}</div>
                                  <div className="text-[10px] text-slate-500">Port {pkt.sourcePort}</div>
                                </td>

                                {/* Destination */}
                                <td className="py-3 px-3 font-mono">
                                  <div className="text-slate-300">{pkt.destIp}</div>
                                  <div className="text-[10px] text-slate-500">Port {pkt.destPort}</div>
                                </td>

                                {/* Threat Tag */}
                                <td className="py-3 px-3 text-center">
                                  <span className={`px-2 py-0.5 rounded-full text-[10px] font-medium font-sans ${
                                    pkt.threatCategory === 'Normal' ? 'bg-slate-800 text-slate-400' :
                                    pkt.threatCategory === 'DDoS Attempt' ? 'bg-red-500/20 text-red-500 border border-red-500/20' :
                                    pkt.threatCategory === 'Port Scan' ? 'bg-amber-500/20 text-amber-400 border border-amber-400/20' :
                                    'bg-indigo-500/20 text-indigo-400 border border-indigo-500/20'
                                  }`}>
                                    {pkt.threatCategory}
                                  </span>
                                </td>

                                {/* Threat Score Factor */}
                                <td className="py-3 px-3 text-center font-mono">
                                  <span className={`font-bold ${
                                    pkt.anomalyScore > 75 ? 'text-red-400' :
                                    pkt.anomalyScore > 40 ? 'text-amber-400' :
                                    'text-emerald-400'
                                  }`}>
                                    {pkt.anomalyScore}/100
                                  </span>
                                </td>

                                {/* Interactive firewall rules response tag */}
                                <td className="py-3 px-4 text-center">
                                  <span className={`text-[10px] uppercase font-mono px-2 py-0.5 rounded font-extrabold ${
                                    pkt.status === 'Allowed' 
                                      ? 'bg-emerald-400/10 text-emerald-400 border border-emerald-400/20' 
                                      : 'bg-red-500/10 text-red-500 border border-red-500/20 animate-pulse'
                                  }`}>
                                    {pkt.status}
                                  </span>
                                </td>

                              </tr>
                            ))
                          ) : (
                            <tr>
                              <td colSpan={6} className="py-12 text-center text-slate-500">
                                No packets currently matching filter criteria. Adjust selectors or start capture engine.
                              </td>
                            </tr>
                          )}
                        </tbody>
                      </table>
                    </div>
                  </div>
                </div>

                {/* Packet payload analyzer & Gemini powered intelligent detection sidebar */}
                <div className="space-y-4">
                  <div className="bg-slate-900/60 border border-slate-800 rounded-xl p-5 sticky top-20">
                    
                    <div className="flex items-center gap-2 pb-3 mb-4 border-b border-slate-800">
                      <Terminal className="h-4 w-4 text-cyan-400" />
                      <h4 className="text-sm font-semibold text-white">Stateful Inspector Pane</h4>
                    </div>

                    {selectedPacket ? (
                      <div className="space-y-4 text-xs">
                        
                        <div className="bg-slate-950 p-3 rounded-lg border border-slate-800 space-y-1.5 font-mono">
                          <div className="flex justify-between">
                            <span className="text-slate-500">Stream Ref ID:</span>
                            <span className="text-white font-bold">{selectedPacket.id}</span>
                          </div>
                          <div className="flex justify-between">
                            <span className="text-slate-500">Enforcement Status:</span>
                            <span className={selectedPacket.status === 'Allowed' ? 'text-emerald-400' : 'text-red-400'}>{selectedPacket.status}</span>
                          </div>
                          <div className="flex justify-between">
                            <span className="text-slate-500">Anomaly Factor:</span>
                            <span className="text-white font-bold">{selectedPacket.anomalyScore}%</span>
                          </div>
                          <div className="flex justify-between">
                            <span className="text-slate-500">Header Flag:</span>
                            <span className="text-slate-350">{selectedPacket.flags}</span>
                          </div>
                        </div>

                        {/* Hex payload presentation block standard */}
                        <div>
                          <p className="text-[10px] uppercase font-mono tracking-wider text-slate-500 mb-2">Raw Packet ASCII/Payload Segment:</p>
                          <div className="bg-slate-950 p-3 border border-slate-900 rounded-lg font-mono text-[10.5px] leading-relaxed break-all text-slate-300">
                            {selectedPacket.payload || "NO PAYLOAD DETECTED IN TRANSPARENT LAYER HEADERS."}
                          </div>
                        </div>

                        {/* AI / Generative Assistant Threat Evaluator module */}
                        <div className="p-4 bg-gradient-to-br from-indigo-500/10 to-transparent border border-indigo-500/20 rounded-xl space-y-3">
                          <div className="flex justify-between items-center">
                            <div className="flex items-center gap-1.5 text-indigo-400">
                              <Sparkles className="h-4 w-4" />
                              <span className="font-semibold text-indigo-300">Intelligent Trace Engine</span>
                            </div>
                            <span className="text-[9px] uppercase font-mono tracking-wider text-slate-500">Gemini Live</span>
                          </div>

                          <p className="text-[11px] leading-relaxed text-slate-400">
                            Perform active analysis using fine-tuned intelligence parameters. Evaluates payload triggers and offers optimized firewall rule code structures directly.
                          </p>

                          <button 
                            onClick={() => runAiEnginePrediction(selectedPacket)}
                            disabled={isLoadingAiAnalysis}
                            className="w-full py-2 bg-indigo-600 hover:bg-indigo-500 disabled:opacity-50 text-white rounded-lg font-semibold text-[11px] flex items-center justify-center gap-1.5 shadow-sm transition"
                          >
                            {isLoadingAiAnalysis ? 'Running Threat Analysis...' : 'Consult Intelligent Threat score'}
                          </button>

                          {aiAnalysisResult && (
                            <div className="bg-slate-950 p-3 border border-slate-900 rounded-lg space-y-2 mt-2 leading-relaxed animate-fade-in text-[11px]">
                              <div className="flex justify-between items-center">
                                <span className="font-semibold text-slate-300">AI Threat Level:</span>
                                <span className={`px-1.5 uppercase font-mono text-[9px] font-bold rounded ${
                                  aiAnalysisResult.analyzedSeverity === 'CRITICAL' ? 'bg-red-500/15 text-red-400' :
                                  aiAnalysisResult.analyzedSeverity === 'HIGH' ? 'bg-orange-500/15 text-orange-400' :
                                  'bg-blue-500/15 text-blue-400'
                                }`}>
                                  {aiAnalysisResult.analyzedSeverity}
                                </span>
                              </div>
                              <div>
                                <span className="font-semibold text-slate-400 block mb-0.5">Identified Payload Context:</span>
                                <span className="text-white text-[10.5px] leading-relaxed">{aiAnalysisResult.explanation}</span>
                              </div>
                              <div className="pt-2 border-t border-slate-900 mt-2 space-y-1.5">
                                <span className="text-slate-500 block">Identified Signature:</span>
                                <div className="text-cyan-400 font-mono text-[10px]">{aiAnalysisResult.signatureIdentified}</div>
                              </div>
                              
                              {/* Option to fast path copy rule */}
                              <div className="pt-2">
                                <button
                                  onClick={() => {
                                    setNewRule({
                                      name: aiAnalysisResult.suggestedRuleName || 'AI Auto Blocking Rule',
                                      type: aiAnalysisResult.firewallRecommendation || 'BLOCK',
                                      sourceIP: selectedPacket.sourceIp,
                                      destIP: '*',
                                      port: String(selectedPacket.destPort),
                                      protocol: selectedPacket.protocol as any,
                                      description: 'Auto integrated via intelligent rule generator module.'
                                    });
                                    setActiveTab('firewall');
                                    setShowRuleModal(true);
                                  }}
                                  className="w-full py-1.5 bg-slate-900 hover:bg-slate-800 text-cyan-400 rounded border border-cyan-400/20 font-mono text-[10px] transition"
                                >
                                  Deploy Custom Firewall ACL Rule
                                </button>
                              </div>
                            </div>
                          )}
                        </div>

                      </div>
                    ) : (
                      <div className="text-center py-12 text-slate-500 text-xs">
                        No packet selected. Click on any log row to open deep stream evaluation window.
                      </div>
                    )}

                  </div>
                </div>

              </div>

            </motion.div>
          )}

          {activeTab === 'firewall' && (
            <motion.div 
              key="firewall"
              initial={{ opacity: 0, y: 5 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, y: -5 }}
              transition={{ duration: 0.15 }}
              className="space-y-6"
            >
              
              {/* Rules Action Header Block */}
              <div className="bg-slate-900/60 border border-slate-900 rounded-xl p-5 flex flex-col md:flex-row justify-between items-center gap-4">
                <div>
                  <h4 className="text-base font-semibold text-white">Access Control ACL Configuration Engine</h4>
                  <p className="text-xs text-slate-400 mt-1">Implement standard stateful firewall rules to bypass or drop packets proactively.</p>
                </div>
                <button 
                  onClick={() => setShowRuleModal(true)}
                  className="px-4 py-2 bg-cyan-500 text-slate-950 font-bold rounded-lg text-xs shadow-md shadow-cyan-500/10 hover:opacity-90 active:scale-95 transition flex items-center gap-1.5"
                >
                  <Lock className="h-3.5 w-3.5" />
                  Create Firewall ACL Rule
                </button>
              </div>

              {/* Active modal dialogue container */}
              {showRuleModal && (
                <div className="bg-slate-900 border border-slate-800 p-5 rounded-xl space-y-4">
                  <div className="flex justify-between items-center pb-2 border-b border-slate-800">
                    <h5 className="text-sm font-semibold text-white flex items-center gap-2">
                       Create Firewall Rule Schema
                    </h5>
                    <button onClick={() => setShowRuleModal(false)} className="text-xs text-slate-500 hover:text-slate-350 font-mono">Cancel</button>
                  </div>

                  <form onSubmit={handleAddRule} className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4 text-xs font-sans">
                    
                    <div className="space-y-1.5">
                      <label className="text-slate-400 font-medium">Descriptive Rule Name</label>
                      <input 
                        type="text" 
                        placeholder="Block DDoS Vector Active"
                        value={newRule.name}
                        onChange={(e) => setNewRule({...newRule, name: e.target.value})}
                        className="w-full bg-slate-950 border border-slate-800 rounded px-3 py-2 text-white focus:outline-none focus:border-cyan-500"
                        required
                      />
                    </div>

                    <div className="space-y-1.5">
                      <label className="text-slate-400 font-medium">Policy Action Action</label>
                      <select 
                        value={newRule.type}
                        onChange={(e) => setNewRule({...newRule, type: e.target.value as any})}
                        className="w-full bg-slate-950 border border-slate-800 rounded px-2.5 py-2 text-white focus:outline-none focus:border-cyan-500"
                      >
                        <option value="BLOCK">BLOCK (Drop incoming packets)</option>
                        <option value="ALLOW">ALLOW (Bypass checks)</option>
                      </select>
                    </div>

                    <div className="space-y-1.5">
                      <label className="text-slate-400 font-medium font-mono">Source Host IP address</label>
                      <input 
                        type="text" 
                        placeholder="185.220.101.5 or *"
                        value={newRule.sourceIP}
                        onChange={(e) => setNewRule({...newRule, sourceIP: e.target.value})}
                        className="w-full bg-slate-950 border border-slate-800 rounded px-3 py-2 text-white font-mono focus:outline-none focus:border-cyan-500"
                        required
                      />
                    </div>

                    <div className="space-y-1.5">
                      <label className="text-slate-400 font-medium">Dest IP Host</label>
                      <input 
                        type="text" 
                        value={newRule.destIP}
                        onChange={(e) => setNewRule({...newRule, destIP: e.target.value})}
                        className="w-full bg-slate-950 border border-slate-800 rounded px-3 py-2 text-slate-400 font-mono focus:outline-none focus:border-cyan-500"
                      />
                    </div>

                    <div className="space-y-1.5">
                      <label className="text-slate-400 font-medium">Traffic Protocol</label>
                      <select 
                        value={newRule.protocol}
                        onChange={(e) => setNewRule({...newRule, protocol: e.target.value as any})}
                        className="w-full bg-slate-950 border border-slate-800 rounded px-2.5 py-2 text-white focus:outline-none focus:border-cyan-500"
                      >
                        <option value="ANY">ANY PROTOCOL</option>
                        <option value="TCP">TCP</option>
                        <option value="UDP">UDP</option>
                        <option value="ICMP">ICMP</option>
                        <option value="HTTP">HTTP</option>
                        <option value="HTTPS">HTTPS</option>
                        <option value="DNS">DNS</option>
                      </select>
                    </div>

                    <div className="space-y-1.5">
                      <label className="text-slate-400 font-medium">Traffic Port Range</label>
                      <input 
                        type="text" 
                        placeholder="e.g. 443 or *"
                        value={newRule.port}
                        onChange={(e) => setNewRule({...newRule, port: e.target.value})}
                        className="w-full bg-slate-950 border border-slate-800 rounded px-3 py-2 text-white font-mono focus:outline-none focus:border-cyan-500"
                      />
                    </div>

                    <div className="space-y-1.5 lg:col-span-3">
                      <label className="text-slate-400 font-medium">Detailed Administrative Notes</label>
                      <input 
                        type="text" 
                        placeholder="Describe risk, signature indicators, or compliance constraints."
                        value={newRule.description}
                        onChange={(e) => setNewRule({...newRule, description: e.target.value})}
                        className="w-full bg-slate-950 border border-slate-800 rounded px-3 py-2 text-white focus:outline-none focus:border-cyan-500"
                      />
                    </div>

                    <div className="lg:col-span-3 pt-3 flex justify-end gap-2">
                      <button 
                        type="submit" 
                        className="px-4 py-2 bg-gradient-to-r from-cyan-500 to-blue-600 font-bold rounded text-slate-950"
                      >
                        Deploy Live ACL Rule Settings
                      </button>
                    </div>

                  </form>
                </div>
              )}

              {/* Rules Grid Panel */}
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                {firewallRules.map((rule) => {
                  const isBlacklistDirect = rule.type === 'BLOCK' && rule.sourceIP !== '*';
                  return (
                    <div 
                      key={rule.id} 
                      className={`p-4 rounded-xl border flex flex-col justify-between ${
                        rule.isActive 
                          ? 'bg-slate-900/60 border-slate-800' 
                          : 'bg-slate-900/10 border-slate-950 opacity-60'
                      }`}
                    >
                      <div className="space-y-2">
                        <div className="flex justify-between items-start">
                          <div>
                            <span className={`px-2 py-0.5 rounded font-mono text-[9px] font-extrabold ${
                              rule.type === 'BLOCK' ? 'bg-red-500/15 text-red-400' : 'bg-emerald-500/15 text-emerald-400'
                            }`}>
                              {rule.type}
                            </span>
                            <h5 className="text-xs font-semibold text-white mt-1.5 leading-relaxed">{rule.name}</h5>
                          </div>
                          
                          <div className="flex items-center gap-1.5">
                            <button
                              onClick={() => toggleRule(rule.id)}
                              className={`text-[10px] font-mono px-2 py-1 rounded transition border ${
                                rule.isActive 
                                  ? 'bg-emerald-500/10 text-emerald-400 border-emerald-400/20 hover:bg-emerald-500/20' 
                                  : 'bg-slate-950 text-slate-500 border-slate-900 hover:text-slate-400'
                              }`}
                            >
                              {rule.isActive ? 'Active' : 'Disabled'}
                            </button>
                            <button
                              onClick={() => deleteRule(rule.id)}
                              className="p-1 text-slate-500 hover:text-red-400 hover:bg-red-500/10 rounded transition"
                              title="Delete rule"
                            >
                              <Trash2 className="h-3.5 w-3.5" />
                            </button>
                          </div>
                        </div>

                        {/* Rules criteria tags */}
                        <div className="grid grid-cols-3 gap-2 bg-slate-950 p-2.5 border border-slate-900 rounded font-mono text-[10px] text-slate-400">
                          <div>
                            <span className="text-slate-650 block text-[9px] uppercase">Src IP</span>
                            <span className="text-slate-200 mt-0.5 block truncate" title={rule.sourceIP}>{rule.sourceIP}</span>
                          </div>
                          <div>
                            <span className="text-slate-650 block text-[9px] uppercase">Protocol</span>
                            <span className="text-slate-200 mt-0.5 block">{rule.protocol}</span>
                          </div>
                          <div>
                            <span className="text-slate-650 block text-[9px] uppercase">Port</span>
                            <span className="text-slate-200 mt-0.5 block">{rule.port}</span>
                          </div>
                        </div>

                        <p className="text-[11px] text-slate-400 leading-relaxed font-sans mt-2">{rule.description}</p>
                      </div>

                      <div className="pt-3 border-t border-slate-900/80 mt-3 flex justify-between items-center text-[10px] text-slate-500 font-mono">
                        <span>Created: {new Date(rule.createdAt).toLocaleDateString()}</span>
                        {isBlacklistDirect && (
                          <span className="text-red-400 font-medium">Triggers hardware Drop</span>
                        )}
                      </div>

                    </div>
                  );
                })}
              </div>

            </motion.div>
          )}

          {activeTab === 'alerts' && (
            <motion.div 
              key="alerts"
              initial={{ opacity: 0, y: 5 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, y: -5 }}
              transition={{ duration: 0.15 }}
              className="space-y-6"
            >
              
              <div className="bg-slate-900/60 border border-slate-900 rounded-xl p-5">
                <h4 className="text-base font-semibold text-white">Intrusion Prevention Alert History Center</h4>
                <p className="text-xs text-slate-400 mt-1">Realtime state tracking log outputs generated from internal Snort/Suricata simulation parameters.</p>
              </div>

              <div className="space-y-3">
                {alerts.length > 0 ? (
                  alerts.map((alert) => (
                    <div 
                      key={alert.id}
                      className={`p-4 rounded-xl border flex flex-col md:flex-row justify-between items-start md:items-center gap-4 transition ${
                        alert.acknowledged
                          ? 'bg-slate-900/20 border-slate-900 opacity-60'
                          : 'bg-slate-900/60 border-slate-800'
                      }`}
                    >
                      <div className="space-y-1">
                        <div className="flex items-center gap-2">
                          <span className={`px-2 py-0.5 font-mono text-[9px] font-bold rounded uppercase ${
                            alert.severity === 'CRITICAL' ? 'bg-red-500/20 text-red-400' : 'bg-amber-500/20 text-amber-500'
                          }`}>
                            {alert.severity} Incident
                          </span>
                          <span className="text-[10px] text-slate-500 font-mono">
                            {new Date(alert.timestamp).toLocaleString()}
                          </span>
                        </div>
                        
                        <p className="text-xs text-slate-200 font-sans leading-relaxed pt-1">{alert.message}</p>
                        
                        <div className="flex flex-wrap items-center gap-3 pt-2 text-[10px] text-slate-400 font-mono">
                          <span>Originating: <span className="text-white font-semibold">{alert.sourceIP}</span></span>
                          <span>&rarr; Target host: <span className="text-slate-350 font-semibold">{alert.destIP}</span></span>
                          <span>Vector Type: <span className="text-cyan-400 font-semibold">{alert.type}</span></span>
                        </div>
                      </div>

                      <div className="flex items-center gap-2 shrink-0">
                        {!alert.acknowledged ? (
                          <button
                            onClick={() => acknowledgeAlert(alert.id)}
                            className="px-3 py-1.5 bg-emerald-600 hover:bg-emerald-500 text-white rounded text-xs font-semibold font-sans transition"
                          >
                            Mark Handled
                          </button>
                        ) : (
                          <span className="text-xs text-slate-500 flex items-center gap-1 font-mono">
                            <CheckCircle className="h-3.5 w-3.5 text-slate-500" />
                            Handled
                          </span>
                        )}
                        
                        {alert.packetLink && (
                          <button
                            onClick={() => {
                              const found = packets.find(p => p.id === alert.packetLink);
                              if (found) {
                                setSelectedPacket(found);
                                setActiveTab('packets');
                              }
                            }}
                            className="px-2 py-1.5 bg-slate-950 hover:bg-slate-800 text-slate-400 hover:text-white rounded text-[11px] font-mono transition border border-slate-900"
                          >
                            Inspect Payload
                          </button>
                        )}
                      </div>

                    </div>
                  ))
                ) : (
                  <div className="p-12 text-center bg-slate-900/20 border border-slate-900 rounded-xl text-slate-500 text-xs">
                    All clear. No dynamic intrusion alarms logged. System state fully monitored.
                  </div>
                )}
              </div>

            </motion.div>
          )}

          {activeTab === 'blacklist' && (
            <motion.div 
              key="blacklist"
              initial={{ opacity: 0, y: 5 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, y: -5 }}
              transition={{ duration: 0.15 }}
              className="space-y-6"
            >
              
              <div className="bg-slate-900/60 border border-slate-900 rounded-xl p-5">
                <h4 className="text-base font-semibold text-white">Direct Access Protection Lists</h4>
                <p className="text-xs text-slate-400 mt-1">High-speed lookups bypassed at layer-3 without processing complex ACL arrays.</p>
              </div>

              {/* Add Entry Form */}
              <div className="bg-slate-900 border border-slate-850 p-5 rounded-xl space-y-4">
                <h5 className="text-sm font-semibold text-white">Add System Control Address</h5>
                
                <form onSubmit={handleAddIpAddress} className="flex flex-col md:flex-row items-end gap-4 text-xs font-sans">
                  
                  <div className="space-y-1.5 w-full md:w-48">
                    <label className="text-slate-400 font-medium">Select List Type</label>
                    <select 
                      value={listTypeSelection}
                      onChange={(e) => setListTypeSelection(e.target.value as any)}
                      className="w-full bg-slate-950 border border-slate-800 rounded px-2.5 py-2 text-white focus:outline-none focus:border-cyan-500"
                    >
                      <option value="blacklist">BLACKLIST (Direct Drop)</option>
                      <option value="whitelist">WHITELIST (Direct Safe Bypass)</option>
                    </select>
                  </div>

                  <div className="space-y-1.5 flex-1 w-full">
                    <label className="text-slate-400 font-medium">Target IP Address</label>
                    <input 
                      type="text" 
                      placeholder="e.g. 192.168.1.150"
                      value={newIpToList}
                      onChange={(e) => setNewIpToList(e.target.value)}
                      className="w-full bg-slate-950 border border-slate-800 rounded px-3 py-2 text-white font-mono focus:outline-none focus:border-cyan-500"
                      required
                    />
                  </div>

                  <button 
                    type="submit"
                    className="px-4 py-2 bg-gradient-to-r from-indigo-500 to-blue-600 font-bold rounded text-white shrink-0 w-full md:w-auto"
                  >
                    Add Address Entry
                  </button>

                </form>
              </div>

              {/* Layout Split: Blacklist & Whitelist Columns */}
              <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                
                {/* Blacklist block */}
                <div className="bg-slate-900/30 border border-slate-900 rounded-xl p-5">
                  <div className="flex justify-between items-center mb-3">
                    <h5 className="text-sm font-semibold text-red-400 flex items-center gap-1.5">
                      <span>●</span> System Blacklist Database
                    </h5>
                    <span className="text-[10px] text-slate-500 font-mono">{blacklist.length} addresses</span>
                  </div>
                  <p className="text-xs text-slate-400 mb-4">Incoming frames from these resources are immediately structured as Blocked.</p>

                  <div className="space-y-2">
                    {blacklist.map(ip => (
                      <div key={ip} className="bg-slate-950 p-3 rounded-lg border border-slate-900 flex justify-between items-center text-xs font-mono">
                        <span className="text-white">{ip}</span>
                        <button 
                          onClick={() => handleRemoveIpAddress('blacklist', ip)}
                          className="text-[11px] text-slate-500 hover:text-red-400 hover:bg-red-500/10 px-2 py-1 rounded transition"
                        >
                          Remove
                        </button>
                      </div>
                    ))}
                  </div>
                </div>

                {/* Whitelist block */}
                <div className="bg-slate-900/30 border border-slate-900 rounded-xl p-5">
                  <div className="flex justify-between items-center mb-3">
                    <h5 className="text-sm font-semibold text-emerald-400 flex items-center gap-1.5">
                      <span>●</span> System Whitelist Bypass
                    </h5>
                    <span className="text-[10px] text-slate-500 font-mono">{whitelist.length} addresses</span>
                  </div>
                  <p className="text-xs text-slate-400 mb-4">Trusted networks and local loopbacks bypassed from threat-scoring blocks.</p>

                  <div className="space-y-2">
                    {whitelist.map(ip => (
                      <div key={ip} className="bg-slate-950 p-3 rounded-lg border border-slate-900 flex justify-between items-center text-xs font-mono">
                        <span className="text-white">{ip}</span>
                        <button 
                          onClick={() => handleRemoveIpAddress('whitelist', ip)}
                          className="text-[11px] text-slate-500 hover:text-red-400 hover:bg-red-500/10 px-2 py-1 rounded transition"
                        >
                          Remove
                        </button>
                      </div>
                    ))}
                  </div>
                </div>

              </div>

            </motion.div>
          )}

          {activeTab === 'education' && (
            <motion.div 
              key="education"
              initial={{ opacity: 0, y: 5 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, y: -5 }}
              transition={{ duration: 0.15 }}
              className="space-y-6"
            >
              
              <div className="bg-slate-900/60 border border-slate-900 rounded-xl p-5">
                <h4 className="text-base font-semibold text-white">Technical Architecture & Deployments Guide</h4>
                <p className="text-xs text-slate-400 mt-1">Structured system layouts of Aegis-Engine, suitable for cybersecurity portfolios and internship reference designs.</p>
              </div>

              {/* Deployment info and cyber guide highlights */}
              <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
                
                {/* Architecture card details */}
                <div className="lg:col-span-2 bg-slate-900/30 border border-slate-900 rounded-xl p-6 space-y-5">
                  
                  <div>
                    <h5 className="text-sm font-semibold text-white flex items-center gap-2 mb-2">
                      <Cpu className="h-4 w-4 text-cyan-400" />
                      1. Modular System Architecture
                    </h5>
                    <p className="text-xs text-slate-400 leading-relaxed font-sans">
                      Aegis is constructed with clear layer segmentation adhering to reliable high-performance network engineering designs. Each subsystem isolates critical workloads neatly:
                    </p>
                    <ul className="text-xs text-slate-350 list-disc list-inside space-y-1.5 mt-2 ml-2 leading-relaxed">
                      <li><strong className="text-slate-100">Packet Capture Module:</strong> Runs socket listeners (using Python/Scapy wrappers in production or mock C-packet handlers) parsing binary frames to structural JSON trace objects.</li>
                      <li><strong className="text-slate-100">Traffic Analysis & Rule Engine:</strong> Employs structured access controls with quick lookup indexing arrays (O(1) whitelists/blacklists search structures).</li>
                      <li><strong className="text-slate-100">Intelligent Threat Scoring Module:</strong> Evaluates anomalous entropy metrics, brute-force indicators, and ports scan traces to auto-suggest rule updates.</li>
                      <li><strong className="text-slate-100">IDS/IPS Center:</strong> Proactively alerts administrators and automatically mounts stateful IPTables drop criteria.</li>
                    </ul>
                  </div>

                  <div>
                    <h5 className="text-sm font-semibold text-white flex items-center gap-2 mb-2">
                      <Server className="h-4 w-4 text-cyan-400" />
                      2. Host Node Deployment Setup (Kali/RedHat Linux)
                    </h5>
                    <p className="text-xs text-slate-400 leading-relaxed">
                      Follow standard guidelines below to integrate live packet scraping into low-level IPTables kernels in your testing environment:
                    </p>
                    
                    <div className="bg-slate-950 p-4 border border-slate-900 rounded-xl font-mono text-[11px] leading-relaxed text-slate-300 mt-2 space-y-3">
                      <div>
                        <span className="text-slate-500"># Install standard raw packet capture libraries</span>
                        <div>sudo apt-get install libpcap-dev tshark iptables</div>
                      </div>
                      <div>
                        <span className="text-slate-500 font-mono"># Bind socket interfaces and execute daemon wrapper</span>
                        <div>python3 -m pip install scapy pyshark fastapi uvicorn</div>
                      </div>
                      <div>
                        <span className="text-slate-500"># Deploy stateful drop commands dynamically for blocked threats</span>
                        <div>sudo iptables -A INPUT -s 185.220.101.5 -p tcp --dport 22 -j DROP</div>
                      </div>
                    </div>
                  </div>

                </div>

                <div className="bg-slate-900/60 border border-slate-800 rounded-xl p-5 space-y-4">
                  <h5 className="text-sm font-semibold text-white flex items-center gap-2">
                    <FileText className="h-4 w-4 text-cyan-400" />
                    Security & Compliance Checklist
                  </h5>

                  <div className="space-y-3.5 text-xs text-slate-350 leading-relaxed font-sans">
                    <div>
                      <h6 className="text-[11px] font-bold text-white uppercase tracking-wider">A. Secure Scoping Permissions</h6>
                      <p className="mt-0.5">Always isolate raw capture daemon interfaces in non-root users utilizing <span className="font-mono text-cyan-400 bg-cyan-400/5 px-1 py-0.2 rounded">CAP_NET_RAW</span> socket capability settings to prevent full kernel exposure.</p>
                    </div>

                    <div>
                      <h6 className="text-[11px] font-bold text-white uppercase tracking-wider">B. Mitigating Stream Race Conditions</h6>
                      <p className="mt-0.5">Utilize dual buffers during packet bursts, enforcing ring-queue boundaries to prevent memory overhead and dashboard lags under active port scans.</p>
                    </div>

                    <div>
                      <h6 className="text-[11px] font-bold text-white uppercase tracking-wider">C. AI Model Fail-Safes</h6>
                      <p className="mt-0.5">Never chain raw generative decisions blindly to direct internet gateway rules. Proactively sanitize all inputs and ensure manual review triggers exist before deploying permanent ACL firewall overrides.</p>
                    </div>
                  </div>
                </div>

              </div>

            </motion.div>
          )}
        </AnimatePresence>

      </main>

      <footer className="border-t border-slate-900 py-6 bg-slate-950 text-center text-xs text-slate-500 font-mono mt-12">
        <div className="max-w-7xl mx-auto px-4 flex flex-col sm:flex-row justify-between items-center gap-4">
          <span>Aegis Shield Cybersecurity Lab Tool. For diagnostic and simulation uses.</span>
          <span className="text-slate-600">Enterprise Standard Trace • GMT 2026</span>
        </div>
      </footer>

    </div>
  );
}
