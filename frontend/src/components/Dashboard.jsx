import React, { useState, useRef } from 'react';
import { Upload, FileText, AlertTriangle, ShieldCheck, Activity, ChevronDown, ChevronRight } from 'lucide-react';
import { motion, AnimatePresence } from 'framer-motion';
import { PieChart, Pie, Cell, ResponsiveContainer, Tooltip, Legend } from 'recharts';
import axios from 'axios';

// Severity Badge Component
const SeverityBadge = ({ severity, riskScore }) => {
    const colors = {
        'CRITICAL': 'bg-red-500/20 text-red-400 border-red-500',
        'HIGH': 'bg-orange-500/ 20 text-orange-400 border-orange-500',
        'MEDIUM': 'bg-yellow-500/20 text-yellow-400 border-yellow-500',
        'LOW': 'bg-blue-500/20 text-blue-400 border-blue-500',
        'INFO': 'bg-slate-500/20 text-slate-400 border-slate-500'
    };

    return (
        <div className="flex items-center gap-2">
            <span className={`px-2 py-1 rounded text-xs font-bold border ${colors[severity] || colors['MEDIUM']}`}>
                {severity}
            </span>
            <span className="text-xs font-mono text-slate-400">
                Risk: {riskScore}/100
            </span>
        </div>
    );
};

// ThreatAccordion Component
const ThreatAccordion = ({ threats, onViewPacket }) => {
    const [expandedTypes, setExpandedTypes] = useState({});

    // Group threats by type
    const groupedThreats = threats.reduce((acc, threat) => {
        const type = threat.type || 'Unknown';
        if (!acc[type]) {
            acc[type] = [];
        }
        acc[type].push(threat);
        return acc;
    }, {});

    const toggleType = (type) => {
        setExpandedTypes(prev => ({
            ...prev,
            [type]: !prev[type]
        }));
    };

    // Separate Encrypted Traffic from other threats
    const encryptedTraffic = groupedThreats['Encrypted Traffic'];
    const otherThreats = Object.entries(groupedThreats).filter(([type]) => type !== 'Encrypted Traffic');

    const renderAccordionItem = ([type, typeThreats]) => {
        const isExpanded = expandedTypes[type];
        const avgRisk = Math.round(typeThreats.reduce((sum, t) => sum + (t.risk_score || 50), 0) / typeThreats.length);
        const highestSeverity = typeThreats.reduce((max, t) => {
            const severities = ['INFO', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'];
            const currentIndex = severities.indexOf(t.severity || 'MEDIUM');
            const maxIndex = severities.indexOf(max);
            return currentIndex > maxIndex ? t.severity : max;
        }, 'INFO');

        return (
            <div key={type} className="border border-slate-700 rounded-lg overflow-hidden">
                {/* Accordion Header */}
                <div
                    onClick={() => toggleType(type)}
                    className="flex items-center justify-between p-4 bg-slate-800/50 hover:bg-slate-800 cursor-pointer transition-colors"
                >
                    <div className="flex items-center gap-3 flex-1">
                        {isExpanded ? (
                            <ChevronDown className="w-5 h-5 text-slate-400" />
                        ) : (
                            <ChevronRight className="w-5 h-5 text-slate-400" />
                        )}
                        <AlertTriangle className="w-5 h-5 text-red-400" />
                        <div>
                            <h4 className="font-semibold text-white">{type}</h4>
                            <p className="text-xs text-slate-400">{typeThreats.length} occurrence{typeThreats.length !== 1 ? 's' : ''}</p>
                        </div>
                    </div>
                    <div className="flex items-center gap-4">
                        <SeverityBadge severity={highestSeverity} riskScore={avgRisk} />
                        {typeThreats[0]?.threat_category && (
                            <span className="px-2 py-1 bg-purple-500/20 text-purple-400 rounded text-xs">
                                {typeThreats[0].threat_category}
                            </span>
                        )}
                    </div>
                </div>

                {/* Accordion Content */}
                <AnimatePresence>
                    {isExpanded && (
                        <motion.div
                            initial={{ height: 0, opacity: 0 }}
                            animate={{ height: 'auto', opacity: 1 }}
                            exit={{ height: 0, opacity: 0 }}
                            transition={{ duration: 0.2 }}
                            className="overflow-hidden"
                        >
                            <div className="p-4 space-y-2 bg-slate-900/30 max-h-[400px] overflow-y-auto custom-scrollbar">
                                {typeThreats.map((alert, idx) => (
                                    <div
                                        key={idx}
                                        onClick={(e) => {
                                            e.stopPropagation();
                                            onViewPacket(alert);
                                        }}
                                        className="p-4 bg-slate-800/50 hover:bg-slate-800 rounded-lg cursor-pointer transition-colors border border-slate-700"
                                    >
                                        <div className="flex justify-between items-start mb-3">
                                            <div className="flex items-center gap-2">
                                                <SeverityBadge severity={alert.severity} riskScore={alert.risk_score} />
                                                {alert.mitre_tactic && (
                                                    <span className="px-2 py-1 bg-cyan-500/20 text-cyan-400 rounded text-xs font-mono">
                                                        {alert.mitre_tactic}
                                                    </span>
                                                )}
                                                {alert.mitre_technique && (
                                                    <span className="px-2 py-1 bg-cyan-500/10 text-cyan-400 rounded text-xs font-mono">
                                                        {alert.mitre_technique}
                                                    </span>
                                                )}
                                            </div>
                                            <span className="text-xs text-slate-500">
                                                {alert.timestamp}
                                            </span>
                                        </div>

                                        <p className="text-sm text-slate-300 mb-3">{alert.details}</p>

                                        <div className="grid grid-cols-2 gap-2 text-xs font-mono">
                                            <div className="text-slate-500">
                                                <span className="text-slate-400">Source:</span> {alert.src_ip}
                                            </div>
                                            <div className="text-slate-500">
                                                <span className="text-slate-400">Dest:</span> {alert.dst_ip}
                                            </div>
                                            <div className="text-slate-500">
                                                <span className="text-slate-400">Port:</span> {alert.port}
                                            </div>
                                            <div className="text-slate-500">
                                                <span className="text-slate-400">Protocol:</span> {alert.protocol}
                                            </div>
                                        </div>

                                        <div className="mt-3 text-xs text-emerald-400 hover:text-emerald-300 transition-colors">
                                            Click to view full packet details →
                                        </div>
                                    </div>
                                ))}
                            </div>
                        </motion.div>
                    )}
                </AnimatePresence>
            </div>
        );
    };

    return (
        <div className="space-y-3">
            {/* Encrypted Traffic - Always visible at top (not in scroll) */}
            {encryptedTraffic && renderAccordionItem(['Encrypted Traffic', encryptedTraffic])}

            {/* Other threats - Scrollable container */}
            {otherThreats.length > 0 && (
                <div className="max-h-[400px] overflow-y-auto custom-scrollbar pr-2 space-y-3">
                    {otherThreats.map(renderAccordionItem)}
                </div>
            )}
        </div>
    );
};

const Dashboard = ({ initialReport, onViewReport, onViewPacket }) => {
    const [file, setFile] = useState(null);
    const [loading, setLoading] = useState(false);
    const [report, setReport] = useState(initialReport);
    const fileInputRef = useRef(null);

    // Update report if initialReport changes (e.g. from history)
    React.useEffect(() => {
        if (initialReport) {
            setReport(initialReport);
        }
    }, [initialReport]);

    const handleFileChange = (e) => {
        if (e.target.files[0]) {
            handleUpload(e.target.files[0]);
        }
    };

    const handleDrop = (e) => {
        e.preventDefault();
        if (e.dataTransfer.files[0]) {
            handleUpload(e.dataTransfer.files[0]);
        }
    };

    const handleUpload = async (uploadedFile) => {
        setFile(uploadedFile);
        setLoading(true);

        const formData = new FormData();
        formData.append('file', uploadedFile);

        try {
            const response = await axios.post('http://localhost:8080/api/upload', formData);
            setReport(response.data);
        } catch (error) {
            console.error('Upload failed:', error);
            alert('Analysis failed. Please try again.');
        } finally {
            setLoading(false);
        }
    };

    const COLORS = ['#38bdf8', '#818cf8', '#c084fc', '#f472b6', '#fb7185'];

    if (report) {
        const protocolData = Object.entries(report.protocols).map(([name, value]) => ({ name, value }));

        return (
            <div className="space-y-6">
                <div className="flex justify-between items-center mb-8">
                    <div>
                        <h2 className="text-3xl font-bold text-white mb-2">Analysis Report</h2>
                        <p className="text-slate-400">File: {file?.name}</p>
                    </div>
                    <button
                        onClick={() => setReport(null)}
                        className="px-4 py-2 bg-slate-800 hover:bg-slate-700 rounded-lg text-sm font-medium transition-colors"
                    >
                        Analyze Another File
                    </button>
                </div>

                {/* Stats Grid */}
                <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
                    <motion.div
                        initial={{ opacity: 0, y: 20 }}
                        animate={{ opacity: 1, y: 0 }}
                        className="glass-card p-6 flex items-center gap-4"
                    >
                        <div className="p-3 bg-blue-500/10 rounded-lg">
                            <Activity className="w-8 h-8 text-blue-400" />
                        </div>
                        <div>
                            <p className="text-slate-400 text-sm uppercase tracking-wider">Total Packets</p>
                            <p className="text-3xl font-bold text-white">{report.packet_count.toLocaleString()}</p>
                        </div>
                    </motion.div>

                    <motion.div
                        initial={{ opacity: 0, y: 20 }}
                        animate={{ opacity: 1, y: 0 }}
                        transition={{ delay: 0.1 }}
                        className="glass-card p-6 flex items-center gap-4"
                    >
                        <div className={`p-3 rounded-lg ${report.malicious_activity.length > 0 ? 'bg-red-500/10' : 'bg-green-500/10'}`}>
                            {report.malicious_activity.length > 0 ? (
                                <AlertTriangle className="w-8 h-8 text-red-400" />
                            ) : (
                                <ShieldCheck className="w-8 h-8 text-green-400" />
                            )}
                        </div>
                        <div>
                            <p className="text-slate-400 text-sm uppercase tracking-wider">Threats Detected</p>
                            <p className={`text-3xl font-bold ${report.malicious_activity.length > 0 ? 'text-red-400' : 'text-green-400'}`}>
                                {report.malicious_activity.length}
                            </p>
                        </div>
                    </motion.div>
                </div>

                <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                    {/* Protocol Chart */}
                    <motion.div
                        initial={{ opacity: 0, scale: 0.95 }}
                        animate={{ opacity: 1, scale: 1 }}
                        transition={{ delay: 0.2 }}
                        className="glass-card p-6"
                    >
                        <h3 className="text-xl font-bold mb-6">Protocol Distribution</h3>
                        <div className="h-[300px]">
                            <ResponsiveContainer width="100%" height="100%">
                                <PieChart>
                                    <Pie
                                        data={protocolData}
                                        cx="50%"
                                        cy="50%"
                                        innerRadius={60}
                                        outerRadius={100}
                                        paddingAngle={5}
                                        dataKey="value"
                                    >
                                        {protocolData.map((entry, index) => (
                                            <Cell key={`cell-${index}`} fill={COLORS[index % COLORS.length]} />
                                        ))}
                                    </Pie>
                                    <Tooltip
                                        contentStyle={{ backgroundColor: '#1e293b', borderColor: '#334155', borderRadius: '8px' }}
                                        itemStyle={{ color: '#fff' }}
                                        formatter={(value, name) => {
                                            const percentage = ((value / report.packet_count) * 100).toFixed(2);
                                            return [`${value} packets (${percentage}%)`, name];
                                        }}
                                    />
                                    <Legend />
                                </PieChart>
                            </ResponsiveContainer>
                        </div>

                        {/* Protocol Details Table */}
                        <div className="mt-6 border-t border-slate-700 pt-4">
                            <h4 className="text-sm font-bold text-slate-400 uppercase tracking-wider mb-3">Breakdown</h4>
                            <div className="space-y-2 max-h-[200px] overflow-y-auto custom-scrollbar pr-2">
                                {protocolData
                                    .sort((a, b) => b.value - a.value)
                                    .map((protocol, idx) => {
                                        const percentage = ((protocol.value / report.packet_count) * 100).toFixed(2);
                                        return (
                                            <div key={idx} className="flex items-center justify-between p-2 bg-slate-800/50 rounded hover:bg-slate-800 transition-colors">
                                                <div className="flex items-center gap-3">
                                                    <div
                                                        className="w-3 h-3 rounded-full"
                                                        style={{ backgroundColor: COLORS[protocolData.findIndex(p => p.name === protocol.name) % COLORS.length] }}
                                                    />
                                                    <span className="font-semibold text-white">{protocol.name}</span>
                                                </div>
                                                <div className="flex items-center gap-3">
                                                    <span className="text-slate-400 text-sm font-mono">{protocol.value} pkts</span>
                                                    <span className="text-primary font-bold text-sm min-w-[50px] text-right">{percentage}%</span>
                                                </div>
                                            </div>
                                        );
                                    })}
                            </div>
                        </div>
                    </motion.div>

                    {/* Security Alerts - Accordion Style */}
                    <motion.div
                        initial={{ opacity: 0, y: 20 }}
                        animate={{ opacity: 1, y: 0 }}
                        transition={{ delay: 0.4 }}
                        className="glass-card p-6"
                    >
                        <h3 className="text-2xl font-bold text-white mb-6 flex items-center gap-3">
                            <AlertTriangle className="w-6 h-6 text-red-400" />
                            Security Alerts
                            <span className="text-sm font-normal text-slate-400 ml-auto">
                                {report.malicious_activity.length} total
                            </span>
                        </h3>

                        {report.malicious_activity.length === 0 ? (
                            <div className="text-center py-12 text-slate-400">
                                <ShieldCheck className="w-16 h-16 mx-auto mb-4 text-emerald-400" />
                                <p>No threats detected in this capture.</p>
                            </div>
                        ) : (
                            <ThreatAccordion
                                threats={report.malicious_activity}
                                onViewPacket={onViewPacket}
                            />
                        )}
                    </motion.div>
                </div>

                {/* IP Tables */}
                <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                    <div className="glass-card p-6">
                        <h3 className="text-xl font-bold mb-4">Top Source IPs</h3>
                        <table className="w-full text-left">
                            <thead>
                                <tr className="border-b border-slate-700 text-slate-400 text-sm">
                                    <th className="pb-3 font-medium">IP Address</th>
                                    <th className="pb-3 font-medium text-right">Count</th>
                                </tr>
                            </thead>
                            <tbody className="text-sm">
                                {Object.entries(report.src_ips).map(([ip, count], i) => (
                                    <tr key={i} className="border-b border-slate-700/50 last:border-0">
                                        <td className="py-3 font-mono text-slate-300">{ip}</td>
                                        <td className="py-3 text-right text-primary">{count}</td>
                                    </tr>
                                ))}
                            </tbody>
                        </table>
                    </div>

                    <div className="glass-card p-6">
                        <h3 className="text-xl font-bold mb-4">Top Destination IPs</h3>
                        <table className="w-full text-left">
                            <thead>
                                <tr className="border-b border-slate-700 text-slate-400 text-sm">
                                    <th className="pb-3 font-medium">IP Address</th>
                                    <th className="pb-3 font-medium text-right">Count</th>
                                </tr>
                            </thead>
                            <tbody className="text-sm">
                                {Object.entries(report.dst_ips).map(([ip, count], i) => (
                                    <tr key={i} className="border-b border-slate-700/50 last:border-0">
                                        <td className="py-3 font-mono text-slate-300">{ip}</td>
                                        <td className="py-3 text-right text-primary">{count}</td>
                                    </tr>
                                ))}
                            </tbody>
                        </table>
                    </div>
                </div>
            </div>
        );
    }

    return (
        <div className="max-w-3xl mx-auto pt-20 text-center">
            <motion.div
                initial={{ opacity: 0, y: 20 }}
                animate={{ opacity: 1, y: 0 }}
                className="mb-12"
            >
                <h2 className="text-5xl font-bold mb-4 bg-gradient-to-r from-primary via-accent to-purple-500 bg-clip-text text-transparent">
                    Analyze Your Network
                </h2>
                <p className="text-xl text-slate-400">
                    Upload a PCAP file to detect threats and visualize traffic patterns.
                </p>
            </motion.div>

            <motion.div
                initial={{ scale: 0.95, opacity: 0 }}
                animate={{ scale: 1, opacity: 1 }}
                transition={{ delay: 0.1 }}
                className="glass-card p-12 border-2 border-dashed border-slate-700 hover:border-primary/50 transition-all duration-300 group cursor-pointer relative overflow-hidden"
                onDragOver={(e) => e.preventDefault()}
                onDrop={handleDrop}
                onClick={() => fileInputRef.current?.click()}
            >
                <div className="absolute inset-0 bg-gradient-to-br from-primary/5 to-purple-500/5 opacity-0 group-hover:opacity-100 transition-opacity duration-500" />

                {loading ? (
                    <div className="flex flex-col items-center justify-center py-8">
                        <div className="w-16 h-16 border-4 border-primary/20 border-t-primary rounded-full animate-spin mb-6" />
                        <p className="text-lg font-medium text-white">Analyzing traffic patterns...</p>
                        <p className="text-sm text-slate-400 mt-2">This may take a few moments</p>
                    </div>
                ) : (
                    <>
                        <div className="w-20 h-20 bg-slate-800/50 rounded-full flex items-center justify-center mx-auto mb-6 group-hover:scale-110 transition-transform duration-300">
                            <Upload className="w-10 h-10 text-primary" />
                        </div>
                        <h3 className="text-2xl font-bold text-white mb-2">Upload PCAP File</h3>
                        <p className="text-slate-400 mb-8">Drag & drop or click to browse</p>
                        <input
                            type="file"
                            ref={fileInputRef}
                            onChange={handleFileChange}
                            accept=".pcap,.pcapng,.cap"
                            className="hidden"
                        />
                        <div className="flex justify-center gap-4 text-sm text-slate-500">
                            <span className="flex items-center gap-1"><FileText className="w-4 h-4" /> .pcap</span>
                            <span className="flex items-center gap-1"><FileText className="w-4 h-4" /> .pcapng</span>
                            <span className="flex items-center gap-1"><FileText className="w-4 h-4" /> .cap</span>
                        </div>
                    </>
                )}
            </motion.div>
        </div>
    );
};

export default Dashboard;
