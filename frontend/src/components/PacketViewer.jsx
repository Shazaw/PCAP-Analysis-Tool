import React, { useState } from 'react';
import { X, Copy, Terminal, Check, ChevronDown, ChevronRight } from 'lucide-react';
import { motion, AnimatePresence } from 'framer-motion';

const PacketViewer = ({ isOpen, onClose, packet }) => {
    const [copiedHex, setCopiedHex] = useState(false);
    const [copiedAscii, setCopiedAscii] = useState(false);
    const [alertExpanded, setAlertExpanded] = useState(false);

    if (!isOpen || !packet) return null;

    const copyToClipboard = async (text, type) => {
        try {
            await navigator.clipboard.writeText(text);
            if (type === 'hex') {
                setCopiedHex(true);
                setTimeout(() => setCopiedHex(false), 2000);
            } else {
                setCopiedAscii(true);
                setTimeout(() => setCopiedAscii(false), 2000);
            }
        } catch (err) {
            console.error('Failed to copy:', err);
        }
    };

    return (
        <AnimatePresence>
            <div className="fixed inset-0 z-[100] flex items-center justify-center p-4">
                <motion.div
                    initial={{ opacity: 0 }}
                    animate={{ opacity: 1 }}
                    exit={{ opacity: 0 }}
                    onClick={onClose}
                    className="absolute inset-0 bg-black/60 backdrop-blur-sm"
                />

                <motion.div
                    initial={{ scale: 0.95, opacity: 0, y: 20 }}
                    animate={{ scale: 1, opacity: 1, y: 0 }}
                    exit={{ scale: 0.95, opacity: 0, y: 20 }}
                    className="relative w-full max-w-4xl bg-slate-900 border border-slate-700 rounded-xl shadow-2xl overflow-hidden flex flex-col max-h-[90vh]"
                >
                    {/* Header */}
                    <div className="flex items-center justify-between p-4 border-b border-slate-700 bg-slate-800/50">
                        <div className="flex items-center gap-3">
                            <div className="p-2 bg-red-500/10 rounded-lg">
                                <Terminal className="w-5 h-5 text-red-400" />
                            </div>
                            <div>
                                <h3 className="font-bold text-white text-lg">Packet Details</h3>
                                <p className="text-xs text-slate-400 font-mono">
                                    {packet.src_ip}:{packet.port} → {packet.dst_ip}
                                </p>
                            </div>
                        </div>
                        <button
                            onClick={onClose}
                            className="p-2 hover:bg-white/10 rounded-lg transition-colors text-slate-400 hover:text-white"
                        >
                            <X className="w-5 h-5" />
                        </button>
                    </div>

                    {/* Content */}
                    <div className="p-6 overflow-y-auto custom-scrollbar space-y-6">
                        {/* Metadata Grid */}
                        <div className="grid grid-cols-2 md:grid-cols-3 gap-4">
                            <div className="bg-slate-800/50 p-3 rounded-lg border border-slate-700/50">
                                <p className="text-xs text-slate-500 uppercase">Protocol</p>
                                <p className="font-mono text-primary">{packet.protocol}</p>
                            </div>
                            <div className="bg-slate-800/50 p-3 rounded-lg border border-slate-700/50">
                                <p className="text-xs text-slate-500 uppercase">Port</p>
                                <p className="font-mono text-red-400">{packet.port}</p>
                            </div>
                            <div className="bg-slate-800/50 p-3 rounded-lg border border-slate-700/50 col-span-2 md:col-span-1">
                                <p className="text-xs text-slate-500 uppercase">Timestamp</p>
                                <p className="font-mono text-slate-300 text-sm">{packet.timestamp || 'N/A'}</p>
                            </div>
                        </div>

                        {/* SIEM Intelligence */}
                        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                            <div className="bg-gradient-to-br from-red-500/10 to-orange-500/10 p-4 rounded-lg border border-red-500/30">
                                <p className="text-xs text-slate-400 uppercase mb-2">Severity</p>
                                <p className={`text-xl font-bold ${packet.severity === 'CRITICAL' ? 'text-red-400' :
                                    packet.severity === 'HIGH' ? 'text-orange-400' :
                                        packet.severity === 'MEDIUM' ? 'text-yellow-400' :
                                            'text-blue-400'
                                    }`}>
                                    {packet.severity || 'MEDIUM'}
                                </p>
                            </div>
                            <div className="bg-gradient-to-br from-purple-500/10 to-pink-500/10 p-4 rounded-lg border border-purple-500/30">
                                <p className="text-xs text-slate-400 uppercase mb-2">Risk Score</p>
                                <p className="text-xl font-bold text-purple-400">
                                    {packet.risk_score || 50}/100
                                </p>
                            </div>
                            <div className="bg-gradient-to-br from-cyan-500/10 to-blue-500/10 p-4 rounded-lg border border-cyan-500/30">
                                <p className="text-xs text-slate-400 uppercase mb-2">Category</p>
                                <p className="text-sm font-semibold text-cyan-400">
                                    {packet.threat_category || 'Unknown'}
                                </p>
                            </div>
                        </div>

                        {/* MITRE ATT&CK Mapping */}
                        {(packet.mitre_tactic || packet.mitre_technique) && (
                            <div className="bg-cyan-500/5 border border-cyan-500/20 p-4 rounded-lg">
                                <h4 className="text-sm font-bold text-cyan-400 mb-3 uppercase tracking-wider">
                                    MITRE ATT&CK Framework
                                </h4>
                                <div className="grid grid-cols-2 gap-3">
                                    {packet.mitre_tactic && (
                                        <div>
                                            <p className="text-xs text-slate-500 mb-1">Tactic</p>
                                            <p className="font-mono text-sm text-cyan-400">{packet.mitre_tactic}</p>
                                        </div>
                                    )}
                                    {packet.mitre_technique && (
                                        <div>
                                            <p className="text-xs text-slate-500 mb-1">Technique</p>
                                            <p className="font-mono text-sm text-cyan-400">{packet.mitre_technique}</p>
                                        </div>
                                    )}
                                </div>
                            </div>
                        )}

                        {/* Detailed Packet Headers */}
                        {packet.packet_details && Object.keys(packet.packet_details).length > 0 && (
                            <div>
                                <h4 className="text-sm font-bold text-slate-400 uppercase tracking-wider mb-3">
                                    Packet Headers
                                </h4>
                                <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
                                    {packet.packet_details.frame_num !== "N/A" && (
                                        <div className="bg-slate-800/50 p-3 rounded-lg border border-slate-700/50">
                                            <p className="text-xs text-slate-500">Frame #</p>
                                            <p className="font-mono text-sm text-slate-300">{packet.packet_details.frame_num}</p>
                                        </div>
                                    )}
                                    {packet.packet_details.frame_len !== "N/A" && (
                                        <div className="bg-slate-800/50 p-3 rounded-lg border border-slate-700/50">
                                            <p className="text-xs text-slate-500">Frame Size</p>
                                            <p className="font-mono text-sm text-slate-300">{packet.packet_details.frame_len}B</p>
                                        </div>
                                    )}
                                    {packet.packet_details.ip_ttl !== "N/A" && (
                                        <div className="bg-slate-800/50 p-3 rounded-lg border border-slate-700/50">
                                            <p className="text-xs text-slate-500">IP TTL</p>
                                            <p className="font-mono text-sm text-slate-300">{packet.packet_details.ip_ttl}</p>
                                        </div>
                                    )}
                                    {packet.packet_details.ip_id !== "N/A" && (
                                        <div className="bg-slate-800/50 p-3 rounded-lg border border-slate-700/50">
                                            <p className="text-xs text-slate-500">IP ID</p>
                                            <p className="font-mono text-sm text-slate-300">{packet.packet_details.ip_id}</p>
                                        </div>
                                    )}
                                    {packet.packet_details.tcp_seq !== "N/A" && (
                                        <div className="bg-slate-800/50 p-3 rounded- lg border border-slate-700/50">
                                            <p className="text-xs text-slate-500">TCP Seq</p>
                                            <p className="font-mono text-sm text-slate-300">{packet.packet_details.tcp_seq}</p>
                                        </div>
                                    )}
                                    {packet.packet_details.tcp_ack !== "N/A" && (
                                        <div className="bg-slate-800/50 p-3 rounded-lg border border-slate-700/50">
                                            <p className="text-xs text-slate-500">TCP Ack</p>
                                            <p className="font-mono text-sm text-slate-300">{packet.packet_details.tcp_ack}</p>
                                        </div>
                                    )}
                                    {packet.packet_details.tcp_flags !== "N/A" && (
                                        <div className="bg-slate-800/50 p-3 rounded-lg border border-slate-700/50">
                                            <p className="text-xs text-slate-500">TCP Flags</p>
                                            <p className="font-mono text-sm text-emerald-400">{packet.packet_details.tcp_flags}</p>
                                        </div>
                                    )}
                                    {packet.packet_details.tcp_window !== "N/A" && (
                                        <div className="bg-slate-800/50 p-3 rounded-lg border border-slate-700/50">
                                            <p className="text-xs text-slate-500">TCP Window</p>
                                            <p className="font-mono text-sm text-slate-300">{packet.packet_details.tcp_window}</p>
                                        </div>
                                    )}
                                </div>
                            </div>
                        )}

                        {/* Alert Details - Collapsible */}
                        <div className="bg-red-500/5 border border-red-500/20 rounded-lg overflow-hidden">
                            <div
                                onClick={() => setAlertExpanded(!alertExpanded)}
                                className="p-4 cursor-pointer hover:bg-red-500/10 transition-colors flex items-center justify-between"
                            >
                                <h4 className="text-sm font-bold text-red-400 uppercase tracking-wider flex items-center gap-2">
                                    {alertExpanded ? <ChevronDown className="w-4 h-4" /> : <ChevronRight className="w-4 h-4" />}
                                    Alert Description
                                </h4>
                                <span className="text-xs text-slate-500">Click to {alertExpanded ? 'collapse' : 'expand'}</span>
                            </div>
                            <AnimatePresence>
                                {alertExpanded && (
                                    <motion.div
                                        initial={{ height: 0, opacity: 0 }}
                                        animate={{ height: 'auto', opacity: 1 }}
                                        exit={{ height: 0, opacity: 0 }}
                                        transition={{ duration: 0.2 }}
                                        className="overflow-hidden"
                                    >
                                        <div className="p-4 pt-0">
                                            {/* Check if this is a port scan with port list */}
                                            {packet.details && packet.details.includes('Scanned') && packet.details.includes('unique ports:') ? (
                                                <div>
                                                    <p className="text-slate-300 text-sm mb-3">
                                                        {packet.details.split(':')[0]}:
                                                    </p>
                                                    <div className="bg-slate-800/50 rounded-lg border border-slate-700 p-3 max-h-64 overflow-y-auto custom-scrollbar">
                                                        <div className="grid grid-cols-4 md:grid-cols-6 lg:grid-cols-8 gap-2">
                                                            {(() => {
                                                                // Extract ports from details string
                                                                const match = packet.details.match(/\[(.*?)\]/);
                                                                if (match) {
                                                                    const portsStr = match[1];
                                                                    const ports = portsStr.split(',').map(p => p.trim());
                                                                    return ports.map((port, idx) => (
                                                                        <div
                                                                            key={idx}
                                                                            className="bg-slate-900/50 border border-slate-600 rounded px-2 py-1 text-center font-mono text-xs text-cyan-400 hover:bg-slate-900 transition-colors"
                                                                        >
                                                                            {port}
                                                                        </div>
                                                                    ));
                                                                }
                                                                return null;
                                                            })()}
                                                        </div>
                                                    </div>
                                                </div>
                                            ) : (
                                                <p className="text-slate-300 text-sm whitespace-pre-wrap">{packet.details}</p>
                                            )}
                                        </div>
                                    </motion.div>
                                )}
                            </AnimatePresence>
                        </div>

                        {/* Hex Dump */}
                        <div>
                            <div className="flex items-center justify-between mb-2">
                                <h4 className="text-sm font-bold text-slate-400 uppercase tracking-wider">Hex Dump</h4>
                                <button
                                    onClick={() => copyToClipboard(packet.full_hex || '', 'hex')}
                                    className="text-xs flex items-center gap-1 text-primary hover:text-white transition-colors px-2 py-1 rounded hover:bg-slate-800"
                                >
                                    {copiedHex ? (
                                        <>
                                            <Check className="w-3 h-3" /> Copied!
                                        </>
                                    ) : (
                                        <>
                                            <Copy className="w-3 h-3" /> Copy
                                        </>
                                    )}
                                </button>
                            </div>
                            <div className="bg-black/50 rounded-lg p-4 font-mono text-xs text-slate-400 overflow-x-auto border border-slate-800 max-h-64 overflow-y-auto custom-scrollbar">
                                <pre>{packet.full_hex || "No hex data available"}</pre>
                            </div>
                        </div>

                        {/* ASCII Dump */}
                        <div>
                            <div className="flex items-center justify-between mb-2">
                                <h4 className="text-sm font-bold text-slate-400 uppercase tracking-wider">ASCII Representation</h4>
                                <button
                                    onClick={() => copyToClipboard(packet.full_ascii || '', 'ascii')}
                                    className="text-xs flex items-center gap-1 text-emerald-400 hover:text-emerald-300 transition-colors px-2 py-1 rounded hover:bg-slate-800"
                                >
                                    {copiedAscii ? (
                                        <>
                                            <Check className="w-3 h-3" /> Copied!
                                        </>
                                    ) : (
                                        <>
                                            <Copy className="w-3 h-3" /> Copy
                                        </>
                                    )}
                                </button>
                            </div>
                            <div className="bg-black/50 rounded-lg p-4 font-mono text-xs text-emerald-400 overflow-x-auto border border-slate-800 whitespace-pre-wrap max-h-64 overflow-y-auto custom-scrollbar">
                                {packet.full_ascii || "No ASCII data available"}
                            </div>
                        </div>
                    </div>
                </motion.div>
            </div>
        </AnimatePresence>
    );
};

export default PacketViewer;
