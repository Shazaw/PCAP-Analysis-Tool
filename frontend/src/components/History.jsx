import React, { useEffect, useState } from 'react';
import axios from 'axios';
import { Clock, FileText, ChevronRight, Search } from 'lucide-react';
import { motion } from 'framer-motion';

const History = ({ onViewReport }) => {
    const [scans, setScans] = useState([]);
    const [loading, setLoading] = useState(true);
    const [searchTerm, setSearchTerm] = useState('');

    useEffect(() => {
        fetchHistory();
    }, []);

    const fetchHistory = async () => {
        try {
            const response = await axios.get('http://localhost:8080/api/history');
            setScans(response.data);
        } catch (error) {
            console.error('Failed to fetch history:', error);
        } finally {
            setLoading(false);
        }
    };

    const filteredScans = scans.filter(scan =>
        scan.filename.toLowerCase().includes(searchTerm.toLowerCase())
    );

    const handleViewReport = async (scanId) => {
        try {
            const response = await axios.get(`http://localhost:8080/api/report/${scanId}`);
            onViewReport(response.data);
        } catch (error) {
            console.error('Failed to load report:', error);
        }
    };

    return (
        <div className="space-y-6">
            <div className="flex justify-between items-center mb-8">
                <h2 className="text-3xl font-bold text-white">Scan History</h2>
                <div className="relative">
                    <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 text-slate-400 w-4 h-4" />
                    <input
                        type="text"
                        placeholder="Search files..."
                        value={searchTerm}
                        onChange={(e) => setSearchTerm(e.target.value)}
                        className="bg-slate-800/50 border border-slate-700 rounded-lg pl-10 pr-4 py-2 text-sm text-white focus:outline-none focus:border-primary transition-colors w-64"
                    />
                </div>
            </div>

            <div className="glass-card overflow-hidden">
                <table className="w-full text-left">
                    <thead>
                        <tr className="bg-slate-800/50 text-slate-400 text-sm uppercase tracking-wider">
                            <th className="p-4 font-medium">ID</th>
                            <th className="p-4 font-medium">Filename</th>
                            <th className="p-4 font-medium">Date Analyzed</th>
                            <th className="p-4 font-medium text-right">Packets</th>
                            <th className="p-4 font-medium text-right">Threats</th>
                            <th className="p-4 font-medium text-right">Action</th>
                        </tr>
                    </thead>
                    <tbody className="divide-y divide-slate-700/50">
                        {loading ? (
                            <tr>
                                <td colSpan="6" className="p-8 text-center text-slate-500">Loading history...</td>
                            </tr>
                        ) : filteredScans.length === 0 ? (
                            <tr>
                                <td colSpan="6" className="p-8 text-center text-slate-500">No scans found</td>
                            </tr>
                        ) : (
                            filteredScans.map((scan) => (
                                <motion.tr
                                    key={scan.id}
                                    initial={{ opacity: 0 }}
                                    animate={{ opacity: 1 }}
                                    className="hover:bg-white/5 transition-colors group"
                                >
                                    <td className="p-4 text-slate-500 font-mono">#{scan.id}</td>
                                    <td className="p-4 font-medium text-white flex items-center gap-2">
                                        <FileText className="w-4 h-4 text-primary" />
                                        {scan.filename}
                                    </td>
                                    <td className="p-4 text-slate-400">
                                        <div className="flex items-center gap-2">
                                            <Clock className="w-3 h-3" />
                                            {scan.timestamp}
                                        </div>
                                    </td>
                                    <td className="p-4 text-right text-slate-300">{scan.packet_count.toLocaleString()}</td>
                                    <td className="p-4 text-right">
                                        <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium ${scan.malicious_count > 0
                                                ? 'bg-red-500/10 text-red-400'
                                                : 'bg-green-500/10 text-green-400'
                                            }`}>
                                            {scan.malicious_count}
                                        </span>
                                    </td>
                                    <td className="p-4 text-right">
                                        <button
                                            onClick={() => handleViewReport(scan.id)}
                                            className="text-primary hover:text-white transition-colors p-2 rounded-lg hover:bg-primary/10"
                                        >
                                            <ChevronRight className="w-4 h-4" />
                                        </button>
                                    </td>
                                </motion.tr>
                            ))
                        )}
                    </tbody>
                </table>
            </div>
        </div>
    );
};

export default History;
