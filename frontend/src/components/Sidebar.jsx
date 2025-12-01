import React from 'react';
import { LayoutDashboard, History, Shield } from 'lucide-react';

const Sidebar = ({ activeTab, setActiveTab }) => {
    const menuItems = [
        { id: 'dashboard', label: 'New Scan', icon: LayoutDashboard },
        { id: 'history', label: 'Scan History', icon: History },
    ];

    return (
        <div className="w-64 h-screen bg-slate-900/95 border-r border-slate-700/50 fixed left-0 top-0 backdrop-blur-xl flex flex-col p-6 z-50">
            <div className="flex items-center gap-3 mb-10">
                <Shield className="w-8 h-8 text-primary" />
                <h1 className="text-2xl font-bold bg-gradient-to-r from-primary to-accent bg-clip-text text-transparent">
                    NetGuard
                </h1>
            </div>

            <nav className="space-y-2">
                {menuItems.map((item) => {
                    const Icon = item.icon;
                    const isActive = activeTab === item.id;

                    return (
                        <button
                            key={item.id}
                            onClick={() => setActiveTab(item.id)}
                            className={`w-full flex items-center gap-3 px-4 py-3 rounded-lg transition-all duration-200 font-medium ${isActive
                                    ? 'bg-primary/10 text-primary shadow-[0_0_20px_rgba(56,189,248,0.1)]'
                                    : 'text-slate-400 hover:text-white hover:bg-white/5'
                                }`}
                        >
                            <Icon className="w-5 h-5" />
                            {item.label}
                        </button>
                    );
                })}
            </nav>

            <div className="mt-auto pt-6 border-t border-slate-800">
                <p className="text-xs text-slate-500 text-center">
                    Network Analysis Tool v2.0
                </p>
            </div>
        </div>
    );
};

export default Sidebar;
