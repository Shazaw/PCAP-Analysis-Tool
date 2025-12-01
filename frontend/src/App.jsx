import React, { useState } from 'react';
import Sidebar from './components/Sidebar';
import Dashboard from './components/Dashboard';
import History from './components/History';
import PacketViewer from './components/PacketViewer';

function App() {
    const [activeTab, setActiveTab] = useState('dashboard');
    const [currentReport, setCurrentReport] = useState(null);
    const [selectedPacket, setSelectedPacket] = useState(null);

    const handleViewReport = (report) => {
        setCurrentReport(report);
        setActiveTab('dashboard');
    };

    // Inject report into Dashboard if viewing from history
    const renderContent = () => {
        switch (activeTab) {
            case 'dashboard':
                return (
                    <Dashboard
                        initialReport={currentReport}
                        onViewReport={handleViewReport}
                        onViewPacket={setSelectedPacket}
                    />
                );
            case 'history':
                return <History onViewReport={handleViewReport} />;
            default:
                return <Dashboard />;
        }
    };

    return (
        <div className="flex min-h-screen bg-bg text-white font-sans">
            <Sidebar activeTab={activeTab} setActiveTab={setActiveTab} />

            <main className="flex-1 ml-64 p-8">
                {renderContent()}
            </main>

            <PacketViewer
                isOpen={!!selectedPacket}
                onClose={() => setSelectedPacket(null)}
                packet={selectedPacket}
            />
        </div>
    );
}

export default App;
