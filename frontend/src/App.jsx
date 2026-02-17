import { useState } from 'react';
import { Shield, Activity, Search, FileText, AlertTriangle } from 'lucide-react';
import PortScanner from './components/PortScanner';
import VulnerabilityScanner from './components/VulnerabilityScanner';
import NetworkRecon from './components/NetworkRecon';
import ReportsDashboard from './components/ReportsDashboard';
import 'bootstrap/dist/css/bootstrap.min.css';

function App() {
  const [activeTab, setActiveTab] = useState('port-scanner');

  const tabs = [
    { id: 'port-scanner', name: 'Port Scanner', icon: Activity },
    { id: 'vuln-scanner', name: 'Vulnerability Scanner', icon: AlertTriangle },
    { id: 'network-recon', name: 'Network Recon', icon: Search },
    { id: 'reports', name: 'Reports', icon: FileText },
  ];

  const renderContent = () => {
    switch (activeTab) {
      case 'port-scanner':
        return <PortScanner />;
      case 'vuln-scanner':
        return <VulnerabilityScanner />;
      case 'network-recon':
        return <NetworkRecon />;
      case 'reports':
        return <ReportsDashboard />;
      default:
        return <PortScanner />;
    }
  };

  return (
    <div className="cyber-app">
      <div className="cyber-grid-overlay" />
      <header className="cyber-header py-3 result-enter">
        <div className="container">
          <div className="d-flex align-items-center justify-content-between gap-3">
            <div className="d-flex align-items-center gap-3">
              <div className="cyber-logo-wrap">
                <Shield size={24} className="text-info" />
              </div>
              <div>
                <h1 className="cyber-title m-0">CyberGuard PenTest</h1>
                <p className="cyber-subtitle m-0">Offensive Security Console</p>
              </div>
            </div>
            <div className="d-none d-sm-flex align-items-center gap-2 cyber-warning-pill">
              <AlertTriangle size={16} className="text-warning" />
              <span>Authorized Use Only</span>
            </div>
          </div>
        </div>
      </header>

      <main className="container py-4">
        <div className="cyber-nav p-2 mb-4 result-enter" style={{ '--item-index': 1 }}>
          <div className="row g-2">
            {tabs.map((tab) => {
              const Icon = tab.icon;
              return (
                <div key={tab.id} className="col-6 col-lg-3">
                  <button
                    onClick={() => setActiveTab(tab.id)}
                    className={`btn w-100 cyber-tab-btn ${activeTab === tab.id ? 'active' : ''}`}
                  >
                    <Icon size={18} />
                    <span>{tab.name}</span>
                  </button>
                </div>
              );
            })}
          </div>
        </div>

        <div className="result-enter" style={{ '--item-index': 2 }}>{renderContent()}</div>
      </main>

      <footer className="cyber-footer py-3">
        <div className="container">
          <p className="text-center m-0">
            Educational and authorized penetration testing only. Unauthorized access is illegal.
          </p>
        </div>
      </footer>
    </div>
  );
}

export default App;
