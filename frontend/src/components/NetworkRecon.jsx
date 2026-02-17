import { useState } from 'react';
import { Play, Network, Server, Globe, MapPin } from 'lucide-react';
import { createScan, runNetworkRecon, updateScan } from '../lib/scanStorage';

function NetworkRecon() {
  const [target, setTarget] = useState('');
  const [scanType, setScanType] = useState('subnet');
  const [scanning, setScanning] = useState(false);
  const [hosts, setHosts] = useState([]);
  const [domainInfo, setDomainInfo] = useState(null);
  const [progress, setProgress] = useState(0);
  const [error, setError] = useState('');

  const startScan = async () => {
    if (!target.trim()) return;

    setScanning(true);
    setError('');
    setHosts([]);
    setDomainInfo(null);
    setProgress(15);

    let scan = null;
    try {
      scan = await createScan({
        scan_type: 'reconnaissance',
        target: target.trim(),
        status: 'running',
      });
    } catch (storageError) {
      console.error('Failed to create scan record:', storageError);
    }

    try {
      setProgress(45);
      const response = await runNetworkRecon({
        target: target.trim(),
        scan_type: scanType,
      });
      setProgress(85);

      if (scanType === 'subnet') {
        const discoveredHosts = response?.results?.hosts || [];
        setHosts(discoveredHosts);
        if (scan?.id) {
          await updateScan(scan.id, {
            status: 'completed',
            results: { hosts: discoveredHosts },
            completed_at: new Date().toISOString(),
          });
        }
      } else {
        const info = response?.results?.domain || null;
        setDomainInfo(info);
        if (scan?.id) {
          await updateScan(scan.id, {
            status: 'completed',
            results: { domain: info },
            completed_at: new Date().toISOString(),
          });
        }
      }

      setProgress(100);
    } catch (scanError) {
      setError(scanError.message || 'Network reconnaissance failed.');
      if (scan?.id) {
        try {
          await updateScan(scan.id, {
            status: 'failed',
            completed_at: new Date().toISOString(),
            results: { error: scanError.message || 'Network reconnaissance failed.' },
          });
        } catch (storageError) {
          console.error('Failed to update failed scan record:', storageError);
        }
      }
    } finally {
      setScanning(false);
    }
  };

  return (
    <div className="cyber-page">
      <div className={`card cyber-card mb-4 ${scanning ? 'cyber-scan-active' : ''}`}>
        <div className="card-body p-4">
          <h2 className="cyber-section-title mb-4">
            <Network size={22} className="text-primary" /> Network Reconnaissance
          </h2>

          {error && <div className="alert alert-danger py-2 mb-3">{error}</div>}

          <label className="form-label cyber-label">Scan Type</label>
          <div className="row g-2 mb-3">
            <div className="col-6">
              <button
                onClick={() => setScanType('subnet')}
                disabled={scanning}
                className={`btn w-100 py-3 cyber-toggle ${scanType === 'subnet' ? 'active' : ''}`}
              >
                <Server size={20} />
                <div>Subnet Discovery</div>
              </button>
            </div>
            <div className="col-6">
              <button
                onClick={() => setScanType('domain')}
                disabled={scanning}
                className={`btn w-100 py-3 cyber-toggle ${scanType === 'domain' ? 'active' : ''}`}
              >
                <Globe size={20} />
                <div>Domain Info</div>
              </button>
            </div>
          </div>

          <label className="form-label cyber-label">{scanType === 'subnet' ? 'Network Range' : 'Domain Name'}</label>
          <input
            type="text"
            value={target}
            onChange={(e) => setTarget(e.target.value)}
            placeholder={scanType === 'subnet' ? 'e.g., 192.168.1.0/24' : 'e.g., example.com'}
            disabled={scanning}
            className="form-control cyber-input mb-3"
          />

          <button onClick={startScan} disabled={!target.trim() || scanning} className="btn btn-cyber-primary w-100">
            <Play size={18} /> {scanning ? 'Scanning...' : 'Start Reconnaissance'}
          </button>

          {scanning && (
            <div className="mt-3">
              <div className="d-flex justify-content-between small text-secondary mb-2">
                <span><span className="scan-dot" />{scanType === 'subnet' ? 'Discovering hosts...' : 'Gathering domain information...'}</span>
                <span>{Math.round(progress)}%</span>
              </div>
              <div className="progress cyber-progress">
                <div className="progress-bar bg-primary" style={{ width: `${progress}%` }} />
              </div>
            </div>
          )}
        </div>
      </div>

      {scanType === 'subnet' && hosts.length > 0 && (
        <div className="card cyber-card mb-4">
          <div className="card-body p-4">
            <div className="d-flex justify-content-between align-items-center mb-3">
              <h3 className="h5 m-0">Discovered Hosts</h3>
              <span className="small text-secondary">{hosts.length} found</span>
            </div>
            <div className="cyber-scroll">
              {hosts.map((host, index) => (
                <div key={`${host.ip}-${index}`} className="cyber-result-item open result-enter" style={{ '--item-index': index }}>
                  <div className="d-flex justify-content-between align-items-start">
                    <div className="d-flex gap-2 align-items-start">
                      <MapPin size={16} className="text-primary mt-1" />
                      <div>
                        <div className="fw-semibold ip-text">{host.ip}</div>
                        <div className="small text-secondary">{host.hostname}</div>
                      </div>
                    </div>
                    <span className="badge text-bg-success">ACTIVE</span>
                  </div>
                  <div className="small text-secondary mt-2">
                    {host.mac} | {host.vendor}
                  </div>
                  {!!host.open_ports?.length && (
                    <div className="small text-secondary mt-1">
                      Open ports:{' '}
                      {host.open_ports
                        .slice(0, 6)
                        .map((entry) => `${entry.port}/${entry.protocol} (${entry.service})`)
                        .join(', ')}
                    </div>
                  )}
                </div>
              ))}
            </div>
          </div>
        </div>
      )}

      {scanType === 'domain' && domainInfo && (
        <div className="row g-3">
          <div className="col-lg-6">
            <div className="card cyber-card h-100">
              <div className="card-body p-4">
                <h3 className="h5 mb-3">Domain Information</h3>
                <ul className="list-unstyled m-0">
                  <li className="mb-2"><span className="text-secondary">Domain:</span> {domainInfo.domain}</li>
                  <li className="mb-2"><span className="text-secondary">Registrar:</span> {domainInfo.registrar}</li>
                  <li className="mb-2"><span className="text-secondary">Organization:</span> {domainInfo.organization || 'Unknown'}</li>
                  <li className="mb-2"><span className="text-secondary">WHOIS Server:</span> {domainInfo.whois_server || 'Unknown'}</li>
                  <li className="mb-2"><span className="text-secondary">Created:</span> {domainInfo.created}</li>
                  <li className="mb-3"><span className="text-secondary">Expires:</span> {domainInfo.expires}</li>
                  {!!domainInfo.status?.length && (
                    <li className="mb-3">
                      <span className="text-secondary">Status:</span> {domainInfo.status.slice(0, 3).join(' | ')}
                    </li>
                  )}
                  <li className="text-secondary small mb-1">Nameservers</li>
                  {domainInfo.nameservers?.length ? (
                    domainInfo.nameservers.map((ns, index) => (
                      <li key={`${ns}-${index}`} className="ip-text">{ns}</li>
                    ))
                  ) : (
                    <li className="small text-secondary">No nameservers available</li>
                  )}
                </ul>
              </div>
            </div>
          </div>
          <div className="col-lg-6">
            <div className="card cyber-card h-100">
              <div className="card-body p-4">
                <h3 className="h5 mb-3">DNS Records</h3>
                <div className="cyber-scroll">
                  {(domainInfo.openPorts || []).map((entry, index) => (
                    <div key={`open-port-${entry.port}-${index}`} className="cyber-result-item result-enter" style={{ '--item-index': index }}>
                      <span className="badge text-bg-success me-2">{entry.port}/{entry.protocol}</span>
                      <span className="ip-text">{entry.service}</span>
                      {(entry.product || entry.version) && (
                        <span className="small text-secondary ms-2">{entry.product} {entry.version}</span>
                      )}
                    </div>
                  ))}
                  {(domainInfo.dnsRecords || []).map((record, index) => (
                    <div key={`${record.type}-${record.value}-${index}`} className="cyber-result-item result-enter" style={{ '--item-index': index }}>
                      <span className="badge text-bg-primary me-2">{record.type}</span>
                      <span className="ip-text">{record.value}</span>
                    </div>
                  ))}
                  {!domainInfo.dnsRecords?.length && (
                    <div className="small text-secondary">No DNS records found.</div>
                  )}
                </div>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

export default NetworkRecon;
