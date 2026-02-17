import { useEffect, useState } from 'react';
import { FileText, Calendar, Target, Activity, Trash2, Eye } from 'lucide-react';
import { deleteScan as deleteStoredScan, getScans } from '../lib/scanStorage';

function ReportsDashboard() {
  const [scans, setScans] = useState([]);
  const [loading, setLoading] = useState(true);
  const [selectedScan, setSelectedScan] = useState(null);
  const [vulnerabilities, setVulnerabilities] = useState([]);

  useEffect(() => {
    loadScans();
  }, []);

  const loadScans = async () => {
    setLoading(true);
    try {
      const data = await getScans();
      setScans(data);
    } catch (error) {
      console.error('Failed to load scans:', error);
      setScans([]);
    } finally {
      setLoading(false);
    }
  };

  const viewScan = (scan) => {
    setSelectedScan(scan);
    setVulnerabilities(scan.results?.vulnerabilities || []);
  };

  const deleteScan = async (scanId) => {
    try {
      await deleteStoredScan(scanId);
      setScans((prev) => prev.filter((scan) => scan.id !== scanId));
      if (selectedScan?.id === scanId) {
        setSelectedScan(null);
        setVulnerabilities([]);
      }
    } catch (error) {
      console.error('Failed to delete scan:', error);
    }
  };

  const getScanTypeIcon = (type) => {
    if (type === 'port') return <Activity size={18} className="text-info" />;
    if (type === 'vulnerability') return <Target size={18} className="text-orange" />;
    if (type === 'reconnaissance') return <Eye size={18} className="text-primary" />;
    return <FileText size={18} className="text-secondary" />;
  };

  const getScanTypeClass = (type) => {
    if (type === 'port') return 'badge text-bg-info';
    if (type === 'vulnerability') return 'badge sev-high';
    if (type === 'reconnaissance') return 'badge text-bg-primary';
    return 'badge text-bg-secondary';
  };

  const getStatusClass = (status) => {
    if (status === 'completed') return 'badge text-bg-success';
    if (status === 'running') return 'badge text-bg-primary';
    if (status === 'failed') return 'badge text-bg-danger';
    return 'badge text-bg-secondary';
  };

  const getSeverityClass = (severity) => {
    if (severity === 'critical') return 'sev-critical';
    if (severity === 'high') return 'sev-high';
    if (severity === 'medium') return 'sev-medium';
    if (severity === 'low') return 'sev-low';
    return 'text-bg-secondary';
  };

  const formatDate = (dateString) => new Date(dateString).toLocaleString();

  if (loading) {
    return (
      <div className="card cyber-card">
        <div className="card-body text-center p-5 text-secondary">Loading scans...</div>
      </div>
    );
  }

  return (
    <div className="cyber-page">
      <div className="card cyber-card mb-4">
        <div className="card-body p-4">
          <div className="d-flex justify-content-between align-items-center mb-3">
            <h2 className="cyber-section-title m-0">
              <FileText size={22} className="text-info" /> Scan History
            </h2>
            <span className="small text-secondary">{scans.length} total</span>
          </div>

          {scans.length === 0 ? (
            <div className="text-center py-5 text-secondary">No scans yet. Run a scan to populate reports.</div>
          ) : (
            <div className="cyber-scroll">
              {scans.map((scan, index) => (
                <div
                  key={scan.id}
                  className={`cyber-result-item result-enter ${selectedScan?.id === scan.id ? 'selected' : ''}`}
                  style={{ '--item-index': index }}
                >
                  <div className="d-flex justify-content-between align-items-start gap-3">
                    <div className="d-flex gap-3 align-items-start flex-grow-1">
                      {getScanTypeIcon(scan.scan_type)}
                      <div className="flex-grow-1">
                        <div className="d-flex flex-wrap align-items-center gap-2 mb-1">
                          <span className="fw-semibold">{scan.target}</span>
                          <span className={getScanTypeClass(scan.scan_type)}>{scan.scan_type}</span>
                          <span className={getStatusClass(scan.status)}>{scan.status}</span>
                        </div>
                        <div className="small text-secondary d-flex align-items-center gap-1">
                          <Calendar size={14} /> {formatDate(scan.created_at)}
                        </div>
                      </div>
                    </div>
                    <div className="d-flex gap-2">
                      <button onClick={() => viewScan(scan)} className="btn btn-sm btn-cyber-muted">
                        <Eye size={15} />
                      </button>
                      <button onClick={() => deleteScan(scan.id)} className="btn btn-sm btn-outline-danger">
                        <Trash2 size={15} />
                      </button>
                    </div>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>

      {selectedScan && (
        <div className="card cyber-card">
          <div className="card-body p-4">
            <h3 className="h5 mb-3">Scan Details</h3>
            <div className="row g-2 mb-3 small">
              <div className="col-md-6"><span className="text-secondary">Target:</span> {selectedScan.target}</div>
              <div className="col-md-6"><span className="text-secondary">Type:</span> {selectedScan.scan_type}</div>
              <div className="col-md-6"><span className="text-secondary">Status:</span> {selectedScan.status}</div>
              <div className="col-md-6"><span className="text-secondary">Started:</span> {formatDate(selectedScan.created_at)}</div>
            </div>

            {selectedScan.scan_type === 'port' && selectedScan.results?.ports && (
              <div className="mb-3">
                <h4 className="h6 mb-2">Open Ports</h4>
                <div className="cyber-scroll">
                  {selectedScan.results.ports.map((port, index) => (
                    <div key={index} className="cyber-result-item result-enter" style={{ '--item-index': index }}>
                      <div className="d-flex justify-content-between align-items-center">
                        <div className="d-flex gap-2 align-items-center">
                          <span className="cyber-port-pill">{port.port}</span>
                          <span>{port.service}</span>
                        </div>
                        <span className={`badge ${port.risk === 'high' ? 'sev-critical' : port.risk === 'medium' ? 'sev-medium' : 'sev-low'}`}>
                          {port.risk} risk
                        </span>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {selectedScan.scan_type === 'vulnerability' && vulnerabilities.length > 0 && (
              <div className="mb-3">
                <h4 className="h6 mb-2">Vulnerabilities ({vulnerabilities.length})</h4>
                <div className="cyber-scroll">
                  {vulnerabilities.map((vuln) => (
                    <div key={vuln.id} className="cyber-result-item result-enter">
                      <div className="d-flex justify-content-between align-items-start gap-2">
                        <div>
                          <div className="fw-semibold">{vuln.title}</div>
                          <div className="small text-secondary">{vuln.description}</div>
                          <div className="small text-orange">CVSS: {vuln.cvss_score ?? vuln.cvss}</div>
                          {(vuln.host || vuln.port) && (
                            <div className="small text-secondary">
                              {vuln.host ? `Host: ${vuln.host} | ` : ''}Service: {vuln.service}:{vuln.port}
                            </div>
                          )}
                          {(vuln.product || vuln.version) && (
                            <div className="small text-secondary">Version: {vuln.product} {vuln.version}</div>
                          )}
                          {vuln.remediation && <div className="small text-success">Remediation: {vuln.remediation}</div>}
                        </div>
                        <span className={`badge ${getSeverityClass(vuln.severity)}`}>{vuln.severity}</span>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {selectedScan.scan_type === 'reconnaissance' && selectedScan.results?.hosts && (
              <div>
                <h4 className="h6 mb-2">Discovered Hosts ({selectedScan.results.hosts.length})</h4>
                <div className="cyber-scroll">
                  {selectedScan.results.hosts.map((host, index) => (
                    <div key={index} className="cyber-result-item result-enter" style={{ '--item-index': index }}>
                      <div className="d-flex justify-content-between align-items-center">
                        <span className="ip-text">{host.ip}</span>
                        <span className="small text-secondary">{host.hostname}</span>
                      </div>
                      <div className="small text-secondary">{host.mac} | {host.vendor}</div>
                      {!!host.open_ports?.length && (
                        <div className="small text-secondary">
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
            )}

            {selectedScan.scan_type === 'reconnaissance' && selectedScan.results?.domain && (
              <div className="mb-3">
                <h4 className="h6 mb-2">Domain Intelligence</h4>
                <div className="cyber-result-item">
                  <div className="small text-secondary">Domain: <span className="ip-text">{selectedScan.results.domain.domain}</span></div>
                  <div className="small text-secondary">Registrar: {selectedScan.results.domain.registrar}</div>
                  <div className="small text-secondary">Organization: {selectedScan.results.domain.organization || 'Unknown'}</div>
                  <div className="small text-secondary">WHOIS Server: {selectedScan.results.domain.whois_server || 'Unknown'}</div>
                  <div className="small text-secondary">Created: {selectedScan.results.domain.created}</div>
                  <div className="small text-secondary">Expires: {selectedScan.results.domain.expires}</div>
                  {!!selectedScan.results.domain.status?.length && (
                    <div className="small text-secondary">Status: {selectedScan.results.domain.status.slice(0, 3).join(' | ')}</div>
                  )}
                </div>
                <div className="cyber-scroll mt-2">
                  {(selectedScan.results.domain.openPorts || []).map((record, index) => (
                    <div key={`open-${index}`} className="cyber-result-item result-enter" style={{ '--item-index': index }}>
                      <span className="badge text-bg-success me-2">{record.port}/{record.protocol}</span>
                      <span className="ip-text">{record.service}</span>
                      {(record.product || record.version) && (
                        <span className="small text-secondary ms-2">{record.product} {record.version}</span>
                      )}
                    </div>
                  ))}
                  {(selectedScan.results.domain.dnsRecords || []).map((record, index) => (
                    <div key={index} className="cyber-result-item result-enter" style={{ '--item-index': index }}>
                      <span className="badge text-bg-primary me-2">{record.type}</span>
                      <span className="ip-text">{record.value}</span>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
}

export default ReportsDashboard;
