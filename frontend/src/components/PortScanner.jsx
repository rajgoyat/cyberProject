import { useState } from 'react';
import { Play, Download, Wifi } from 'lucide-react';
import { createScan, runPortScan, updateScan } from '../lib/scanStorage';

const DEFAULT_PORTS = '21,22,23,25,80,443,3306,5432,8080,3389';

function parsePorts(portsInput) {
  const values = portsInput
    .split(',')
    .map((value) => Number.parseInt(value.trim(), 10))
    .filter((value) => Number.isInteger(value) && value >= 1 && value <= 65535);

  return [...new Set(values)];
}

function PortScanner() {
  const [target, setTarget] = useState('');
  const [targetPorts, setTargetPorts] = useState(DEFAULT_PORTS);
  const [scanning, setScanning] = useState(false);
  const [results, setResults] = useState([]);
  const [progress, setProgress] = useState(0);
  const [error, setError] = useState('');

  const startScan = async () => {
    if (!target.trim()) return;

    const ports = parsePorts(targetPorts);
    if (!ports.length) {
      setError('Provide at least one valid port (1-65535).');
      return;
    }

    setScanning(true);
    setError('');
    setResults([]);
    setProgress(15);

    let scan = null;
    try {
      scan = await createScan({
        scan_type: 'port',
        target: target.trim(),
        status: 'running',
      });
    } catch (storageError) {
      console.error('Failed to create scan record:', storageError);
    }

    try {
      setProgress(45);
      const response = await runPortScan({
        target: target.trim(),
        ports,
      });
      const scanResults = response?.results || [];
      const openPorts = scanResults.filter((entry) => entry.status === 'OPEN');

      setResults(scanResults);
      setProgress(100);

      if (scan?.id) {
        await updateScan(scan.id, {
          status: 'completed',
          results: { ports: openPorts, total_scanned: scanResults.length },
          completed_at: new Date().toISOString(),
        });
      }
    } catch (scanError) {
      setError(scanError.message || 'Port scan failed.');
      if (scan?.id) {
        try {
          await updateScan(scan.id, {
            status: 'failed',
            completed_at: new Date().toISOString(),
            results: { error: scanError.message || 'Port scan failed.' },
          });
        } catch (storageError) {
          console.error('Failed to update failed scan record:', storageError);
        }
      }
    } finally {
      setScanning(false);
    }
  };

  const exportResults = () => {
    const openPorts = results.filter((result) => result.status === 'OPEN');
    const report = {
      target,
      scan_date: new Date().toISOString(),
      total_ports_scanned: results.length,
      open_ports: openPorts.length,
      ports: openPorts,
    };

    const blob = new Blob([JSON.stringify(report, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `port-scan-${target}-${Date.now()}.json`;
    a.click();
  };

  const getRiskClass = (risk) => {
    if (risk === 'high') return 'risk-high';
    if (risk === 'medium') return 'risk-medium';
    return 'risk-low';
  };

  const openPortsCount = results.filter((result) => result.status === 'OPEN').length;

  return (
    <div className="cyber-page">
      <div className={`card cyber-card mb-4 ${scanning ? 'cyber-scan-active' : ''}`}>
        <div className="card-body p-4">
          <h2 className="cyber-section-title mb-4">
            <Wifi size={22} className="text-info" /> Port Scanner
          </h2>

          {error && <div className="alert alert-danger py-2 mb-3">{error}</div>}

          <label className="form-label cyber-label">Target IP or Domain</label>
          <input
            type="text"
            value={target}
            onChange={(event) => setTarget(event.target.value)}
            placeholder="e.g., 192.168.1.1 or example.com"
            disabled={scanning}
            className="form-control cyber-input mb-3"
          />

          <label className="form-label cyber-label">Ports (comma separated)</label>
          <input
            type="text"
            value={targetPorts}
            onChange={(event) => setTargetPorts(event.target.value)}
            placeholder="e.g., 21,22,80,443"
            disabled={scanning}
            className="form-control cyber-input mb-3"
          />

          <div className="d-flex flex-column flex-md-row gap-2 mb-3">
            <button onClick={startScan} disabled={!target.trim() || scanning} className="btn btn-cyber-info flex-fill">
              <Play size={18} /> {scanning ? 'Scanning...' : 'Start Scan'}
            </button>

            {results.length > 0 && !scanning && (
              <button onClick={exportResults} className="btn btn-cyber-muted">
                <Download size={18} /> Export
              </button>
            )}
          </div>

          {scanning && (
            <>
              <div className="d-flex justify-content-between small text-secondary mb-2">
                <span><span className="scan-dot" />Scanning in progress...</span>
                <span>{Math.round(progress)}%</span>
              </div>
              <div className="progress cyber-progress">
                <div className="progress-bar bg-info" style={{ width: `${progress}%` }} />
              </div>
            </>
          )}
        </div>
      </div>

      {results.length > 0 && (
        <div className="card cyber-card">
          <div className="card-body p-4">
            <div className="d-flex flex-wrap align-items-center justify-content-between gap-2 mb-3">
              <h3 className="h5 m-0">Scan Results</h3>
              <div className="small text-secondary">
                Total <span className="text-light fw-semibold">{results.length}</span> | Open{' '}
                <span className="text-info fw-semibold">{openPortsCount}</span>
              </div>
            </div>

            <div className="cyber-scroll">
              {results.map((result, index) => (
                <div
                  key={`${result.port}-${index}`}
                  className={`cyber-result-item result-enter ${result.status === 'OPEN' ? 'open' : 'closed'}`}
                  style={{ '--item-index': index }}
                >
                  <div className="d-flex justify-content-between align-items-start gap-3">
                    <div className="d-flex gap-3 align-items-center">
                      <span className="cyber-port-pill">{result.port}</span>
                      <div>
                        <div className="fw-semibold">{result.service}</div>
                        {result.banner && <div className="small text-secondary">{result.banner}</div>}
                      </div>
                    </div>
                    <div className="d-flex gap-2">
                      <span className={`badge ${result.status === 'OPEN' ? 'text-bg-success' : 'text-bg-secondary'}`}>
                        {result.status}
                      </span>
                      {result.status === 'OPEN' && <span className={`badge ${getRiskClass(result.risk)}`}>{result.risk} risk</span>}
                    </div>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

export default PortScanner;
