const API_BASE_URL = process.env.REACT_APP_API_URL || 'https://cyberproject-backend.onrender.com';

async function request(path, options = {}) {
  let response;
  try {
    response = await fetch(`${API_BASE_URL}${path}`, {
      headers: {
        'Content-Type': 'application/json',
        ...(options.headers || {}),
      },
      ...options,
    });
  } catch (error) {
    throw new Error('Unable to connect to backend API.');
  }

  if (!response.ok) {
    let message = `Request failed with status ${response.status}`;
    try {
      const data = await response.json();
      if (data?.error) message = data.error;
    } catch (error) {
      // Ignore JSON parse errors and keep fallback message.
    }
    throw new Error(message);
  }

  if (response.status === 204) {
    return null;
  }

  return response.json();
}

export function createScan(payload) {
  return request('/api/scans', {
    method: 'POST',
    body: JSON.stringify(payload),
  });
}

export function updateScan(scanId, payload) {
  return request(`/api/scans/${scanId}`, {
    method: 'PATCH',
    body: JSON.stringify(payload),
  });
}

export function getScans() {
  return request('/api/scans');
}

export function deleteScan(scanId) {
  return request(`/api/scans/${scanId}`, {
    method: 'DELETE',
  });
}

export function runPortScan(payload) {
  return request('/scan', {
    method: 'POST',
    body: JSON.stringify(payload),
  });
}

export function runNetworkRecon(payload) {
  return request('/api/network-recon', {
    method: 'POST',
    body: JSON.stringify(payload),
  });
}

export function runVulnerabilityScan(payload) {
  return request('/api/vulnerability-scan', {
    method: 'POST',
    body: JSON.stringify(payload),
  });
}
