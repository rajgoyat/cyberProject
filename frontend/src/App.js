import { useState } from "react";

function App() {
  const [target, setTarget] = useState("");       // IP/domain input
  const [ports, setPorts] = useState("21,22,80,443"); // Default ports as string
  const [results, setResults] = useState([]);     // Store scan results
  const [loading, setLoading] = useState(false);  // Loading state
  const [error, setError] = useState("");         // Error messages

  const scanPorts = async () => {
    setError("");
    setResults([]);

    if (!target) {
      setError("Please enter a valid IP or domain.");
      return;
    }

    // Convert comma-separated ports to numbers
    const portList = ports
      .split(",")
      .map((p) => parseInt(p.trim()))
      .filter((p) => !isNaN(p));

    if (portList.length === 0) {
      setError("Please enter at least one valid port.");
      return;
    }

    setLoading(true);

    try {
      const response = await fetch("https://cyberproject-backend.onrender.com", { // Replace with live URL later
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ target, ports: portList }),
      });

      if (!response.ok) {
        setError(`Backend error: ${response.status}`);
        setLoading(false);
        return;
      }

      const data = await response.json();
      setResults(data.results);
    } catch (err) {
      setError("Failed to connect to backend. Is it running?");
      console.error(err);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div style={{ maxWidth: "500px", margin: "50px auto", fontFamily: "Arial" }}>
      <h1>Port Scanner</h1>

      <div style={{ marginBottom: "10px" }}>
        <input
          type="text"
          placeholder="Enter IP or domain"
          value={target}
          onChange={(e) => setTarget(e.target.value)}
          style={{ width: "100%", padding: "8px", marginBottom: "5px" }}
        />
        <input
          type="text"
          placeholder="Enter ports (comma separated)"
          value={ports}
          onChange={(e) => setPorts(e.target.value)}
          style={{ width: "100%", padding: "8px" }}
        />
      </div>

      <button
        onClick={scanPorts}
        style={{ padding: "10px 20px", cursor: "pointer" }}
        disabled={loading}
      >
        {loading ? "Scanning..." : "Scan Ports"}
      </button>

      {error && <p style={{ color: "red" }}>{error}</p>}

      {results.length > 0 && (
        <ul style={{ listStyle: "none", padding: 0, marginTop: "20px" }}>
          {results.map((r) => (
            <li
              key={r.port}
              style={{
                padding: "5px 0",
                color: r.status === "OPEN" ? "green" : r.status === "CLOSED" ? "red" : "gray",
              }}
            >
              Port {r.port}: {r.status}
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}

export default App;
