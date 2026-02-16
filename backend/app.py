from flask import Flask, request, jsonify
from flask_cors import CORS
import socket
import threading

app = Flask(__name__)
# Fixed CORS for all origins
CORS(app, resources={r"/*": {"origins": "*"}})

def scan_ports(target, ports):
    results = []
    for port in ports:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(1)
            result = s.connect_ex((target, port))
            status = "OPEN" if result == 0 else "CLOSED"
            results.append({"port": port, "status": status})
            s.close()
        except:
            results.append({"port": port, "status": "ERROR"})
    return results

@app.route("/scan", methods=["POST"])
def scan():
    data = request.get_json()
    target = data.get("target")
    ports = data.get("ports", [21,22,23,25,53,80,110,139,143,443,445,3306])
    results = []

    def worker():
        nonlocal results
        results = scan_ports(target, ports)

    thread = threading.Thread(target=worker)
    thread.start()
    thread.join()
    return jsonify({"target": target, "results": results})

if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5000)
