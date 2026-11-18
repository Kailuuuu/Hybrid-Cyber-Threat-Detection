
def detect_network_threat(connection_count, failed_attempts, unique_ports):

    risk_score = 0
    alerts = []

    if connection_count > 100:
        risk_score += 40
        alerts.append("High number of network connections")

    if failed_attempts > 20:
        risk_score += 30
        alerts.append("Multiple failed connection attempts")

    if unique_ports > 15:
        risk_score += 30
        alerts.append("Possible port scanning activity")

    status = "SUSPICIOUS" if risk_score >= 50 else "NORMAL"

    return {
        "status": status,
        "risk_score": risk_score,
        "alerts": alerts
    }


if __name__ == "__main__":

    print("\nTEST 1: Suspicious Network Traffic")

    result = detect_network_threat(150, 25, 20)
    print("Status:", result["status"])
    print("Risk Score:", result["risk_score"])
    print("Alerts:", result["alerts"])

    print("\nTEST 2: Normal Network Traffic")

    result = detect_network_threat(20, 2, 5)
    print("Status:", result["status"])
    print("Risk Score:", result["risk_score"])
    print("Alerts:", result["alerts"])
