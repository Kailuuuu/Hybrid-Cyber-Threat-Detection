
from ml_network_detector import predict_network_threat

def detect_network_threat(
    connection_count,
    failed_attempts,
    unique_ports,
    observed_ips=None,
    known_bad_ips=None
):
    risk_score = 0
    alerts = []

    observed_ips = observed_ips or []
    known_bad_ips = known_bad_ips or []

    # 1. High connection detection
    if connection_count > 100:
        risk_score += 25
        alerts.append("High number of network connections")

    # 2. Failed connection detection
    if failed_attempts > 20:
        risk_score += 25
        alerts.append("Multiple failed connection attempts")

    # 3. Port scanning detection
    if unique_ports > 15:
        risk_score += 30
        alerts.append("Possible port scanning activity")

    # 4. Suspicious IP detection
    suspicious_matches = set(observed_ips) & set(known_bad_ips)

    flagged_ip = 1 if suspicious_matches else 0

    if suspicious_matches:
        risk_score += 30
        alerts.append("Communication with known flagged IP address")

    # Limit rule-based risk score
    risk_score = min(risk_score, 100)

    # 5. Machine Learning prediction
    ml_result = predict_network_threat(
        total_connections=connection_count,
        failed_connections=failed_attempts,
        unique_ports=unique_ports,
        flagged_ip=flagged_ip
    )

    # 6. Combine rule-based and ML results
    if ml_result["prediction"] == 1:
        status = "SUSPICIOUS"
    else:
        status = "NORMAL"

    return {
        "status": status,
        "risk_score": risk_score,
        "alerts": alerts,
        "ml_result": ml_result
    }


if __name__ == "__main__":

    print("\nTEST 1: Suspicious Network Traffic")

    result = detect_network_threat(150, 25, 20)

    print("Status:", result["status"])
    print("Risk Score:", result["risk_score"])
    print("ML Result:", result["ml_result"])
    print("Alerts:", result["alerts"])

    print("\nTEST 2: Normal Network Traffic")

    result = detect_network_threat(20, 2, 5)

    print("Status:", result["status"])
    print("Risk Score:", result["risk_score"])
    print("ML Result:", result["ml_result"])
    print("Alerts:", result["alerts"])

    print("\nTEST 3: Suspicious IP Detection")

    result = detect_network_threat(
        30,
        5,
        5,
        observed_ips=["203.0.113.10"],
        known_bad_ips=["203.0.113.10"]
    )

    print("Status:", result["status"])
    print("Risk Score:", result["risk_score"])
    print("ML Result:", result["ml_result"])
    print("Alerts:", result["alerts"])
