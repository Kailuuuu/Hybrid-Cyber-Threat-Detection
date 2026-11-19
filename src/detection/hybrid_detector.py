
def analyze_hybrid_threat(network_result, malware_result):

    network_score = network_result["risk_score"]
    malware_score = malware_result["risk_score"]

    # Validate risk scores
    if not (0 <= network_score <= 100):
        raise ValueError("Invalid network risk score")

    if not (0 <= malware_score <= 100):
        raise ValueError("Invalid malware risk score")

    # Get ML prediction
    ml_result = network_result.get("ml_result")

    if ml_result is not None:
        ml_prediction = ml_result["prediction"]

        if ml_prediction not in (0, 1):
            raise ValueError("Invalid ML prediction")

        ml_score = ml_prediction * 100

        # Combine rule-based and ML scores
        network_score = (
            network_score * 0.60 +
            ml_score * 0.40
        )

    # Weighted hybrid risk calculation
    hybrid_score = (
        network_score * 0.60 +
        malware_score * 0.40
    )

    # Final threat classification
    if hybrid_score >= 85:
        status = "CRITICAL RISK"

    elif hybrid_score >= 60:
        status = "HIGH RISK"

    elif hybrid_score >= 30:
        status = "MEDIUM RISK"

    else:
        status = "LOW RISK"

    # Combine alerts
    alerts = (
        network_result.get("alerts", []) +
        malware_result.get("alerts", [])
    )

    if ml_result and ml_result["prediction"] == 1:
        alerts.append(
            "Machine Learning detected suspicious network activity"
        )

    return {
        "network_score": round(network_score, 2),
        "malware_score": malware_score,
        "hybrid_score": round(hybrid_score, 2),
        "status": status,
        "alerts": alerts
    }
