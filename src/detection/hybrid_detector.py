
def analyze_hybrid_threat(network_result, malware_result):

    network_score = network_result["risk_score"]
    malware_score = malware_result["risk_score"]

    # Calculate combined risk score
    hybrid_score = (
        network_score * 0.5 +
        malware_score * 0.5
    )

    if hybrid_score >= 70:
        status = "HIGH RISK"

    elif hybrid_score >= 40:
        status = "MEDIUM RISK"

    else:
        status = "LOW RISK"

    return {
        "network_score": network_score,
        "malware_score": malware_score,
        "hybrid_score": round(hybrid_score, 2),
        "status": status
    }


if __name__ == "__main__":

    network = {
        "risk_score": 100
    }

    malware = {
        "risk_score": 30
    }

    result = analyze_hybrid_threat(network, malware)

    print("\nHYBRID THREAT ANALYSIS")
    print("----------------------")
    print("Network Risk:", result["network_score"])
    print("Malware Risk:", result["malware_score"])
    print("Combined Risk:", result["hybrid_score"])
    print("Final Status:", result["status"])
