
def hybrid_threat_analysis(network_risk, malware_risk):

    # Weighted risk calculation
    combined_risk = (network_risk * 0.60) + (malware_risk * 0.40)

    # Threat classification
    if combined_risk >= 80:
        final_status = "CRITICAL RISK"

    elif combined_risk >= 60:
        final_status = "HIGH RISK"

    elif combined_risk >= 30:
        final_status = "MEDIUM RISK"

    else:
        final_status = "LOW RISK"

    print("\nHYBRID THREAT ANALYSIS")
    print("----------------------")
    print(f"Network Risk: {network_risk}")
    print(f"Malware Risk: {malware_risk}")
    print(f"Combined Risk: {combined_risk:.1f}")
    print(f"Final Status: {final_status}")

    return combined_risk, final_status
