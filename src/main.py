
from network.network_detector import detect_network_threat
from malware.malware_detector import detect_malware_indicators
from detection.hybrid_detector import analyze_hybrid_threat


def get_integer_input(message):
    while True:
        try:
            value = int(input(message))
            if value < 0:
                print("Please enter a non-negative number.")
                continue
            return value
        except ValueError:
            print("Invalid input. Enter a number.")


def main():

    print("\n===================================")
    print(" HYBRID CYBER THREAT DETECTION")
    print("===================================")

    # NETWORK ANALYSIS
    print("\n[1] NETWORK THREAT ANALYSIS")

    connection_count = get_integer_input(
        "Enter total network connections: "
    )

    failed_attempts = get_integer_input(
        "Enter failed connection attempts: "
    )

    unique_ports = get_integer_input(
        "Enter number of unique ports: "
    )

    observed_input = input(
        "Enter observed IP addresses (comma separated, optional): "
    )

    flagged_input = input(
        "Enter manually flagged IP addresses (comma separated, optional): "
    )

    observed_ips = [
        ip.strip() for ip in observed_input.split(",") if ip.strip()
    ]

    known_bad_ips = [
        ip.strip() for ip in flagged_input.split(",") if ip.strip()
    ]

    network_result = detect_network_threat(
        connection_count,
        failed_attempts,
        unique_ports,
        observed_ips,
        known_bad_ips
    )

    print("\nNETWORK DETECTION RESULT")
    print("------------------------")
    print("Status:", network_result["status"])
    print("Risk Score:", network_result["risk_score"])
    print("Alerts:", network_result["alerts"])

    # MALWARE ANALYSIS
    print("\n[2] MALWARE INDICATOR ANALYSIS")

    file_path = input("Enter file path to scan: ").strip().strip('"')

    malware_result = detect_malware_indicators(file_path)

    print("\nMALWARE DETECTION RESULT")
    print("-----------------------")
    print("Status:", malware_result["status"])
    print("Risk Score:", malware_result["risk_score"])
    print("Alerts:", malware_result["alerts"])

    # Stop if the requested file cannot be scanned
    if malware_result["status"] == "ERROR":
        print("\nHybrid analysis stopped because file scanning failed.")
        return

    # HYBRID ANALYSIS
    print("\n[3] HYBRID THREAT ANALYSIS")

    hybrid_result = analyze_hybrid_threat(
        network_result,
        malware_result
    )

    print("\n===================================")
    print(" FINAL HYBRID THREAT REPORT")
    print("===================================")

    print("Network Risk:", hybrid_result["network_score"])
    print("Malware Risk:", hybrid_result["malware_score"])
    print("Combined Risk:", hybrid_result["hybrid_score"])
    print("Final Status:", hybrid_result["status"])

    print("\nCOMBINED SECURITY ALERTS")

    if hybrid_result["alerts"]:
        for alert in hybrid_result["alerts"]:
            print("-", alert)
    else:
        print("No suspicious indicators detected.")

    print("\n===================================")
    print(" ANALYSIS COMPLETED")
    print("===================================")


if __name__ == "__main__":
    main()
