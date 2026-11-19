
import pickle
from pathlib import Path
import pandas as pd

BASE_DIR = Path(__file__).resolve().parents[1] / "malware"
MODEL_PATH = BASE_DIR / "network_model.pkl"

# Load trained ML model
with open(MODEL_PATH, "rb") as file:
    model = pickle.load(file)


def predict_network_threat(
    total_connections,
    failed_connections,
    unique_ports,
    flagged_ip
):
    features = pd.DataFrame([{
        "total_connections": total_connections,
        "failed_connections": failed_connections,
        "unique_ports": unique_ports,
        "flagged_ip": flagged_ip
    }])

    prediction = model.predict(features)[0]
    probability = model.predict_proba(features)[0]

    return {
        "status": "SUSPICIOUS" if prediction == 1 else "NORMAL",
        "prediction": int(prediction),
        "confidence": round(float(max(probability)) * 100, 2)
    }
if __name__ == "__main__":

    result = predict_network_threat(
        total_connections=150,
        failed_connections=25,
        unique_ports=20,
        flagged_ip=1
    )

    print("\nMACHINE LEARNING NETWORK RESULT")
    print("--------------------------------")
    print("Status:", result["status"])
    print("Prediction:", result["prediction"])
    print("Confidence:", result["confidence"], "%")