import os
import requests
from dotenv import load_dotenv

load_dotenv()

api_key = os.getenv("MALWAREBAZAAR_AUTH_KEY")

families = [
    "Emotet",
    "NanoCore",
    "njRAT",
    "BitRAT",
    "AsyncRAT",
    "Dridex",
    "TrickBot",
    "FormBook",
    "DarkComet",
    "IcedID",
    "AgentTesla",
    "XWorm",
]

headers = {
    "Auth-Key": api_key,
    "User-Agent": "Adaptive-Honeypot-Availability-Probe",
}

url = "https://mb-api.abuse.ch/api/v1/"

print("=== PE AVAILABILITY PROBE ===")
print("Downloads: DISABLED")
print()

for family in families:
    try:
        response = requests.post(
            url,
            headers=headers,
            data={
                "query": "get_siginfo",
                "signature": family,
                "limit": 1000,
            },
            timeout=60,
        )

        data = response.json()
        status = data.get("query_status")

        if status != "ok":
            print(f"{family}: status={status}")
            continue

        records = data.get("data", [])

        pe_count = sum(
            (
                str(sample.get("file_type") or "").lower()
                in {"exe", "dll"}
                or "dosexec"
                in str(sample.get("file_type_mime") or "").lower()
                or str(sample.get("file_format") or "").lower() == "pe"
            )
            for sample in records
        )

        print(
            f"{family}: "
            f"records={len(records)} "
            f"PE={pe_count} "
            f"status={status}"
        )

    except Exception as exc:
        print(
            f"{family}: "
            f"ERROR={type(exc).__name__}: {exc}"
        )
