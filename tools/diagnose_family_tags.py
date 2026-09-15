import os
import requests
from dotenv import load_dotenv

load_dotenv()

key = os.getenv("MALWAREBAZAAR_AUTH_KEY")

url = "https://mb-api.abuse.ch/api/v1/"
headers = {
    "Auth-Key": key,
    "User-Agent": "Adaptive-Honeypot-Family-Availability",
}

queries = [
    ("FormBook", "get_taginfo", {"tag": "FormBook", "limit": 1000}),
    ("AgentTesla", "get_taginfo", {"tag": "AgentTesla", "limit": 1000}),
]

for family, query, extra in queries:
    print("=" * 70)
    print(f"{family}: {query}")
    
    try:
        r = requests.post(
            url,
            headers=headers,
            data={"query": query, **extra},
            timeout=60,
        )

        print("HTTP:", r.status_code)

        body = r.json()
        status = body.get("query_status")
        print("query_status:", status)

        if status != "ok":
            print("response:", body)
            continue

        records = body.get("data", [])

        pe_records = [
            x for x in records
            if (
                str(x.get("file_type") or "").lower() in {"exe", "dll"}
                or "dosexec" in str(x.get("file_type_mime") or "").lower()
                or str(x.get("file_format") or "").lower() == "pe"
            )
        ]

        unique_sha256 = {
            str(x.get("sha256_hash")).lower()
            for x in pe_records
            if x.get("sha256_hash")
        }

        signatures = sorted({
            str(x.get("signature") or "")
            for x in pe_records
            if x.get("signature")
        })

        print("records:", len(records))
        print("PE records:", len(pe_records))
        print("unique PE SHA-256:", len(unique_sha256))
        print("signatures observed:", signatures)

    except Exception as e:
        print("ERROR:", type(e).__name__, e)
