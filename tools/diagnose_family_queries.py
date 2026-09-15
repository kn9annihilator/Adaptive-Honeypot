import os
import requests
from dotenv import load_dotenv

load_dotenv()

api_key = os.getenv("MALWAREBAZAAR_AUTH_KEY")

url = "https://mb-api.abuse.ch/api/v1/"
headers = {
    "Auth-Key": api_key,
    "User-Agent": "Adaptive-Honeypot-Diagnostic",
}

for family in ["FormBook", "AgentTesla"]:
    print("=" * 70)
    print(f"FAMILY: {family}")
    print()

    for signature in [family, family.lower(), family.upper()]:
        try:
            r = requests.post(
                url,
                headers=headers,
                data={
                    "query": "get_siginfo",
                    "signature": signature,
                    "limit": 1000,
                },
                timeout=60,
            )

            print(f"signature={signature!r}")
            print(f"HTTP={r.status_code}")

            try:
                body = r.json()
                print(f"query_status={body.get('query_status')}")
                print(f"data_count={len(body.get('data', []))}")

                if body.get("query_status") != "ok":
                    print(f"response={body}")
                else:
                    data = body.get("data", [])

                    pe = sum(
                        (
                            str(x.get("file_type") or "").lower()
                            in {"exe", "dll"}
                            or "dosexec"
                            in str(x.get("file_type_mime") or "").lower()
                            or str(x.get("file_format") or "").lower() == "pe"
                        )
                        for x in data
                    )

                    print(f"PE_count={pe}")

            except Exception:
                print("Non-JSON response:")
                print(r.text[:1000])

            print()

        except Exception as e:
            print(f"ERROR: {type(e).__name__}: {e}")
            print()

