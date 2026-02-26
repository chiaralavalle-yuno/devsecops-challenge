# payments.py — DO NOT COMMIT THIS (demo only)
import requests

# BAD: hardcoded API key — this would be caught by gitleaks
BANCOSUR_API_KEY = "bsur_a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0"

def process_payment(amount: float) -> dict:
    response = requests.post(
        "https://api.bancosur.com/v1/payments",
        headers={"Authorization": f"Bearer {BANCOSUR_API_KEY}"},
        json={"amount": amount}
    )
    return response.json()
