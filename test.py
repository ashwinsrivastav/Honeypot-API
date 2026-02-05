import os, requests

# Local API URL
url = "https://honeypot-api-721b.onrender.com/honeypot"

# Replace with your actual API key
headers = {
    "Content-Type": "application/json",
    "x-api-key": os.getenv("API_KEY", "")
}

# Diverse test cases
test_cases = [
    {"text": "Your bank account will be blocked today. Verify immediately."},
    {"text": "Send money to scammer@upi immediately"},
    {"text": "Click http://fake-bank.com to verify your details"},
    {"text": "Call +919876543210 to unblock account"},
    {"text": "Transfer to 1234-5678-9012 now"},
    {"text": "Contact support@fakebank.com for help"},
    {"text": "My PAN is ABCDE1234F and IFSC is HDFC0001234"},
    {"text": "Hello, how are you today?"}
]

# Run all test cases
for i, case in enumerate(test_cases, 1):
    payload = {
        "sessionId": f"test{i}",
        "message": {
            "sender": "scammer",
            "text": case["text"],
            "timestamp": 1770005528731
        },
        "conversationHistory": [],
        "metadata": {
            "channel": "SMS",
            "language": "English",
            "locale": "IN"
        }
    }

    try:
        response = requests.post(url, headers=headers, json=payload)
        print(f"\n--- Test {i} ---")
        print(f"Input: {case['text']}")
        print("Output:", response.json())
    except Exception as e:
        print(f"Test {i} failed: {e}")