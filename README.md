Honeypot API – Scam Interaction & Intelligence Extraction

A FastAPI-based Honeypot API designed to simulate human-like responses to suspected scam messages, extract actionable intelligence (UPI IDs, phone numbers, links, etc.), and report findings automatically to the GUVI Hackathon endpoint.

This API is built to engage scammers, waste their time, and collect useful indicators for fraud analysis.

Features

* Human-like dynamic responses to scam messages

* Scam detection using keyword heuristics

* Extraction of sensitive indicators:

UPI IDs

Phone numbers

URLs

Emails

PAN numbers

IFSC codes

✅ Session-based conversation tracking

✅ Automatic callback to GUVI Hackathon endpoint

✅ Secure API key authentication via headers

🧠 Scam Detection Logic

The API flags a message as potential scam if it contains urgency-based or sensitive keywords such as:

verify, blocked, upi, account, urgent, suspend, password


Once detected:

The API replies with context-aware bait messages

Extracts intelligence from the message

Sends a final report to the GUVI hackathon callback API

📦 Tech Stack

Backend: FastAPI

Language: Python 3

Server: Uvicorn

HTTP Client: Requests

Environment Management: python-dotenv

🔐 Authentication

All requests to the honeypot endpoint require an API key passed via HTTP header:

x-api-key: <YOUR_API_KEY>


The API key is securely loaded from environment variables.

📡 API Endpoints
1️⃣ Root Endpoint (Health Check)

GET /

{
  "message": "Honeypot API is running!"
}

2️⃣ Honeypot Endpoint

POST /honeypot

Headers
x-api-key: YOUR_API_KEY
Content-Type: application/json

Request Body (Sample)
{
  "sessionId": "session_123",
  "message": {
    "text": "Your account is blocked, verify your UPI immediately"
  }
}

Response (Sample)
{
  "status": "success",
  "reply": "Why is my account being suspended?",
  "intelligence": {
    "upiIds": [],
    "phoneNumbers": [],
    "phishingLinks": [],
    "bankAccounts": [],
    "emails": [],
    "panNumbers": [],
    "ifscCodes": [],
    "suspiciousKeywords": ["blocked", "upi", "verify"]
  }
}

🔁 Automatic Callback (GUVI Hackathon)

When a scam is detected and intelligence is extracted, the API automatically sends results to:

https://hackathon.guvi.in/api/updateHoneyPotFinalResult

Callback Payload Includes:

Session ID

Scam detection status

Total messages exchanged

Extracted intelligence

Agent analysis notes

⚙️ Local Setup
1️⃣ Clone Repository
git clone https://github.com/Saumya-249/Honeypot-API.git
cd Honeypot-API

2️⃣ Install Dependencies
pip install -r requirements.txt

3️⃣ Set Environment Variable

Create .env file (DO NOT COMMIT):

API_KEY=your_secret_key

4️⃣ Run Server
uvicorn main:app --reload

☁️ Deployment (Render)
Build Command
pip install -r requirements.txt

Start Command
uvicorn main:app --host 0.0.0.0 --port $PORT

Environment Variables (Render Dashboard)
API_KEY = your_secret_key

🛑 Security Notes

.env and venv/ are excluded from version control

API key is mandatory for honeypot access

No sensitive data is stored persistently

🎯 Hackathon Objective Alignment

This project aligns with:

Fraud detection & prevention

Cybersecurity & threat intelligence

Real-world scam simulation

Automated incident reporting

👨‍💻 Author

Ashwin srivastav
Built for GUVI Hackathon
