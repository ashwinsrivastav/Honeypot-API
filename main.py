from fastapi import FastAPI, Request, Header
from dotenv import load_dotenv
import re, requests, os, logging, random

load_dotenv()
app = FastAPI()

# Load API key from environment variable
API_KEY = os.getenv("API_KEY", "")

# Conversation storage
conversations = {}

# Configure logging
logging.basicConfig(level=logging.INFO)

# Root endpoint
@app.get("/")
def root():
    return {"message": "Honeypot API is running!"}

# Honeypot endpoint
@app.post("/honeypot")
async def honeypot(request: Request, x_api_key: str = Header(...)):
    if x_api_key != API_KEY:
        return {"status": "error", "message": "Unauthorized"}

    data = await request.json()
    text = data["message"]["text"]
    session_id = data["sessionId"]

    # Store conversation history
    if session_id not in conversations:
        conversations[session_id] = []
    conversations[session_id].append(data["message"])

    # Scam detection
    scam_keywords = ["verify", "blocked", "upi", "account", "urgent", "suspend", "password"]
    scamDetected = any(word in text.lower() for word in scam_keywords)

    # Varied agent replies
    possible_replies = [
        "Why is my account being suspended?",
        "Can you explain why my account is blocked?",
        "I don’t understand, what’s happening with my account?",
        "What details do you need from me?",
        "Why should I share my UPI ID?"
    ]
    reply = random.choice(possible_replies) if scamDetected else "Okay, noted."

    # Intelligence extraction
    intelligence = {
        "upiIds": re.findall(r"\w+@upi", text),
        "phoneNumbers": re.findall(r"\+91\d{10}", text),
        "phishingLinks": re.findall(r"http[s]?://\S+", text),
        "bankAccounts": re.findall(r"\d{4}-\d{4}-\d{4}", text),
        "emails": re.findall(r"[\w\.-]+@[\w\.-]+\.\w+", text),
        "panNumbers": re.findall(r"[A-Z]{5}[0-9]{4}[A-Z]{1}", text),
        "ifscCodes": re.findall(r"[A-Z]{4}0[A-Z0-9]{6}", text),
        "suspiciousKeywords": [kw for kw in scam_keywords if kw in text.lower()]
    }

    logging.info(f"Session {session_id}: ScamDetected={scamDetected}, Text='{text}'")

    # Auto callback if scam detected and intelligence found
    if scamDetected and any(intelligence.values()):
        send_final_result(session_id, conversations[session_id], intelligence,
                          "Scammer used urgency tactics and attempted to collect sensitive info")

    return {"status": "success", "reply": reply, "intelligence": intelligence}

# Final result callback
def send_final_result(session_id, conversation, intelligence, agent_notes):
    payload = {
        "sessionId": session_id,
        "scamDetected": True,
        "totalMessagesExchanged": len(conversation),
        "extractedIntelligence": intelligence,
        "agentNotes": agent_notes
    }
    try:
        response = requests.post(
            "https://hackathon.guvi.in/api/updateHoneyPotFinalResult",
            json=payload,
            timeout=5
        )
        logging.info(f"Final result sent for {session_id}, status={response.status_code}")
    except Exception as e:
        logging.error(f"Error sending final result: {e}")