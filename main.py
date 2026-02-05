from fastapi import FastAPI, Request, Header
from dotenv import load_dotenv
import re, requests, os, logging, random

load_dotenv()
app = FastAPI()

# Load API key from environment variable
API_KEY = os.getenv("API_KEY", "")

# Conversation storage
conversations = {}
# Per-session state
sessions = {}

# Configure logging
logging.basicConfig(level=logging.INFO)

# Root endpoint (supports GET, POST, PUT)
@app.get("/")
def root_get():
    return {"message": "Honeypot API is running!"}

@app.post("/")
async def root_post(request: Request, x_api_key: str = Header(...)):
    return await honeypot_handler(request, x_api_key)

@app.put("/")
async def root_put(request: Request, x_api_key: str = Header(...)):
    return await honeypot_handler(request, x_api_key)


# Honeypot endpoint (POST and PUT supported)
from fastapi import APIRouter

router = APIRouter()

async def honeypot_handler(request: Request, x_api_key: str = Header(...)):
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
    scam_keywords = ["verify", "blocked", "upi", "account", "urgent", "suspend", "password", "otp", "code", "transfer", "paytm", "gpay", "google pay", "immediately", "click"]
    scamDetected = any(word in text.lower() for word in scam_keywords)

    # staged reply templates
    initial_probes = [
        "I got a message about my account — which account is this about?",
        "Which app did this message come from?",
        "It says to verify — what details are you asking for?",
        "I am getting a message saying my account is blocked — what should I do?"
    ]
    probe_for_payment = [
        "Is this asking for UPI or bank transfer details?",
        "Should I give my UPI ID or my account number?",
        "Do you need my UPI ID, phone number, or account number to proceed?"
    ]
    request_identifiers = {
        "upi": [
            "Can you confirm the UPI ID to which I should send?",
            "How should I share my UPI ID?"
        ],
        "phone": [
            "Can you call or message me on which number?",
            "Which phone number should I use for this?"
        ],
        "bank": [
            "Which bank account do you need the transfer to?",
            "Can you confirm the last 4 digits of the account?"
        ],
        "link": [
            "You sent a link — can you paste the full URL here?",
            "I can't open that short link — what's the full address?"
        ],
        "otp": [
            "I received a code — is that the 6-digit OTP you need?",
            "There's a 6-digit code on my phone — do you want that code?"
        ]
    }

    neutral_replies = [
        "Okay, noted.",
        "Thanks for the update.",
        "Got it, I'll check and get back.",
        "Understood, thanks.",
        "Noted."
    ]

    # Intelligence extraction (improved patterns)
    def extract_intelligence(txt):
        lower = txt.lower()
        upi_ids = re.findall(r"\b[\w.\-]+@upi\b", txt, flags=re.IGNORECASE)
        phone_numbers = re.findall(r"\b(?:\+91|0)?\s*[6-9]\d{9}\b", txt)
        links = re.findall(r"https?://[^\s,]+", txt)
        domains = re.findall(r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}\b", txt, flags=re.IGNORECASE)
        bank_accounts = re.findall(r"\b\d{9,18}\b", txt)
        bank_accounts += re.findall(r"\b\d{4}-\d{4}-\d{4}\b", txt)
        emails = re.findall(r"[\w\.-]+@[\w\.-]+\.\w+", txt)
        pan = re.findall(r"\b[A-Z]{5}[0-9]{4}[A-Z]{1}\b", txt)
        ifsc = re.findall(r"\b[A-Z]{4}0[A-Z0-9]{6}\b", txt)
        aadhaar = re.findall(r"\b\d{4}\s?\d{4}\s?\d{4}\b", txt)
        amounts = re.findall(r"(?:₹|rs\.?|inr)\s?[0-9,]+(?:\.\d{1,2})?", txt, flags=re.IGNORECASE)
        possible_otps = []
        for m in re.findall(r"\b\d{4,6}\b", txt):
            idx = txt.find(m)
            start = max(0, idx-20)
            context = txt[start:idx+len(m)+20].lower()
            if "otp" in context or "code" in context or "pin" in context:
                possible_otps.append(m)
        suspicious = [kw for kw in scam_keywords if kw in lower]
        return {
            "upiIds": list(set(upi_ids)),
            "phoneNumbers": list(set(phone_numbers)),
            "phishingLinks": list(set(links)),
            "domains": list(set([d for d in domains if d.lower() not in (e.lower() for e in emails)])),
            "bankAccounts": list(set(bank_accounts)),
            "emails": list(set(emails)),
            "panNumbers": list(set(pan)),
            "ifscCodes": list(set(ifsc)),
            "aadhaarLike": list(set(aadhaar)),
            "amounts": list(set(amounts)),
            "possibleOtps": list(set(possible_otps)),
            "suspiciousKeywords": suspicious
        }

    intelligence = extract_intelligence(text)

    logging.info(f"Session {session_id}: ScamDetected={scamDetected}, Text='{text}'")

    # Initialize session state
    if session_id not in sessions:
        sessions[session_id] = {"stage": "new", "turns": 0, "asked": []}
    session = sessions[session_id]

    # State transitions and reply selection
    reply = None
    # If already completed, send neutral response
    if session["stage"] == "done":
        reply = random.choice(neutral_replies)
    else:
        # If scam detected, escalate to probing
        if scamDetected and session["stage"] == "new":
            session["stage"] = "probing"
            reply = random.choice(initial_probes)
        elif session["stage"] == "probing":
            # If we already extracted useful intelligence, move to collecting
            if any(intelligence.get(k) for k in ("upiIds", "phoneNumbers", "phishingLinks", "bankAccounts")):
                session["stage"] = "collecting"
                reply = random.choice(probe_for_payment)
            else:
                # continue probing for payment method
                reply = random.choice(probe_for_payment)
        elif session["stage"] == "collecting":
            # Ask targeted questions based on what we still need
            if not intelligence.get("upiIds"):
                reply = random.choice(request_identifiers["upi"])
            elif not intelligence.get("phoneNumbers"):
                reply = random.choice(request_identifiers["phone"])
            elif not intelligence.get("bankAccounts"):
                reply = random.choice(request_identifiers["bank"])
            elif not intelligence.get("phishingLinks"):
                reply = random.choice(request_identifiers["link"])
            elif not intelligence.get("possibleOtps"):
                reply = random.choice(request_identifiers["otp"])
            else:
                reply = random.choice(neutral_replies)
        else:
            # default fallback
            reply = random.choice(neutral_replies)

    # Increment turns and mark asked
    session["turns"] += 1
    session["asked"].append(reply)

    # If intelligence found, finalize and callback
    if any(intelligence.get(k) for k in ("upiIds", "phoneNumbers", "phishingLinks", "bankAccounts", "possibleOtps")):
        session["stage"] = "done"
        try:
            send_final_result(session_id, conversations[session_id], intelligence,
                              "Scammer used staged tactics; intelligence captured")
        except Exception:
            pass

    logging.info(f"Session {session_id}: ScamDetected={scamDetected}, Text='{text}'")

    # Auto callback if scam detected and intelligence found
    if scamDetected and any(intelligence.values()):
        send_final_result(session_id, conversations[session_id], intelligence,
                          "Scammer used urgency tactics and attempted to collect sensitive info")

    return {"status": "success", "reply": reply, "intelligence": intelligence}

@app.post("/honeypot")
async def honeypot_post(request: Request, x_api_key: str = Header(...)):
    return await honeypot_handler(request, x_api_key)

@app.put("/honeypot")
async def honeypot_put(request: Request, x_api_key: str = Header(...)):
    return await honeypot_handler(request, x_api_key)

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
        response = requests.put(
            "https://hackathon.guvi.in/api/updateHoneyPotFinalResult",
            json=payload,
            timeout=5
        )
        logging.info(f"Final result sent for {session_id}, status={response.status_code}")
    except Exception as e:
        logging.error(f"Error sending final result: {e}")