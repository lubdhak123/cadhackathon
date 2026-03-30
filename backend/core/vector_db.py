"""
Vector Database – ChromaDB + sentence-transformers
Stores known scam message embeddings for semantic similarity detection.
"""

import chromadb
from chromadb.utils import embedding_functions
from typing import List, Dict


KNOWN_SCAMS = [
    # ── Financial / Banking ───────────────────────────────────────
    "Congratulations! You have won a lottery. Click here to claim your prize now.",
    "Your bank account has been suspended. Verify your details immediately to restore access.",
    "URGENT: Your OTP is expiring. Share it now to keep your account active.",
    "You owe Rs 5000 in unpaid taxes. Pay immediately or face arrest.",
    "Dear customer, your KYC is incomplete. Update now or your account will be blocked within 24 hours.",
    "We need your credit card details to process your refund. Click the secure link below.",
    "Click this link to verify your PayTM/UPI account or it will be suspended permanently.",
    "Your SBI/HDFC/ICICI net banking password has expired. Click here to reset immediately.",

    # ── Government / Identity ─────────────────────────────────────
    "You have been selected for a government scheme. Send your Aadhaar and PAN to claim benefits.",
    "Your SIM card will be deactivated in 24 hours by TRAI order. Call us immediately.",
    "Income Tax Department: You have a pending refund of Rs 15,000. Click to claim now.",

    # ── Tech Support ──────────────────────────────────────────────
    "Hi, I'm from Microsoft support. Your computer has a virus. Give me remote access to fix it.",
    "Windows Defender alert: Your PC is infected. Call this number immediately for support.",
    "Your iCloud account has been compromised. Verify your Apple ID now.",

    # ── Package / Delivery ────────────────────────────────────────
    "Your parcel is held at customs. Pay Rs 2000 processing fee to release it.",
    "Amazon delivery failed. Update your address and pay redelivery fee.",

    # ── Prize / Reward ────────────────────────────────────────────
    "Win an iPhone 15! You are our lucky draw winner. Click the link to claim your prize.",
    "Investment opportunity: 40% returns guaranteed in 30 days. Limited slots available.",

    # ── Social Engineering ────────────────────────────────────────
    "Send money urgently, I am stuck abroad and lost my wallet. Will repay tomorrow.",
    "Hi Mom/Dad, I dropped my phone in water. This is my new number. Can you send me Rs 5000?",

    # ── Job / Loan ────────────────────────────────────────────────
    "Work from home and earn Rs 50,000 per day. No experience needed. WhatsApp us now.",
    "Your loan of Rs 5,00,000 has been pre-approved. Pay Rs 2,000 processing fee to activate.",

    # ── AI-Generated Phishing (modern) ────────────────────────────
    "As per our records, your account shows suspicious activity. To prevent unauthorized access, please verify your identity by clicking the secure link below. This is an automated security measure.",
    "Dear valued customer, we have detected a login attempt from an unrecognized device. If this was not you, please immediately verify your account to prevent any unauthorized transactions.",
]


class VectorDB:
    def __init__(self, persist_dir: str = "./chroma_db"):
        self.client = chromadb.PersistentClient(path=persist_dir)
        self.ef = embedding_functions.SentenceTransformerEmbeddingFunction(
            model_name="all-MiniLM-L6-v2"
        )
        self.collection = self.client.get_or_create_collection(
            name="scam_templates",
            embedding_function=self.ef,
        )

    def seed_known_scams(self):
        """Populate DB with known scam templates if empty or outdated."""
        if self.collection.count() >= len(KNOWN_SCAMS):
            return
        self.collection.upsert(
            documents=KNOWN_SCAMS,
            ids=[f"scam_{i}" for i in range(len(KNOWN_SCAMS))],
            metadatas=[{"type": "known_scam", "index": i} for i in range(len(KNOWN_SCAMS))],
        )

    def query_similarity(self, text: str, n_results: int = 3) -> List[Dict]:
        """Return top-N similar scam templates with similarity percentage."""
        count = self.collection.count()
        if count == 0:
            return []
        results = self.collection.query(
            query_texts=[text],
            n_results=min(n_results, count),
        )
        output = []
        if results and results["documents"]:
            for doc, dist in zip(results["documents"][0], results["distances"][0]):
                similarity = round((1 - dist / 2) * 100, 1)
                output.append({"template": doc, "similarity_pct": similarity})
        return output

    def add_scam(self, text: str, reported_by: str = "user"):
        """Add a user-reported scam to the database (human-in-the-loop learning)."""
        doc_id = f"user_reported_{self.collection.count()}"
        self.collection.add(
            documents=[text],
            ids=[doc_id],
            metadatas=[{"type": "user_reported", "reported_by": reported_by}],
        )
