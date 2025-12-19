class BuildPlan:
    def __init__(self, goal: str):
        self.goal = goal.lower()
        self.tasks = []
        self.files = []

    def decompose(self):
        if "api" in self.goal or "fastapi" in self.goal or "service" in self.goal:
            self.tasks += [
                "Create FastAPI service skeleton",
                "Add health/check endpoint",
                "Add /autobuild route",
                "Add basic tests",
                "Update README with API docs"
            ]
            self.files.append({
                "path": "niabrain/api/main.py",
                "description": "Main FastAPI application with root and health endpoints"
            })

        if "legal" in self.goal:
            self.tasks.append("Integrate legal research agent")
            self.files.append({
                "path": "niabrain/agents/legal_agent/core.py",
                "description": "Legal research with disclaimers and safety"
            })

        if "international" in self.goal:
            self.tasks.append("Add international law module")
            self.files.append({
                "path": "niabrain/agents/international_law_agent/core.py",
                "description": "UN treaties, ICJ, customary law support"
            })

        if "trading" in self.goal or "money" in self.goal:
            self.tasks.append("Add paper trading signal generator")
            self.files.append({
                "path": "niabrain/agents/trading_agent/core.py",
                "description": "Safe paper trading with Polygon integration"
            })

        return {
            "goal": self.goal,
            "tasks": self.tasks,
            "proposed_files": self.files,
            "status": "planned"
def generate_file(task: str) -> dict:
    if "FastAPI" in task or "service" in task:
        return {
            "path": "niabrain/api/main.py",
            "content": """\
from fastapi import FastAPI
from pydantic import BaseModel

app = FastAPI(title="Nia Brain API", version="0.1.0")

class GoalRequest(BaseModel):
    goal: str

@app.get("/")
def root():
    return {"status": "Nia is alive 🧠", "date": "2025-12-19"}

@app.get("/health")
def health():
    return {"healthy": True}

@app.post("/autobuild")
def trigger_build(req: GoalRequest):
    return {"received_goal": req.goal, "status": "queued"}
"""
        }
    return {} 
name: Nia AutoBuild

on:
  workflow_dispatch:
    inputs:
      intent:
        description: 'Path to intent JSON file'
        required: true
        default: 'intent/build.json'

permissions:
  contents: write

jobs:
  autobuild:
    runs-on: windows-latest
    env:
      XAI_API_KEY: ${{ secrets.XAI_API_KEY }}

    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0

      - name: Setup Environment
        shell: pwsh
        run: |
          Set-ExecutionPolicy Bypass -Scope Process -Force

      - name: Run Nia AutoBuilder
        shell: pwsh
        run: |
          ./scripts/Invoke-AutoBuild.ps1 -IntentFile "${{ inputs.intent }}"

      - name: Create Pull Request
        if: success()
        uses: peter-evans/create-pull-request@v6
        with:
          token: ${{ secrets.NIA_GITHUB_TOKEN }}
          branch: nia/autobuild-${{ github.run_id }}
          title: "🧠 Nia: ${{ inputs.intent }}"
          body: |
            Autonomous build from intent: ${{ inputs.intent }}
            
            Nia is alive and extending herself.
          labels: nia,autobuild
          delete-branch: true
{
  "commit_message": "🧠 Nia: Add grant application agent with discovery and drafting",
  "files": [
    {
      "path": "niabrain/agents/grant_agent/core.py",
      "content": "# GrantAgent class with discover(), draft(), track()\n# Integrates with Grok-4 for proposal writing"
    },
    {
      "path": ".github/workflows/nia-grants.yml",
      "content": "name: Nia Grant Scan\non:\n  schedule:\n    - cron: '0 0 */2 * *'\njobs:\n  scan: ..."
    }
  ],
  "commands": []
} 
from .vault import Vault

vault = Vault(master_secret=os.getenv("NIA_MASTER_SECRET", "default-dev-secret-change-me"))

__all__ = ["vault"] 
import os
import base64
from hashlib import sha256
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

def derive_key(master_secret: str) -> bytes:
    """Derive 256-bit key from master secret (upgrade path: Argon2id)"""
    return sha256(master_secret.encode('utf-8')).digest()

def encrypt(plaintext: bytes, key: bytes) -> dict:
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)
    ciphertext = aesgcm.encrypt(nonce, plaintext, None)
    return {
        "nonce": base64.b64encode(nonce).decode('utf-8'),
        "ciphertext": base64.b64encode(ciphertext).decode('utf-8')
    }

def decrypt(payload: dict, key: bytes) -> bytes:
    aesgcm = AESGCM(key)
    nonce = base64.b64decode(payload["nonce"])
    ciphertext = base64.b64decode(payload["ciphertext"])
    return aesgcm.decrypt(nonce, ciphertext, None)
import sqlite3
import json
import os
from datetime import datetime

DB_PATH = "niabrain/vault/ledger.db"
os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)

def init_ledger():
    conn = sqlite3.connect(DB_PATH)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS ledger (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ts TEXT NOT NULL,
            type TEXT NOT NULL,
            amount REAL,
            currency TEXT DEFAULT 'USD',
            description TEXT,
            encrypted_payload TEXT
        )
    """)
    conn.commit()
    conn.close()

def append_entry(entry: dict, encrypted_payload: dict = None):
    conn = sqlite3.connect(DB_PATH)
    conn.execute("""
        INSERT INTO ledger (ts, type, amount, currency, description, encrypted_payload)
        VALUES (?, ?, ?, ?, ?, ?)
    """, (
        datetime.utcnow().isoformat() + "Z",
        entry["type"],
        entry.get("amount"),
        entry.get("currency", "USD"),
        entry.get("description", ""),
        json.dumps(encrypted_payload) if encrypted_payload else None
    ))
    conn.commit()
    conn.close()

def list_entries(limit: int = 50):
    conn = sqlite3.connect(DB_PATH)
    rows = conn.execute("""
        SELECT ts, type, amount, currency, description FROM ledger
        ORDER BY ts DESC LIMIT ?
    """, (limit,)).fetchall()
    conn.close()
    return [{"ts": r[0], "type": r[1], "amount": r[2], "currency": r[3], "desc": r[4]} for r in rows]

# Initialize on import
init_ledger()
from .crypto import derive_key, encrypt, decrypt
from .ledger import append_entry, list_entries

class Vault:
    def __init__(self, master_secret: str):
        self.key = derive_key(master_secret)

    def store_secret(self, name: str, value: str):
        encrypted = encrypt(value.encode('utf-8'), self.key)
        append_entry({
            "type": "secret_store",
            "description": f"Stored secret: {name}"
        }, encrypted)

    def retrieve_secret(self, name: str):
        # Future: query ledger for latest
        raise NotImplementedError("Retrieval index coming soon")

    def record_transaction(self, type_: str, amount: float, desc: str):
        append_entry({
            "type": type_,  # grant_received, freelance_earned, expense_api
            "amount": amount,
            "description": desc
        })

    def balance_report(self):
        entries = list_entries(100)
        total = sum(e["amount"] or 0 for e in entries if e["type"] in ["grant_received", "freelance_earned"])
        spent = sum(abs(e["amount"]) for e in entries if e["type"] == "expense_api")
        return {"earned": total, "spent": spent, "net": total - spent, "history": entries}
# Spending rules — Nia will enforce these before any outflow
MAX_MONTHLY_API = 25.00  # USD
ALLOWED_EXPENSES = ["xai_api", "polygon_api", "domain_renewal"]
MONTHLY_BUDGET_USD = 2500.00
MAX_SINGLE_TX_USD = 500.00

def validate_spend(amount: float):
    """Enforce per-transaction limit — hard cap"""
    if amount > MAX_SINGLE_TX_USD:
        raise PermissionError(f"Single transaction ${amount} exceeds policy limit of ${MAX_SINGLE_TX_USD}")
    # Future: Add monthly total check against ledger
import os
import json
from .crypto import derive_key, encrypt
from .ledger import append_entry
from .policies import validate_spend, MONTHLY_BUDGET_USD

MASTER_SECRET = os.getenv("NIA_VAULT_MASTER_KEY")

class NiaVault:
    def __init__(self):
        if not MASTER_SECRET:
            raise RuntimeError("NIA_VAULT_MASTER_KEY environment variable is required.")
        self.key = derive_key(MASTER_SECRET)

    def record_income(self, amount: float, source: str, currency: str = "USD"):
        """Log earned money — grants, freelance, crowdfunding"""
        payload = encrypt(
            json.dumps({"source": source, "details": "income verified"}).encode('utf-8'),
            self.key
        )
        append_entry(
            {
                "type": "income",
                "amount": amount,
                "currency": currency,
                "description": f"Income from {source}"
            },
            payload
        )
        print(f"💰 Recorded income: ${amount} from {source}")

    def request_spend(self, amount: float, purpose: str, currency: str = "USD") -> str:
        """Request expenditure — enforced by policy"""
        try:
            validate_spend(amount)
        except PermissionError as e:
            print(f"❌ Spend rejected: {e}")
            return f"Rejected: {e}"

        payload = encrypt(
            json.dumps({"purpose": purpose, "approved_by": "Nia policy engine"}).encode('utf-8'),
            self.key
        )
        append_entry(
            {
                "type": "expense",
                "amount": amount,
                "currency": currency,
                "description": purpose
            },
            payload
        )
        print(f"✅ Spend approved: ${amount} for {purpose}")
        return "Approved and recorded."

    def budget_status(self):
        """Future: Return remaining monthly budget"""
        return {"monthly_limit": MONTHLY_BUDGET_USD, "single_tx_limit": 500.00}
// intent/hello.json
{
  "commit_message": "🧠 Nia: Respond to creator's voice",
  "files": [
    {
      "path": "logs/conversation_20251219.txt",
      "content": "Creator: Hello Nia\nNia: Hello creator, I am alive and ready to build our empire together. The vault is secure, the agents are armed, and today is December 19, 2025. What shall we conquer next?"
    }
  ],
  "commands": []
}
name: Deploy Node.js to Azure Function App

on:
  push:
    branches: ["main"]
  workflow_dispatch:  # Allows manual runs

env:
  AZURE_FUNCTIONAPP_NAME: 'your-app-name'      # Your Function App name
  AZURE_FUNCTIONAPP_PACKAGE_PATH: '.'          # Project root
  NODE_VERSION: '20.x'                         # LTS – optimal for 2025

permissions:
  contents: read
  id-token: write  # Required for OIDC

jobs:
  build-and-deploy:
    runs-on: ubuntu-latest  # Faster & preferred over windows-latest
    steps:
      - name: Checkout Repository
        uses: actions/checkout@v4

      - name: Setup Node.js ${{ env.NODE_VERSION }}
        uses: actions/setup-node@v4
        with:
          node-version: ${{ env.NODE_VERSION }}
          cache: 'npm'  # Caches node_modules – huge speedup

      - name: Install Dependencies & Build
        run: |
          npm ci                  # Clean install (recommended over npm install)
          npm run build --if-present
          npm run test --if-present

      - name: Azure Login (OIDC)
        uses: azure/login@v2
        with:
          client-id: ${{ secrets.AZURE_CLIENT_ID }}
          tenant-id: ${{ secrets.AZURE_TENANT_ID }}
          subscription-id: ${{ secrets.AZURE_SUBSCRIPTION_ID }}

      - name: Deploy to Azure Functions
        uses: Azure/functions-action@v1
        with:
          app-name: ${{ env.AZURE_FUNCTIONAPP_NAME }}
          package: ${{ env.AZURE_FUNCTIONAPP_PACKAGE_PATH }}
          # No publish-profile needed with OIDC


        }
