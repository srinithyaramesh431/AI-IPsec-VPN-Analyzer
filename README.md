# AI-Powered IPsec VPN Protocol Analyzer & Security Assessment

An academic cybersecurity project that captures IPsec VPN traffic
(IKE + ESP), analyzes cryptographic configuration, uses machine
learning to infer encrypted-traffic characteristics from metadata
only, and produces an explainable Security Score, Risk Level, Threat
Matrix, and remediation recommendations through an interactive
dashboard.

```
Capture → Identify → Infer → Assess → Score → Recommend
```

## Project structure

```
ai-ipsec-analyzer/
├── testbed/            strongSwan configs for the 2-VM IPsec testbed,
│                        config-matrix generator, traffic generator
├── capture/             tcpdump capture wrapper script
├── backend/              FastAPI app: IKE/ESP parsing, ML module,
│                        security rubric, scorer, recommendations, DB
├── frontend/            React + Vite + Tailwind dashboard
├── dataset/              generated CSV datasets land here
└── docs/                SETUP_GUIDE.md — full step-by-step instructions
```

## Data-provenance guarantee

Every value the system reports is tagged with exactly one of:

| Tag | Meaning |
|---|---|
| **Observed** | Read directly from captured packets |
| **Inferred** | Produced by the ML traffic-type classifier |
| **Configuration-Supplied** | From an uploaded strongSwan config/label, not the wire |
| **Unavailable** | Could not be determined — never guessed |

Nothing is fabricated. Where IKEv2 encrypts a field (e.g. PFS, key
lifetime are rarely visible in cleartext after IKE_AUTH), the system
says so explicitly rather than inventing a plausible-looking value.

## Quickstart

See **[docs/SETUP_GUIDE.md](docs/SETUP_GUIDE.md)** for the full walkthrough
(testbed VMs → capture → backend → ML training → frontend). Short version:

```bash
# Backend
cd backend
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt
python3 -m pytest tests/ -v                 # sanity-check the scoring rubric
uvicorn app.main:app --reload --port 8000

# Frontend (separate terminal)
cd frontend
npm install
npm run dev
```

Then open `http://localhost:5173`, upload a `.pcap`, and review the
result.

## Tech stack

Python · FastAPI · Scapy/PyShark/TShark · scikit-learn · SQLite ·
React + Vite · Tailwind CSS · strongSwan
