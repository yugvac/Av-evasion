# 🛡️ SentinelLab — AV Evasion Research Platform

A **private, VirusTotal-style malware analysis platform** for cybersecurity researchers. Upload any file, scan it against **70+ real AV engines**, and get custom **deep static analysis** — all from your own machine.

## ✨ Features

- **Multi-Engine Scanning** — Real results from 70+ AV vendors via VirusTotal API
- **Deep Static Analysis** — PE parsing, string extraction, network IOC detection
- **Entropy Heatmap** — Visual entropy distribution to spot packed/encrypted payloads
- **MITRE ATT&CK Mapping** — Auto-maps findings to adversary techniques
- **Composite Risk Score** — Weighted 0-100 score combining 6 analysis factors
- **Scan History & Search** — Track all scans, search by hash or filename
- **PDF Reports** — Professional research reports via ReportLab
- **Experiment System** — Generate test payloads and study detection patterns

## 🏗️ Tech Stack

| Layer | Technology |
| :--- | :--- |
| **Backend** | Python 3.13, FastAPI, Uvicorn |
| **Database** | SQLite + SQLAlchemy ORM |
| **Frontend** | React 18 + Vite |
| **External API** | VirusTotal API v3 |
| **Scheduler** | APScheduler |
| **Reports** | ReportLab |

## 🚀 Getting Started

### Prerequisites
- Python 3.10+
- Node.js 18+
- VirusTotal API Key ([get one free](https://www.virustotal.com/gui/my-apikey))(paste that VP api key inside the **.env.example** file and change the file name to **.env**)

### Backend Setup
```bash
# Create virtual environment
python -m venv venv
source venv/bin/activate        # Linux/Mac
# source venv/bin/activate.fish  # Fish shell

# Install dependencies
pip install -r requirements.txt

# Configure API key
cp .env.example .env
# Edit .env and add your VT_API_KEY

# Run the backend
uvicorn backend.main:app --reload --port 8000
```

### Frontend Setup
```bash
cd frontend
npm install
npm run dev
```

### Access
- **Frontend**: http://localhost:5173
- **Backend API**: http://localhost:8000
- **API Docs (Swagger)**: http://localhost:8000/docs

## 📁 Project Structure
```
├── backend/
│   ├── main.py              # FastAPI app entry point
│   ├── config.py            # App settings & paths
│   ├── database.py          # SQLAlchemy engine & session
│   ├── models.py            # ORM models (FileScan, EngineResult)
│   ├── routes/
│   │   ├── scan.py          # Core scan API (upload, poll, history)
│   │   ├── dashboard.py     # Analytics endpoints
│   │   ├── experiments.py   # Experiment CRUD
│   │   └── reports.py       # PDF report generation
│   ├── scanner/
│   │   ├── engine.py        # VirusTotal API integration
│   │   └── analyzer.py      # Deep static analysis engine
│   ├── generator/
│   │   └── engine.py        # Test payload generator
│   └── scheduler/
│       └── scheduler.py     # Automated experiment runner
├── frontend/
│   └── src/
│       ├── App.jsx           # React Router (4 pages)
│       ├── api.js            # API service layer
│       ├── pages/            # ScanUpload, ScanResult, History, Stats
│       └── components/       # Sidebar, EntropyHeatmap, MitreMap
├── .env.example              # API key template
└── requirements.txt          # Python dependencies
```

## 🔒 Privacy Notice

SentinelLab's deep analysis engine (entropy, PE parsing, MITRE mapping, risk scoring) runs **100% locally** — your files never leave your machine. The VirusTotal API integration is **optional** and only activates when a `VT_API_KEY` is configured.

## 📄 License

This project is for **educational and research purposes only**. Do not use it for malicious activities.
