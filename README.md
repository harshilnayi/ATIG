# ATIG - Automated Threat Intelligence Aggregator

Network Intrusion Detection System with real-time packet capture, signature-based detection, ML-powered anomaly detection, and threat intelligence feed integration.

## Architecture

```
┌─────────────────────┐     ┌──────────────────────┐     ┌───────────────────┐
│   Go Packet Core    │ ──→ │  Python Detection    │ ──→ │  PostgreSQL       │
│  (libpcap/af_pkt)   │     │  + Threat Intel      │     │  + Vue Dashboard  │
└─────────────────────┘     └──────────────────────┘     └───────────────────┘
```

## Stack

- **Packet Capture:** Go (libpcap/AF_PACKET)
- **Detection Engine:** Python (FastAPI, scikit-learn)
- **Database:** PostgreSQL 15+
- **Dashboard:** Vue 3 + Tailwind CSS
- **Threat Feeds:** OTX, Abuse.ch, PhishTank (all free)

## Quick Start

### Prerequisites

- Go 1.21+
- Python 3.11+
- PostgreSQL 15+
- (Optional) Docker for easy DB setup

### Development Setup

```bash
# PostgreSQL via Docker
docker-compose up -d postgres

# Go packet engine
cd go && go mod tidy && go run main.go

# Python services
cd python && pip install -r requirements.txt
uvicorn main:app:reload --host 0.0.0.0 --port 8000

# Dashboard (optional)
cd dashboard && npm install && npm run dev
```

## Project Structure

```
ATIG/
├── go/                    # Packet capture core
│   ├── main.go
│   ├── pkg/
│   │   ├── packet/       # Capture & decoding
│   │   └── protocol/     # TCP/UDP/ICMP parsers
│   └── internal/
│       └── pipeline/     # Channel-based processing
├── python/               # Detection & analytics
│   ├── main.py
│   ├── engine/           # Signature + ML detection
│   ├── services/         # DB, threat intel APIs
│   └── models/           # SQLAlchemy models
├── dashboard/            # Vue 3 frontend
└── docker-compose.yml
```

## License

MIT
