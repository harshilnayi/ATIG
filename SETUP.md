# ATIG Setup Guide

## Option 1: Docker (Recommended)

### Prerequisites
- Install [Docker Desktop](https://www.docker.com/products/docker-desktop/) for Windows
- Restart your computer after installation

### Start PostgreSQL
```bash
docker-compose up -d postgres
```

### Verify PostgreSQL is running
```bash
docker-compose ps
# Should show postgres container as "healthy"
```

## Option 2: Native PostgreSQL

### Install PostgreSQL 15+
1. Download from: https://www.postgresql.org/download/windows/
2. During installation, set password for `postgres` user
3. Remember the password (default port: 5432)

### Update database URL
Edit `python/.env`:
```
DATABASE_URL=postgresql://atig:YOUR_PASSWORD@localhost:5432/atig_db
```

### Create database
```bash
psql -U postgres
CREATE DATABASE atig_db;
CREATE USER atig WITH PASSWORD 'YOUR_PASSWORD';
GRANT ALL PRIVILEGES ON DATABASE atig_db TO atig;
\q
```

## Run the Application

### Python API
```bash
cd python
pip install -r requirements.txt
uvicorn main:app --reload --host 0.0.0.0 --port 8000
```

### Go Engine
```bash
cd go
go mod tidy
go run main.go
```

### Dashboard (Optional)
```bash
cd dashboard
npm install
npm run dev
```

## Test the API

```bash
# Terminal 1: Start API
cd python && uvicorn main:app --reload --port 8000

# Terminal 2: Test
curl http://localhost:8000/health
curl http://localhost:8000/stats
```

## Troubleshooting

### "Database connection refused"
- PostgreSQL not running? Start it or run `docker-compose up -d`
- Check `.env` DATABASE_URL matches your setup

### "go: cannot find module"
- Run `go mod tidy` in the `go/` directory
- Ensure Go 1.21+ is installed: `go version`

### "npm not found"
- Install Node.js from https://nodejs.org/
- Restart terminal after installation
