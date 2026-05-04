import httpx

print("Testing ATIG API...")

try:
    resp = httpx.get("http://localhost:8000/health", timeout=5)
    print(f"Health check: {resp.json()}")
except:
    print("API not running - start with: uvicorn main:app --reload --port 8000")

try:
    resp = httpx.get("http://localhost:8000/stats", timeout=5)
    print(f"Stats: {resp.json()}")
except:
    print("Could not fetch stats")
