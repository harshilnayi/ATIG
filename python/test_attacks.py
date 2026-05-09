"""
Quick Attack Tester - Tests all detection types
"""
import httpx

API_URL = "http://localhost:8001"

tests = [
    ("SQL Injection - UNION", "UNION SELECT * FROM users", 80),
    ("SQL Injection - OR 1=1", "OR 1=1 --", 80),
    ("XSS - Script Tag", "<script>alert('XSS')</script>", 80),
    ("XSS - Event Handler", "<img src=x onerror=alert(1)>", 80),
    ("Path Traversal", "../../../etc/passwd", 80),
    ("Command Injection", "|cat /etc/passwd", 80),
    ("Normal Traffic", "GET /index.html HTTP/1.1", 80),
]

print("=" * 60)
print("ATIG Quick Attack Tester")
print("=" * 60)

for name, payload, port in tests:
    try:
        params = {
            'src_ip': '192.168.1.100',
            'dst_ip': '10.0.0.1',
            'src_port': 54321,
            'dst_port': port,
            'protocol': 'tcp',
            'payload': payload
        }
        response = httpx.post(f"{API_URL}/packet/analyze", params=params, timeout=10)
        result = response.json()

        if result.get('analysis'):
            print(f"✓ {name}: DETECTED")
            for detection in result['analysis']:
                print(f"    → {detection.get('message')} ({detection.get('severity')})")
        else:
            print(f"✓ {name}: No detection (safe)")
    except Exception as e:
        print(f"✗ {name}: ERROR - {e}")

print("=" * 60)

# Get stats
try:
    stats = httpx.get(f"{API_URL}/stats").json()
    print(f"\nTotal Alerts: {stats.get('total_alerts', 0)}")
    print(f"Critical: {stats.get('critical', 0)}")
    print(f"High: {stats.get('high_severity', 0)}")
    print(f"Medium: {stats.get('medium_severity', 0)}")
    print(f"Low: {stats.get('low_severity', 0)}")
except:
    pass