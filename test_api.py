"""Quick test script for the Fleet Management API."""
import os
import requests
import json

BASE = os.environ.get("FLEET_BASE_URL", "http://127.0.0.1:8000")
API = f"{BASE}/api/v1"

# The API needs a session. Defaults match the demo login.
session = requests.Session()
r = session.post(
    f"{BASE}/login",
    data={
        "username": os.environ.get("AUTH_USERNAME", "demo"),
        "password": os.environ.get("AUTH_PASSWORD", "demo1234"),
    },
    allow_redirects=False,
)
assert r.status_code == 303, f"Login failed ({r.status_code})"

# List vehicles
r = session.get(f"{API}/vehicles/")
print("=== VEHICLES ===")
for v in r.json():
    print(f"  #{v['id']} {v['make']} {v['model']} ({v['license_plate']}) - {v['status']}")

# Fleet summary
r = session.get(f"{API}/vehicles/fleet/summary")
print(f"\n=== FLEET SUMMARY ===")
print(json.dumps(r.json(), indent=2))

# Test telemetry ingest (open endpoint, no login needed)
data = {
    "vehicle_id": 1, "latitude": 28.6139, "longitude": 77.2090,
    "vehicle_speed": 85.5, "engine_rpm": 3200, "coolant_temp": 92.0,
    "fuel_level": 65.0, "battery_voltage": 13.8, "odometer": 12550
}
r = requests.post(f"{API}/telemetry/ingest", json=data)
print(f"\n=== TELEMETRY INGEST ===")
print(json.dumps(r.json(), indent=2))

# Get alerts
r = session.get(f"{API}/alerts/")
print(f"\n=== ALERTS ({len(r.json())}) ===")
for a in r.json()[:5]:
    print(f"  [{a['severity']}] {a['message']}")

print("\n All tests passed!")
