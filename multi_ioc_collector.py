import requests
import csv
import json
import os
from datetime import datetime
import re
from dotenv import load_dotenv

load_dotenv()

# ==================== SUAS KEYS ====================
OTX_API_KEY = os.getenv("OTX_API_KEY") or "SUA_OTX_KEY_AQUI"
ABUSE_AUTH_KEY = os.getenv("ABUSE_AUTH_KEY") or "SUA_ABUSE_KEY_AQUI"

OUTPUT_DIR = "iocs_coletados"
os.makedirs(OUTPUT_DIR, exist_ok=True)
timestamp = datetime.now().strftime("%Y%m%d_%H%M")

iocs = []

def classify_ioc(value: str) -> str:
    value = value.strip().lower()
    if re.match(r'^\d{1,3}(\.\d{1,3}){3}$', value) or re.match(r'^[0-9a-f]{32,64}$', value):
        return 'hash' if len(value) > 15 else 'ip'
    if re.match(r'^https?://', value):
        return 'url'
    if '.' in value and not re.search(r'\d', value[:5]):
        return 'domain'
    return 'unknown'

# ==================== 1. ALIENVAULT OTX (CORRIGIDO - agora usa /recent) ====================
print("🔄 Coletando de OTX...")
if OTX_API_KEY == "SUA_OTX_KEY_AQUI":
    print("⚠️  OTX pulado (coloque sua key real)")
else:
    headers = {"X-OTX-API-KEY": OTX_API_KEY}
    r = requests.get(
        "https://otx.alienvault.com/api/v1/pulses/recent",
        headers=headers,
        params={"limit": 100}   # traz 100 pulses públicos recentes
    )
    if r.status_code == 200:
        for pulse in r.json().get("results", []):
            for ind in pulse.get("indicators", []):
                iocs.append({
                    "type": ind.get("type", classify_ioc(ind["indicator"])),
                    "value": ind["indicator"],
                    "source": f"OTX - {pulse['name']}",
                    "date": pulse.get("created", ""),
                    "extra": {"pulse_id": pulse["id"]}
                })
        print(f"✅ OTX: {len(r.json().get('results', []))} pulses carregados")
    else:
        print(f"❌ OTX falhou (status {r.status_code}) - verifique a key no site da OTX")

# ==================== 2. URLHAUS ====================
print("🔄 Coletando de URLhaus...")
r = requests.get("https://urlhaus-api.abuse.ch/v1/urls/recent/", headers={"Auth-Key": ABUSE_AUTH_KEY})
if r.status_code == 200:
    for item in r.json().get("urls", []):
        iocs.append({"type": "url", "value": item["url"], "source": "URLhaus", "date": item["date_added"], "extra": {"threat": item.get("threat")}})

# ==================== 3. MALWAREBAZAAR ====================
print("🔄 Coletando de MalwareBazaar...")
r = requests.post("https://mb-api.abuse.ch/api/v1/", headers={"Auth-Key": ABUSE_AUTH_KEY}, data={"query": "recent_detections", "hours": "48"})
if r.status_code == 200 and r.json().get("query_status") == "ok":
    for sample in r.json().get("data", []):
        iocs.append({
            "type": "hash",
            "value": sample.get("sha256_hash"),
            "source": "MalwareBazaar",
            "date": sample.get("first_seen"),
            "extra": {"signature": sample.get("signature"), "file_name": sample.get("file_name")}
        })

# ==================== 4. OPENPHISH ====================
print("🔄 Coletando de OpenPhish...")
r = requests.get("https://openphish.com/feed.txt")
if r.status_code == 200:
    for url in r.text.strip().split("\n"):
        if url.strip():
            iocs.append({"type": "url", "value": url.strip(), "source": "OpenPhish", "date": datetime.now().isoformat(), "extra": {}})

# ==================== DEDUPLICAÇÃO + SALVAR ====================
seen = set()
unique_iocs = []
for ioc in iocs:
    if ioc.get("value"):
        key = (ioc["type"], ioc["value"].lower())
        if key not in seen:
            seen.add(key)
            unique_iocs.append(ioc)

print(f"✅ Total de IOCs únicos: {len(unique_iocs)}")

csv_path = f"{OUTPUT_DIR}/iocs_{timestamp}.csv"
with open(csv_path, "w", newline="", encoding="utf-8") as f:
    writer = csv.DictWriter(f, fieldnames=["type", "value", "source", "date", "extra"])
    writer.writeheader()
    for ioc in unique_iocs:
        ioc["extra"] = json.dumps(ioc["extra"])
        writer.writerow(ioc)

json_path = f"{OUTPUT_DIR}/iocs_{timestamp}.json"
with open(json_path, "w", encoding="utf-8") as f:
    json.dump(unique_iocs, f, indent=2, ensure_ascii=False)

print(f"\n🗂 PRONTO! Arquivos salvos em /{OUTPUT_DIR}/")
print(f"   → iocs_{timestamp}.csv")
print(f"   → iocs_{timestamp}.json")
