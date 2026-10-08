import requests
import os
import re
import json
import sys
from dotenv import load_dotenv


ioc = sys.argv[1]

base = "https://www.virustotal.com/api/v3/"

load_dotenv()

vt_api_key = os.getenv("VT_API_key")

headers = {
    "accept": "application/json",
    "x-apikey": vt_api_key
    
}

def detect_ioc_type(ioc):

    domain_regex = r"^(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}$"

    if re.match(domain_regex, ioc):
        return "domain"
    
    if len(ioc) in [32, 40, 64]:
        return "hash"
    
    return "ip"

ioc_type = detect_ioc_type(ioc)

def build_url(ioc, ioc_type):
    base = "https://www.virustotal.com/api/v3"

    if ioc_type == "ip":
        return f"{base}/ip_addresses/{ioc}"
    
    elif ioc_type == "domain":
        return f"{base}/domains/{ioc}"
    
    elif ioc_type == "hash":
        return f"{base}/files/{ioc}"

url = build_url(ioc, ioc_type)

try:
    response = requests.get(url, headers=headers)
    response.raise_for_status() # Raise an exception for bad status codes (4xx or 5xx)
    
    # Process the response data, typically JSON
    data = response.json()

except requests.exceptions.RequestException as e:
    print(f"An error occurred: {e}")


def parse_vt_response(data):

    stats = data["data"]["attributes"]["last_analysis_stats"]

    print("\nDetection Summary")

    print(f"Malicious: {stats['malicious']}")
    print(f"Suspicious: {stats['suspicious']}")
    print(f"Harmless: {stats['harmless']}")
    print(f"Undetected: {stats['undetected']}")


#if data:
#    verdict = parse_vt_response(data)
 #   print(verdict)
 
parse_vt_response(data)