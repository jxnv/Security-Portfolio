import requests
import os
import re
import json
import csv
import time
from dotenv import load_dotenv

load_dotenv()

vt_api_key = os.getenv("VT_API_key")

headers = {
    "accept": "application/json",
    "x-apikey": vt_api_key
}

def process_ips_from_csv(filename):
    iocs = []

    with open(filename, mode='r', newline='') as csvfile:
        csv_reader = csv.reader(csvfile)

        try:
            next(csv_reader)
        except StopIteration:
            pass

        for row in csv_reader:
            if row:
                iocs.append(row[0])
    iocs = list(set(iocs))

    return iocs



def detect_ioc_type(ioc):
    ipv4_regex = r"^\d{1,3}(\.\d{1,3}){3}$"
    domain_regex = r"^(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}$"

    if re.match(ipv4_regex, ioc):
        return "ip"

    if re.match(domain_regex, ioc):
        return "domain"

    if len(ioc) in [32, 40, 64]:
        return "hash"

    return "nothing"


def build_url(ioc, ioc_type):
    base = "https://www.virustotal.com/api/v3"

    if ioc_type == "ip":
        return f"{base}/ip_addresses/{ioc}"

    elif ioc_type == "domain":
        return f"{base}/domains/{ioc}"

    elif ioc_type == "hash":
        return f"{base}/files/{ioc}"


def vt_request(url):

    try:
        response = requests.get(url, headers=headers)
        response.raise_for_status()
        return response.json()

    except requests.exceptions.RequestException as e:
        print(f"Error querying VT: {e}")
        return None


def parse_vt_response(data, ioc, ioc_type):

    stats = data["data"]["attributes"]["last_analysis_stats"]

    malicious = stats["malicious"]
    suspicious = stats["suspicious"]
    harmless = stats["harmless"]
    undetected = stats["undetected"]

    if malicious > 0:
        verdict = "malicious"
    elif suspicious > 0:
        verdict = "suspicious"
    else:
        verdict = "clean"

    return {
        "ioc": ioc,
        "type": ioc_type,
        "malicious": malicious,
        "suspicious": suspicious,
        "harmless": harmless,
        "undetected": undetected,
        "verdict": verdict
    }

# -------------------------
# PIPELINE
# -------------------------

iocs = process_ips_from_csv("Flagged_IP_List.csv")

results = []

open("vt_report.json", "w").close()

for ioc in iocs:

    print(f"Processing {ioc}...")

    ioc_type = detect_ioc_type(ioc)

    if ioc_type == "nothing":
        continue

    url = build_url(ioc, ioc_type)

    data = vt_request(url)

    if data:
        result = parse_vt_response(data, ioc, ioc_type)

        with open("vt_report.json", "a") as f:
            json.dump(result, f)
            f.write("\n")   # new line so each object is separate

    time.sleep(15)


# Write results AFTER loop finishes
with open("vt_report.json", "w") as f:
    json.dump(results, f, indent=4)