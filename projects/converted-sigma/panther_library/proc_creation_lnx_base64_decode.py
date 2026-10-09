# Title: Decode Base64 Encoded Text
# ID: e2072cab-8c9a-459b-b63c-40ae79e27031
# Status: test
# Level: low
# Author: Daniil Yugoslavskiy, oscd.community
# Date: 2020-10-19
# Tags: attack.stealth, attack.t1027
# Description: Detects usage of base64 utility to decode arbitrary base64-encoded text
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: Decode Base64 Encoded Text
def rule(event):
    # Detection Logic:
    # (Image="*/base64" AND CommandLine="*-d*")
    return True

def title(event):
    return "Decode Base64 Encoded Text"

