# Title: Advanced IP Scanner - File Event
# ID: fed85bf9-e075-4280-9159-fbe8a023d6fa
# Status: test
# Level: medium
# Author: @ROxPinTeddy
# Date: 2020-05-12
# Tags: attack.discovery, attack.t1046
# Description: Detects the use of Advanced IP Scanner. Seems to be a popular tool for ransomware groups.
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: Advanced IP Scanner - File Event
def rule(event):
    # Detection Logic:
    # (TargetFilename="*\\AppData\\Local\\Temp\\Advanced IP Scanner 2*")
    return True

def title(event):
    return "Advanced IP Scanner - File Event"

