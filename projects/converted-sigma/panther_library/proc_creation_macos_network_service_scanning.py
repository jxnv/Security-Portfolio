# Title: MacOS Network Service Scanning
# ID: 84bae5d4-b518-4ae0-b331-6d4afd34d00f
# Status: test
# Level: low
# Author: Alejandro Ortuno, oscd.community
# Date: 2020-10-21
# Tags: attack.discovery, attack.t1046
# Description: Detects enumeration of local or remote network services.
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: MacOS Network Service Scanning
def rule(event):
    # Detection Logic:
    # ((((Image="*/nc" OR Image="*/netcat")) AND NOT ((CommandLine="*l*"))) OR ((Image="*/nmap" OR Image="*/telnet")))
    return True

def title(event):
    return "MacOS Network Service Scanning"

