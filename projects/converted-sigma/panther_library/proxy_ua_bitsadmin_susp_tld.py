# Title: Bitsadmin to Uncommon TLD
# ID: 9eb68894-7476-4cd6-8752-23b51f5883a7
# Status: test
# Level: high
# Author: Florian Roth (Nextron Systems), Tim Shelton
# Date: 2019-03-07
# Tags: attack.command-and-control, attack.execution, attack.stealth, attack.t1071.001, attack.persistence, attack.t1197, attack.s0190
# Description: Detects Bitsadmin connections to domains with uncommon TLDs
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: Bitsadmin to Uncommon TLD
def rule(event):
    # Detection Logic:
    # ((c-useragent="Microsoft BITS/*") AND NOT (((cs-host="*.com" OR cs-host="*.microsoft" OR cs-host="*.net" OR cs-host="*.org" OR cs-host="*.scdn.co" OR cs-host="*.sfx.ms"))))
    return True

def title(event):
    return "Bitsadmin to Uncommon TLD"

