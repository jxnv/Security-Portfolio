# Title: Suspicious Package Installed - Linux
# ID: 700fb7e8-2981-401c-8430-be58e189e741
# Status: test
# Level: medium
# Author: Nasreddine Bencherchali (Nextron Systems)
# Date: 2023-01-03
# Tags: attack.defense-impairment, attack.t1553.004
# Description: Detects installation of suspicious packages using system installation utilities
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: Suspicious Package Installed - Linux
def rule(event):
    # Detection Logic:
    # ((((Image="*/apt" OR Image="*/apt-get") AND CommandLine="*install*") OR (Image="*/dpkg" AND (CommandLine="*--install*" OR CommandLine="*-i*")) OR (Image="*/rpm" AND CommandLine="*-i*") OR (Image="*/yum" AND (CommandLine="*localinstall*" OR CommandLine="*install*"))) AND ((CommandLine="*nmap*" OR CommandLine="* nc*" OR CommandLine="*netcat*" OR CommandLine="*wireshark*" OR CommandLine="*tshark*" OR CommandLine="*openconnect*" OR CommandLine="*proxychains*" OR CommandLine="*socat*")))
    return True

def title(event):
    return "Suspicious Package Installed - Linux"

