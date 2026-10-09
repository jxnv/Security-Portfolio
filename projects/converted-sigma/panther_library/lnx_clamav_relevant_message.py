# Title: Relevant ClamAV Message
# ID: 36aa86ca-fd9d-4456-814e-d3b1b8e1e0bb
# Status: stable
# Level: high
# Author: Florian Roth (Nextron Systems)
# Date: 2017-03-01
# Tags: attack.resource-development, attack.t1588.001
# Description: Detects relevant ClamAV messages
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: Relevant ClamAV Message
def rule(event):
    # Detection Logic:
    # ("Trojan*FOUND" OR "VirTool*FOUND" OR "Webshell*FOUND" OR "Rootkit*FOUND" OR "Htran*FOUND")
    return True

def title(event):
    return "Relevant ClamAV Message"

