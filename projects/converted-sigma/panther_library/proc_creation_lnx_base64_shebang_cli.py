# Title: Linux Base64 Encoded Shebang In CLI
# ID: fe2f9663-41cb-47e2-b954-8a228f3b9dff
# Status: test
# Level: medium
# Author: Nasreddine Bencherchali (Nextron Systems)
# Date: 2022-09-15
# Tags: attack.stealth, attack.t1140
# Description: Detects the presence of a base64 version of the shebang in the commandline, which could indicate a malicious payload about to be decoded
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: Linux Base64 Encoded Shebang In CLI
def rule(event):
    # Detection Logic:
    # ((CommandLine="*IyEvYmluL2Jhc2*" OR CommandLine="*IyEvYmluL2Rhc2*" OR CommandLine="*IyEvYmluL3pza*" OR CommandLine="*IyEvYmluL2Zpc2*" OR CommandLine="*IyEvYmluL3No*"))
    return True

def title(event):
    return "Linux Base64 Encoded Shebang In CLI"

