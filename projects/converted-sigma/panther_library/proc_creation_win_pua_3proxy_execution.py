# Title: PUA - 3Proxy Execution
# ID: f38a82d2-fba3-4781-b549-525efbec8506
# Status: test
# Level: high
# Author: Florian Roth (Nextron Systems)
# Date: 2022-09-13
# Tags: attack.command-and-control, attack.t1572
# Description: Detects the use of 3proxy, a tiny free proxy server
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: PUA - 3Proxy Execution
def rule(event):
    # Detection Logic:
    # ((Image="*\\3proxy.exe") OR (CommandLine="*.exe -i127.0.0.1 -p*") OR (Description="3proxy - tiny proxy server"))
    return True

def title(event):
    return "PUA - 3Proxy Execution"

