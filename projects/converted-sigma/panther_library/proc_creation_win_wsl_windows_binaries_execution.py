# Title: Windows Binary Executed From WSL
# ID: ed825c86-c009-4014-b413-b76003e33d35
# Status: test
# Level: medium
# Author: Nasreddine Bencherchali (Nextron Systems)
# Date: 2023-02-14
# Tags: attack.execution, attack.stealth, attack.t1202
# Description: Detects the execution of Windows binaries from within a WSL instance.
# This could be used to masquerade parent-child relationships
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: Windows Binary Executed From WSL
def rule(event):
    # Detection Logic:
    # (Image=regex("[a-zA-Z]:\\\\") AND CurrentDirectory="*\\\\\\\\wsl.localhost*")
    return True

def title(event):
    return "Windows Binary Executed From WSL"

