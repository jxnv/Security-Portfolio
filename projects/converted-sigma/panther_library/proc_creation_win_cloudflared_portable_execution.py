# Title: Cloudflared Portable Execution
# ID: fadb84f0-4e84-4f6d-a1ce-9ef2bffb6ccd
# Status: test
# Level: medium
# Author: Nasreddine Bencherchali (Nextron Systems)
# Date: 2023-12-20
# Tags: attack.command-and-control, attack.t1090.001
# Description: Detects the execution of the "cloudflared" binary from a non standard location.
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: Cloudflared Portable Execution
def rule(event):
    # Detection Logic:
    # ((Image="*\\cloudflared.exe") AND NOT (((Image="*:\\Program Files (x86)\\cloudflared\\*" OR Image="*:\\Program Files\\cloudflared\\*"))))
    return True

def title(event):
    return "Cloudflared Portable Execution"

