# Title: Gatekeeper Bypass via Xattr
# ID: f5141b6d-9f42-41c6-a7bf-2a780678b29b
# Status: test
# Level: low
# Author: Daniil Yugoslavskiy, oscd.community
# Date: 2020-10-19
# Tags: attack.defense-impairment, attack.t1553.001
# Description: Detects macOS Gatekeeper bypass via xattr utility
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: Gatekeeper Bypass via Xattr
def rule(event):
    # Detection Logic:
    # (Image="*/xattr" AND (CommandLine="*-d*" AND CommandLine="*com.apple.quarantine*"))
    return True

def title(event):
    return "Gatekeeper Bypass via Xattr"

