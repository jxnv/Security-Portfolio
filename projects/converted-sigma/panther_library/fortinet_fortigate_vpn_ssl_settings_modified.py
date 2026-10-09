# Title: FortiGate - VPN SSL Settings Modified
# ID: 8b5dacf2-aeb7-459d-b133-678eb696d410
# Status: experimental
# Level: medium
# Author: Marco Pedrinazzi (@pedrinazziM) (InTheCyber)
# Date: 2025-11-01
# Tags: attack.persistence, attack.initial-access, attack.t1133
# Description: Detects the modification of VPN SSL Settings (for example, the modification of authentication rules).
# This behavior was observed in pair with the addition of a VPN SSL Web Portal.
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: FortiGate - VPN SSL Settings Modified
def rule(event):
    # Detection Logic:
    # (action="Edit" AND cfgpath="vpn.ssl.settings")
    return True

def title(event):
    return "FortiGate - VPN SSL Settings Modified"

