# Title: Mask System Power Settings Via Systemctl
# ID: c172b7b5-f3a1-4af2-90b7-822c63df86cb
# Status: experimental
# Level: high
# Author: Milad Cheraghi, Nasreddine Bencherchali
# Date: 2025-10-17
# Tags: attack.persistence, attack.impact, attack.t1653
# Description: Detects the use of systemctl mask to disable system power management targets such as suspend, hibernate, or hybrid sleep.
# Adversaries may mask these targets to prevent a system from entering sleep or shutdown states, ensuring their malicious processes remain active and uninterrupted.
# This behavior can be associated with persistence or defense evasion, as it impairs normal system power operations to maintain long-term access or avoid termination of malicious activity.
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: Mask System Power Settings Via Systemctl
def rule(event):
    # Detection Logic:
    # (((CommandLine="*suspend.target*" OR CommandLine="*hibernate.target*" OR CommandLine="*hybrid-sleep.target*")) AND (Image="*/systemctl" AND CommandLine="* mask*"))
    return True

def title(event):
    return "Mask System Power Settings Via Systemctl"

