# Title: System Shutdown/Reboot - MacOs
# ID: 40b1fbe2-18ea-4ee7-be47-0294285811de
# Status: test
# Level: informational
# Author: Igor Fits, Mikhail Larin, oscd.community
# Date: 2020-10-19
# Tags: attack.impact, attack.t1529
# Description: Adversaries may shutdown/reboot systems to interrupt access to, or aid in the destruction of, those systems.
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: System Shutdown/Reboot - MacOs
def rule(event):
    # Detection Logic:
    # ((Image="*/shutdown" OR Image="*/reboot" OR Image="*/halt"))
    return True

def title(event):
    return "System Shutdown/Reboot - MacOs"

