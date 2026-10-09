# Title: Kubernetes Events Deleted
# ID: 3132570d-cab2-4561-9ea6-1743644b2290
# Status: test
# Level: medium
# Author: Leo Tsaousis (@laripping)
# Date: 2024-03-26
# Tags: attack.stealth, attack.t1070
# Description: Detects when events are deleted in Kubernetes.
# An adversary may delete Kubernetes events in an attempt to evade detection.
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: Kubernetes Events Deleted
def rule(event):
    # Detection Logic:
    # (verb="delete" AND objectRef.resource="events")
    return True

def title(event):
    return "Kubernetes Events Deleted"

