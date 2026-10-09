# Title: Google Workspace Role Privilege Deleted
# ID: bf638ef7-4d2d-44bb-a1dc-a238252e6267
# Status: test
# Level: medium
# Author: Austin Songer
# Date: 2021-08-24
# Tags: attack.impact
# Description: Detects when an a role privilege is deleted in Google Workspace.
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: Google Workspace Role Privilege Deleted
def rule(event):
    # Detection Logic:
    # (eventService="admin.googleapis.com" AND eventName="REMOVE_PRIVILEGE")
    return True

def title(event):
    return "Google Workspace Role Privilege Deleted"

