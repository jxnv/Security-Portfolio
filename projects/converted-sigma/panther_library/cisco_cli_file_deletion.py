# Title: Cisco File Deletion
# ID: 71d65515-c436-43c0-841b-236b1f32c21e
# Status: test
# Level: medium
# Author: Austin Clark
# Date: 2019-08-12
# Tags: attack.impact, attack.stealth, attack.t1070.004, attack.t1561.001, attack.t1561.002
# Description: See what files are being deleted from flash file systems
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: Cisco File Deletion
def rule(event):
    # Detection Logic:
    # ("erase" OR "delete" OR "format")
    return True

def title(event):
    return "Cisco File Deletion"

