# Title: DirLister Execution
# ID: b4dc61f5-6cce-468e-a608-b48b469feaa2
# Status: test
# Level: low
# Author: frack113
# Date: 2022-08-20
# Tags: attack.discovery, attack.t1083
# Description: Detect the usage of "DirLister.exe" a utility for quickly listing folder or drive contents. It was seen used by BlackCat ransomware to create a list of accessible directories and files.
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: DirLister Execution
def rule(event):
    # Detection Logic:
    # ((OriginalFileName="DirLister.exe") OR (Image="*\\DirLister.exe"))
    return True

def title(event):
    return "DirLister Execution"

