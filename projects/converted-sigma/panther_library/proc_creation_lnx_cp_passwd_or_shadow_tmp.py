# Title: Copy Passwd Or Shadow From TMP Path
# ID: fa4aaed5-4fe0-498d-bbc0-08e3346387ba
# Status: test
# Level: high
# Author: Joseliyo Sanchez, @Joseliyo_Jstnk
# Date: 2023-01-31
# Tags: attack.credential-access, attack.t1552.001
# Description: Detects when the file "passwd" or "shadow" is copied from tmp path
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: Copy Passwd Or Shadow From TMP Path
def rule(event):
    # Detection Logic:
    # (((CommandLine="*passwd*" OR CommandLine="*shadow*")) AND (Image="*/cp") AND (CommandLine="*/tmp/*"))
    return True

def title(event):
    return "Copy Passwd Or Shadow From TMP Path"

