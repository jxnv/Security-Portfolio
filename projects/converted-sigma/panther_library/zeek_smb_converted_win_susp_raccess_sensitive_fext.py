# Title: Suspicious Access to Sensitive File Extensions - Zeek
# ID: 286b47ed-f6fe-40b3-b3a8-35129acd43bc
# Status: test
# Level: medium
# Author: Samir Bousseaden, @neu5ron
# Date: 2020-04-02
# Tags: attack.collection
# Description: Detects known sensitive file extensions via Zeek
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: Suspicious Access to Sensitive File Extensions - Zeek
def rule(event):
    # Detection Logic:
    # ((name="*.pst" OR name="*.ost" OR name="*.msg" OR name="*.nst" OR name="*.oab" OR name="*.edb" OR name="*.nsf" OR name="*.bak" OR name="*.dmp" OR name="*.kirbi" OR name="*.rdp"))
    return True

def title(event):
    return "Suspicious Access to Sensitive File Extensions - Zeek"

