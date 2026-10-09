# Title: Group Has Been Deleted Via Groupdel
# ID: 8a46f16c-8c4c-82d1-b121-0fdd3ba70a84
# Status: test
# Level: medium
# Author: Tuan Le (NCSGroup)
# Date: 2022-12-26
# Tags: attack.impact, attack.t1531
# Description: Detects execution of the "groupdel" binary. Which is used to delete a group. This is sometimes abused by threat actors in order to cover their tracks
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: Group Has Been Deleted Via Groupdel
def rule(event):
    # Detection Logic:
    # (Image="*/groupdel")
    return True

def title(event):
    return "Group Has Been Deleted Via Groupdel"

