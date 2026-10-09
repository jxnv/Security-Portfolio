# Title: DD File Overwrite
# ID: 2953194b-e33c-4859-b9e8-05948c167447
# Status: test
# Level: low
# Author: Roberto Rodriguez (Cyb3rWard0g), OTR (Open Threat Research), MSTIC
# Date: 2021-10-15
# Tags: attack.impact, attack.t1485
# Description: Detects potential overwriting and deletion of a file using DD.
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: DD File Overwrite
def rule(event):
    # Detection Logic:
    # (((Image="/bin/dd" OR Image="/usr/bin/dd")) AND (CommandLine="*of=*") AND ((CommandLine="*if=/dev/zero*" OR CommandLine="*if=/dev/null*")))
    return True

def title(event):
    return "DD File Overwrite"

