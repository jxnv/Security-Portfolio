# Title: Remote Service Activity via SVCCTL Named Pipe
# ID: 586a8d6b-6bfe-4ad9-9d78-888cd2fe50c3
# Status: test
# Level: medium
# Author: Samir Bousseaden
# Date: 2019-04-03
# Tags: attack.lateral-movement, attack.persistence, attack.t1021.002
# Description: Detects remote service activity via remote access to the svcctl named pipe
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: Remote Service Activity via SVCCTL Named Pipe
def rule(event):
    # Detection Logic:
    # (EventID="5145" AND ShareName="\\\\\\\\\\*\\\\IPC$" AND RelativeTargetName="svcctl" AND AccessList="*WriteData*")
    return True

def title(event):
    return "Remote Service Activity via SVCCTL Named Pipe"

