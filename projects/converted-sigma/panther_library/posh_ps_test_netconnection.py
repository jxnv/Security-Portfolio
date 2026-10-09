# Title: Testing Usage of Uncommonly Used Port
# ID: adf876b3-f1f8-4aa9-a4e4-a64106feec06
# Status: test
# Level: medium
# Author: frack113
# Date: 2022-01-23
# Tags: attack.command-and-control, attack.t1571
# Description: Adversaries may communicate using a protocol and port paring that are typically not associated.
# For example, HTTPS over port 8088(Citation: Symantec Elfin Mar 2019) or port 587(Citation: Fortinet Agent Tesla April 2018) as opposed to the traditional port 443.
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: Testing Usage of Uncommonly Used Port
def rule(event):
    # Detection Logic:
    # (((ScriptBlockText="*Test-NetConnection*" AND ScriptBlockText="*-ComputerName *" AND ScriptBlockText="*-port *")) AND NOT (((ScriptBlockText="* 443 *" OR ScriptBlockText="* 80 *"))))
    return True

def title(event):
    return "Testing Usage of Uncommonly Used Port"

