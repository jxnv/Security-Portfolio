# Title: HackTool - Rubeus Execution
# ID: 7ec2c172-dceb-4c10-92c9-87c1881b7e18
# Status: stable
# Level: critical
# Author: Florian Roth (Nextron Systems)
# Date: 2018-12-19
# Tags: attack.credential-access, attack.t1003, attack.t1558.003, attack.lateral-movement, attack.t1550.003
# Description: Detects the execution of the hacktool Rubeus via PE information of command line parameters
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: HackTool - Rubeus Execution
def rule(event):
    # Detection Logic:
    # ((Image="*\\Rubeus.exe") OR (OriginalFileName="Rubeus.exe") OR (Description="Rubeus") OR ((CommandLine="*asreproast *" OR CommandLine="*dump /service:krbtgt *" OR CommandLine="*dump /luid:0x*" OR CommandLine="*kerberoast *" OR CommandLine="*createnetonly /program:*" OR CommandLine="*ptt /ticket:*" OR CommandLine="*/impersonateuser:*" OR CommandLine="*renew /ticket:*" OR CommandLine="*asktgt /user:*" OR CommandLine="*harvest /interval:*" OR CommandLine="*s4u /user:*" OR CommandLine="*s4u /ticket:*" OR CommandLine="*hash /password:*" OR CommandLine="*golden /aes256:*" OR CommandLine="*silver /user:*")))
    return True

def title(event):
    return "HackTool - Rubeus Execution"

