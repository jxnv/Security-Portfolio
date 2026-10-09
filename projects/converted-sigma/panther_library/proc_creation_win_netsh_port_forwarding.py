# Title: New Port Forwarding Rule Added Via Netsh.EXE
# ID: 322ed9ec-fcab-4f67-9a34-e7c6aef43614
# Status: test
# Level: medium
# Author: Florian Roth (Nextron Systems), omkar72, oscd.community, Swachchhanda Shrawan Poudel
# Date: 2019-01-29
# Tags: attack.lateral-movement, attack.command-and-control, attack.t1090
# Description: Detects the execution of netsh commands that configure a new port forwarding (PortProxy) rule
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: New Port Forwarding Rule Added Via Netsh.EXE
def rule(event):
    # Detection Logic:
    # (((Image="*\\netsh.exe") OR (OriginalFileName="netsh.exe")) AND (((CommandLine="*interface*" AND CommandLine="*portproxy*" AND CommandLine="*add*" AND CommandLine="*v4tov4*")) OR ((CommandLine="*i *" AND CommandLine="*p *" AND CommandLine="*a *" AND CommandLine="*v *")) OR ((CommandLine="*connectp*" AND CommandLine="*listena*" AND CommandLine="*c=*"))))
    return True

def title(event):
    return "New Port Forwarding Rule Added Via Netsh.EXE"

